#include "VppHftExporter.h"

#include "VppHftNetlinkSender.h"

#include "meta/sai_serialize.h"

#include "swss/logger.h"

#include <algorithm>

using namespace saivs;

std::atomic<bool> VppHftExporter::m_statsEndpointClaimed(false);

// C++14 requires out of line definitions for odr-used static const members.
const uint64_t VppHftExporter::MIN_POLLING_INTERVAL_NS;
const uint64_t VppHftExporter::STATS_ACCESS_TIMEOUT_NS;
const int64_t VppHftExporter::STATISTICS_LOG_PERIOD_SECONDS;

namespace
{
    /**
     * Statistics source backed by the persistent, reentrant VPP statistics
     * reader. The reader is created eagerly but connects lazily on the first
     * sample, so constructing an exporter never requires a live VPP.
     */
    class VppHftVppStatsSource:
        public VppHftStatsSource
    {
        public:

            VppHftVppStatsSource():
                m_reader(vpp_stats_reader_create(VppHftExporter::STATS_ACCESS_TIMEOUT_NS))
            {
                SWSS_LOG_ENTER();

                if (m_reader == nullptr)
                {
                    SWSS_LOG_ERROR("failed to create the VPP statistics reader");
                }
            }

            virtual ~VppHftVppStatsSource()
            {
                SWSS_LOG_ENTER();

                if (m_reader != nullptr)
                {
                    vpp_stats_reader_destroy(m_reader);
                    m_reader = nullptr;
                }
            }

            virtual SampleResult sample(
                    const std::vector<std::string>& interfaces,
                    std::vector<vpp_interface_sample_t>& samples) override
            {
                // SWSS_LOG_ENTER(); // disabled: periodic sampling hot path

                if (m_reader == nullptr || interfaces.empty())
                {
                    return SampleResult::FAILED;
                }

                std::vector<const char*> names;

                names.reserve(interfaces.size());

                for (auto& name: interfaces)
                {
                    names.push_back(name.c_str());
                }

                samples.assign(interfaces.size(), vpp_interface_sample_t());

                int rv = vpp_stats_reader_sample(
                        m_reader,
                        names.data(),
                        static_cast<uint32_t>(names.size()),
                        samples.data());

                if (rv == VPP_STATS_READER_OK)
                {
                    return SampleResult::OK;
                }

                if (rv == VPP_STATS_READER_RETRY)
                {
                    return SampleResult::RETRY;
                }

                return SampleResult::FAILED;
            }

            virtual void disconnect() override
            {
                SWSS_LOG_ENTER();

                if (m_reader != nullptr)
                {
                    vpp_stats_reader_disconnect(m_reader);
                }
            }

        private:

            vpp_stats_reader_t *m_reader;
    };
}

VppHftExporter::VppHftExporter():
    VppHftExporter(
            std::unique_ptr<VppHftStatsSource>(new VppHftVppStatsSource()),
            std::unique_ptr<VppHftSink>(new VppHftNetlinkSender()))
{
    SWSS_LOG_ENTER();
}

VppHftExporter::VppHftExporter(
        std::unique_ptr<VppHftStatsSource> statsSource,
        std::unique_ptr<VppHftSink> sink):
    m_statsSource(std::move(statsSource)),
    m_sink(std::move(sink)),
    m_generationCounter(0),
    m_nextTemplateId(TamIpfixBuilder::MIN_TEMPLATE_ID),
    m_shutdown(false),
    m_workerStarted(false),
    m_nextStatisticsLog(
            std::chrono::steady_clock::now() +
            std::chrono::seconds(STATISTICS_LOG_PERIOD_SECONDS)),
    m_ownsStatsEndpoint(false)
{
    SWSS_LOG_ENTER();

    m_ownsStatsEndpoint = !m_statsEndpointClaimed.exchange(true);

    if (!m_ownsStatsEndpoint)
    {
        SWSS_LOG_ERROR("another switch instance already owns the VPP statistics endpoint, "
                "high frequency telemetry is disabled for this instance");
    }
}

VppHftExporter::~VppHftExporter()
{
    SWSS_LOG_ENTER();

    shutdown();

    if (m_ownsStatsEndpoint)
    {
        m_statsEndpointClaimed.store(false);
        m_ownsStatsEndpoint = false;
    }
}

const std::vector<sai_stat_id_t>& VppHftExporter::supportedPortStats()
{
    // Only PORT counters with an exact VPP statistics segment source are
    // advertised. Unicast packet counters are excluded because the current VPP
    // mapping uses aggregate packet vectors.
    static const std::vector<sai_stat_id_t> stats = {
        SAI_PORT_STAT_IF_IN_OCTETS,
        SAI_PORT_STAT_IF_IN_DISCARDS,
        SAI_PORT_STAT_IF_OUT_OCTETS,
        SAI_PORT_STAT_IF_OUT_ERRORS,
    };

    return stats;
}

bool VppHftExporter::isSupportedPortStat(
        sai_stat_id_t statId)
{
    SWSS_LOG_ENTER();

    auto& stats = supportedPortStats();

    return std::find(stats.begin(), stats.end(), statId) != stats.end();
}

sai_status_t VppHftExporter::queryPortStatsStCapability(
        sai_stat_st_capability_list_t *capability)
{
    SWSS_LOG_ENTER();

    if (capability == nullptr)
    {
        SWSS_LOG_ERROR("stats capability list is null");

        return SAI_STATUS_INVALID_PARAMETER;
    }

    auto& stats = supportedPortStats();

    const uint32_t count = static_cast<uint32_t>(stats.size());

    if (capability->count < count || capability->list == nullptr)
    {
        capability->count = count;

        return SAI_STATUS_BUFFER_OVERFLOW;
    }

    capability->count = count;

    for (uint32_t i = 0; i < count; i++)
    {
        capability->list[i].capability.stat_enum = stats[i];
        capability->list[i].capability.stat_modes = SAI_STATS_MODE_READ;
        capability->list[i].minimal_polling_interval = MIN_POLLING_INTERVAL_NS;
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t VppHftExporter::copyTemplateToSaiList(
        const std::vector<uint8_t>& templateMessage,
        sai_u8_list_t& list)
{
    SWSS_LOG_ENTER();

    const uint32_t required = static_cast<uint32_t>(templateMessage.size());

    if (list.list == nullptr || list.count < required)
    {
        list.count = required;

        return SAI_STATUS_BUFFER_OVERFLOW;
    }

    std::copy(templateMessage.begin(), templateMessage.end(), list.list);

    list.count = required;

    return SAI_STATUS_SUCCESS;
}

bool VppHftExporter::mapPortStat(
        sai_stat_id_t statId,
        const vpp_interface_sample_t& sample,
        uint64_t& value)
{
    // SWSS_LOG_ENTER(); // disabled: periodic sampling hot path

    switch (statId)
    {
        case SAI_PORT_STAT_IF_IN_OCTETS:

            if ((sample.present & VPP_INTF_STAT_PRESENT_RX) == 0)
            {
                return false;
            }

            value = sample.stats.rx_bytes;
            return true;

        case SAI_PORT_STAT_IF_OUT_OCTETS:

            if ((sample.present & VPP_INTF_STAT_PRESENT_TX) == 0)
            {
                return false;
            }

            value = sample.stats.tx_bytes;
            return true;

        case SAI_PORT_STAT_IF_IN_DISCARDS:

            // VPP keeps a single per interface drop counter and does not
            // distinguish ingress from egress drops. The same mapping is used
            // by the synchronous SwitchVpp::setPortStats() path.
            if ((sample.present & VPP_INTF_STAT_PRESENT_DROPS) == 0)
            {
                return false;
            }

            value = sample.stats.drops;
            return true;

        case SAI_PORT_STAT_IF_OUT_ERRORS:

            if ((sample.present & VPP_INTF_STAT_PRESENT_TX_ERROR) == 0)
            {
                return false;
            }

            value = sample.stats.tx_error;
            return true;

        default:

            return false;
    }
}

bool VppHftExporter::ownsStatsEndpoint() const
{
    SWSS_LOG_ENTER();

    return m_ownsStatsEndpoint;
}

uint16_t VppHftExporter::allocateTemplateId()
{
    SWSS_LOG_ENTER();

    std::lock_guard<std::mutex> lock(m_stateMutex);

    for (uint32_t attempt = 0;
         attempt <= 0xffffu - TamIpfixBuilder::MIN_TEMPLATE_ID;
         attempt++)
    {
        uint16_t candidate = m_nextTemplateId;

        m_nextTemplateId = (m_nextTemplateId == 0xffff)
                ? TamIpfixBuilder::MIN_TEMPLATE_ID
                : static_cast<uint16_t>(m_nextTemplateId + 1);

        bool inUse = false;

        for (auto& stream: m_streams)
        {
            if (stream.second.config && stream.second.config->templateId == candidate)
            {
                inUse = true;
                break;
            }
        }

        if (!inUse)
        {
            return candidate;
        }
    }

    // Every template id is taken, which v1 scale cannot reach.
    return TamIpfixBuilder::MIN_TEMPLATE_ID;
}

void VppHftExporter::startWorker()
{
    SWSS_LOG_ENTER();

    std::lock_guard<std::mutex> lock(m_stateMutex);

    if (m_workerStarted || m_shutdown)
    {
        return;
    }

    m_workerStarted = true;

    m_worker = std::thread(&VppHftExporter::workerMain, this);

    SWSS_LOG_NOTICE("started the high frequency telemetry exporter worker");
}

void VppHftExporter::quiesceStream(
        sai_object_id_t telemetryTypeId,
        bool erase)
{
    SWSS_LOG_ENTER();

    {
        std::lock_guard<std::mutex> lock(m_stateMutex);

        auto it = m_streams.find(telemetryTypeId);

        if (it != m_streams.end())
        {
            it->second.running = false;
            it->second.generation = ++m_generationCounter;

            if (erase)
            {
                m_streams.erase(it);
            }
        }
    }

    m_cv.notify_all();

    // Wait for a send that entered the fence before the generation was
    // invalidated. The worker never holds m_stateMutex while sending, so this
    // cannot deadlock.
    std::unique_lock<std::shared_timed_mutex> fence(m_sendFence);
}

sai_status_t VppHftExporter::commitStream(
        std::shared_ptr<const VppHftStreamConfig> config)
{
    SWSS_LOG_ENTER();

    std::lock_guard<std::mutex> lifecycleLock(m_lifecycleMutex);

    if (config == nullptr)
    {
        SWSS_LOG_ERROR("stream configuration is null");

        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (!m_ownsStatsEndpoint)
    {
        SWSS_LOG_ERROR("refusing to commit stream %s, this instance does not own the "
                "VPP statistics endpoint",
                sai_serialize_object_id(config->telemetryTypeId).c_str());

        return SAI_STATUS_NOT_SUPPORTED;
    }

    if (config->fields.empty() ||
        config->interfaces.empty() ||
        config->templateMessage.empty() ||
        config->templateId < TamIpfixBuilder::MIN_TEMPLATE_ID ||
        config->pollingInterval.count() <= 0)
    {
        SWSS_LOG_ERROR("refusing to commit an incomplete stream configuration for %s",
                sai_serialize_object_id(config->telemetryTypeId).c_str());

        return SAI_STATUS_INVALID_PARAMETER;
    }

    {
        std::lock_guard<std::mutex> lock(m_stateMutex);

        if (m_shutdown)
        {
            SWSS_LOG_ERROR("exporter is shutting down, refusing to commit stream %s",
                    sai_serialize_object_id(config->telemetryTypeId).c_str());

            return SAI_STATUS_FAILURE;
        }
    }

    // A replacement must not race an in progress send of the previous
    // generation. The lifecycle mutex prevents shutdown from invalidating the
    // replacement after this point.
    quiesceStream(config->telemetryTypeId, false);

    {
        std::lock_guard<std::mutex> lock(m_stateMutex);
        auto& stream = m_streams[config->telemetryTypeId];

        stream.config = config;
        stream.running = false;
        stream.generation = ++m_generationCounter;
        stream.nextDeadline = std::chrono::steady_clock::now();
    }

    startWorker();

    m_cv.notify_all();

    SWSS_LOG_NOTICE("committed high frequency telemetry stream %s, %zu counters on %zu interfaces, "
            "template id %u, polling interval %lld us",
            sai_serialize_object_id(config->telemetryTypeId).c_str(),
            config->fields.size(),
            config->interfaces.size(),
            static_cast<unsigned int>(config->templateId),
            static_cast<long long>(config->pollingInterval.count()));

    return SAI_STATUS_SUCCESS;
}

sai_status_t VppHftExporter::startStream(
        sai_object_id_t telemetryTypeId)
{
    SWSS_LOG_ENTER();

    std::lock_guard<std::mutex> lifecycleLock(m_lifecycleMutex);

    {
        std::lock_guard<std::mutex> lock(m_stateMutex);

        auto it = m_streams.find(telemetryTypeId);

        if (it == m_streams.end() || it->second.config == nullptr)
        {
            SWSS_LOG_ERROR("cannot start stream %s, no configuration was committed",
                    sai_serialize_object_id(telemetryTypeId).c_str());

            return SAI_STATUS_INVALID_PARAMETER;
        }

        if (m_shutdown)
        {
            return SAI_STATUS_FAILURE;
        }

        it->second.running = true;
        it->second.generation = ++m_generationCounter;
        it->second.nextDeadline =
                std::chrono::steady_clock::now() + it->second.config->pollingInterval;
    }

    m_cv.notify_all();

    SWSS_LOG_NOTICE("started high frequency telemetry stream %s",
            sai_serialize_object_id(telemetryTypeId).c_str());

    return SAI_STATUS_SUCCESS;
}

sai_status_t VppHftExporter::updatePollingIntervals(
        const std::vector<sai_object_id_t>& telemetryTypeIds,
        std::chrono::microseconds interval)
{
    SWSS_LOG_ENTER();

    if (interval.count() <= 0)
    {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    std::lock_guard<std::mutex> lifecycleLock(m_lifecycleMutex);

    {
        std::lock_guard<std::mutex> lock(m_stateMutex);

        for (auto telemetryTypeId: telemetryTypeIds)
        {
            auto it = m_streams.find(telemetryTypeId);

            if (it == m_streams.end() || it->second.config == nullptr)
            {
                return SAI_STATUS_ITEM_NOT_FOUND;
            }
        }

        if (m_shutdown)
        {
            return SAI_STATUS_FAILURE;
        }

        const auto now = std::chrono::steady_clock::now();

        for (auto telemetryTypeId: telemetryTypeIds)
        {
            auto& stream = m_streams.at(telemetryTypeId);
            auto updated = std::make_shared<VppHftStreamConfig>(*stream.config);

            updated->pollingInterval = interval;

            stream.config = updated;
            stream.generation = ++m_generationCounter;
            stream.nextDeadline = now + interval;
        }
    }

    m_cv.notify_all();

    SWSS_LOG_NOTICE("updated %zu high frequency telemetry stream polling intervals to %lld us",
            telemetryTypeIds.size(),
            static_cast<long long>(interval.count()));

    return SAI_STATUS_SUCCESS;
}

void VppHftExporter::stopStream(
        sai_object_id_t telemetryTypeId)
{
    SWSS_LOG_ENTER();

    std::lock_guard<std::mutex> lifecycleLock(m_lifecycleMutex);

    quiesceStream(telemetryTypeId, false);

    SWSS_LOG_NOTICE("stopped high frequency telemetry stream %s",
            sai_serialize_object_id(telemetryTypeId).c_str());
}

void VppHftExporter::removeStream(
        sai_object_id_t telemetryTypeId)
{
    SWSS_LOG_ENTER();

    std::lock_guard<std::mutex> lifecycleLock(m_lifecycleMutex);

    quiesceStream(telemetryTypeId, true);

    SWSS_LOG_NOTICE("removed high frequency telemetry stream %s",
            sai_serialize_object_id(telemetryTypeId).c_str());
}

std::shared_ptr<const VppHftStreamConfig> VppHftExporter::getStream(
        sai_object_id_t telemetryTypeId) const
{
    SWSS_LOG_ENTER();

    std::lock_guard<std::mutex> lock(m_stateMutex);

    auto it = m_streams.find(telemetryTypeId);

    if (it == m_streams.end())
    {
        return nullptr;
    }

    return it->second.config;
}

VppHftExporter::Statistics VppHftExporter::getStatistics() const
{
    SWSS_LOG_ENTER();

    std::lock_guard<std::mutex> lock(m_stateMutex);

    return m_statistics;
}

void VppHftExporter::shutdown()
{
    SWSS_LOG_ENTER();

    std::lock_guard<std::mutex> lifecycleLock(m_lifecycleMutex);

    {
        std::lock_guard<std::mutex> lock(m_stateMutex);

        if (m_shutdown)
        {
            return;
        }

        m_shutdown = true;

        for (auto& stream: m_streams)
        {
            stream.second.running = false;
            stream.second.generation = ++m_generationCounter;
        }
    }

    m_cv.notify_all();

    if (m_worker.joinable())
    {
        m_worker.join();
    }

    {
        std::lock_guard<std::mutex> lock(m_stateMutex);

        m_streams.clear();
    }

    if (m_sink)
    {
        m_sink->close();
    }

    if (m_statsSource)
    {
        m_statsSource->disconnect();
    }

    SWSS_LOG_NOTICE("high frequency telemetry exporter stopped");
}

void VppHftExporter::workerMain()
{
    SWSS_LOG_ENTER();

    std::vector<DueSample> due;

    while (true)
    {
        due.clear();

        {
            std::unique_lock<std::mutex> lock(m_stateMutex);

            if (m_shutdown)
            {
                break;
            }

            auto now = std::chrono::steady_clock::now();

            bool scheduled = false;

            std::chrono::steady_clock::time_point earliest = now;

            for (auto& entry: m_streams)
            {
                auto& stream = entry.second;

                if (!stream.running || stream.config == nullptr)
                {
                    continue;
                }

                if (stream.nextDeadline <= now)
                {
                    DueSample sample;

                    sample.telemetryTypeId = entry.first;
                    sample.generation = stream.generation;
                    sample.config = stream.config;

                    due.push_back(sample);

                    auto interval = stream.config->pollingInterval;

                    stream.nextDeadline += interval;

                    if (stream.nextDeadline <= now)
                    {
                        // Sampling fell behind. Skip the missed deadlines
                        // instead of running concurrent or back to back polls.
                        auto behind = now - stream.nextDeadline;
                        auto missed = behind / interval + 1;

                        m_statistics.overruns += static_cast<uint64_t>(missed);

                        stream.nextDeadline += interval * missed;
                    }
                }
                else if (!scheduled || stream.nextDeadline < earliest)
                {
                    earliest = stream.nextDeadline;
                    scheduled = true;
                }
            }

            if (due.empty())
            {
                if (scheduled)
                {
                    m_cv.wait_until(lock, earliest);
                }
                else
                {
                    m_cv.wait(lock);
                }

                continue;
            }
        }

        for (auto& sample: due)
        {
            processSample(sample);
        }

        logStatistics();
    }

    SWSS_LOG_NOTICE("high frequency telemetry exporter worker exited");
}

void VppHftExporter::processSample(
        const DueSample& due)
{
    // SWSS_LOG_ENTER(); // disabled: periodic sampling hot path

    const auto& config = *due.config;

    std::vector<vpp_interface_sample_t> samples;

    auto result = m_statsSource->sample(config.interfaces, samples);

    if (result != VppHftStatsSource::SampleResult::OK ||
        samples.size() != config.interfaces.size())
    {
        std::lock_guard<std::mutex> lock(m_stateMutex);

        m_statistics.samplesDropped++;

        if (result != VppHftStatsSource::SampleResult::RETRY)
        {
            m_statistics.statsFailures++;
        }

        return;
    }

    // The observation time is taken after the dump so it describes a fully
    // sampled record.
    const uint64_t observationTimeNs = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count());

    const uint32_t exportTimeSeconds =
            static_cast<uint32_t>(observationTimeNs / 1000000000ULL);

    std::vector<uint64_t> values;

    values.reserve(config.fields.size());

    for (auto& field: config.fields)
    {
        uint64_t value = 0;

        if (field.interfaceIndex >= samples.size() ||
            !mapPortStat(field.statId, samples[field.interfaceIndex], value))
        {
            std::lock_guard<std::mutex> dropLock(m_stateMutex);

            m_statistics.samplesDropped++;

            return;
        }

        values.push_back(value);
    }

    // Hold the outbound fence in shared mode across the final generation check
    // and the send, so a stop or replacement that started later returns only
    // after this send completed.
    std::shared_lock<std::shared_timed_mutex> fence(m_sendFence);

    uint32_t sequenceNumber = 0;

    {
        std::lock_guard<std::mutex> generationLock(m_stateMutex);

        auto it = m_streams.find(due.telemetryTypeId);

        if (it == m_streams.end() ||
            !it->second.running ||
            it->second.generation != due.generation)
        {
            m_statistics.samplesDropped++;

            return;
        }

        sequenceNumber = m_sequenceNumbers[config.observationDomainId];
    }

    std::vector<uint8_t> message;

    std::string error;

    if (!TamIpfixBuilder::buildDataMessage(
                config.templateId,
                config.observationDomainId,
                exportTimeSeconds,
                sequenceNumber,
                observationTimeNs,
                values,
                message,
                error))
    {
        SWSS_LOG_ERROR("failed to encode an IPFIX data message for stream %s: %s",
                sai_serialize_object_id(due.telemetryTypeId).c_str(),
                error.c_str());

        std::lock_guard<std::mutex> encodeLock(m_stateMutex);

        m_statistics.samplesDropped++;

        return;
    }

    auto sendResult = m_sink->send(message.data(), message.size());

    std::lock_guard<std::mutex> lock(m_stateMutex);

    switch (sendResult)
    {
        case VppHftSink::SendResult::OK:
            m_statistics.samplesSent++;
            m_sequenceNumbers[config.observationDomainId] = sequenceNumber + 1;
            break;

        case VppHftSink::SendResult::DROPPED:
            m_statistics.samplesDropped++;
            break;

        case VppHftSink::SendResult::FAILED:
            m_statistics.samplesDropped++;
            m_statistics.sendFailures++;
            break;

        default:
            break;
    }

}

void VppHftExporter::logStatistics()
{
    // SWSS_LOG_ENTER(); // disabled: called after every sampling round

    Statistics snapshot;

    {
        std::lock_guard<std::mutex> lock(m_stateMutex);

        auto now = std::chrono::steady_clock::now();

        if (now < m_nextStatisticsLog)
        {
            return;
        }

        m_nextStatisticsLog = now + std::chrono::seconds(STATISTICS_LOG_PERIOD_SECONDS);

        snapshot = m_statistics;
    }

    SWSS_LOG_NOTICE("high frequency telemetry: sent %llu, dropped %llu, stats failures %llu, "
            "send failures %llu, overruns %llu",
            static_cast<unsigned long long>(snapshot.samplesSent),
            static_cast<unsigned long long>(snapshot.samplesDropped),
            static_cast<unsigned long long>(snapshot.statsFailures),
            static_cast<unsigned long long>(snapshot.sendFailures),
            static_cast<unsigned long long>(snapshot.overruns));
}
