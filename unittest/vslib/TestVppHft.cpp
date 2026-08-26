#include "vpp/TamIpfixBuilder.h"
#include "vpp/VppHftExporter.h"
#include "vpp/VppHftNetlinkSender.h"
#include "vpp/vppxlate/SaiIntfStats.h"
#include "vpp/vppxlate/SaiVppStatsReader.h"

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <cstdlib>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

using namespace saivs;

namespace
{
    constexpr sai_object_id_t TEL_TYPE_ID = 0x4b000000000001;
    constexpr sai_object_id_t TEL_TYPE_ID_2 = 0x4b000000000002;
    constexpr sai_object_id_t PORT_ID = 0x1000000000001;

    constexpr uint32_t OBSERVATION_DOMAIN = 0x2a;
    constexpr uint32_t EXPORT_TIME = 0x11223344;

    /** Deterministic stats source under full test control. */
    class FakeStatsSource:
        public VppHftStatsSource
    {
        public:

            virtual SampleResult sample(
                    const std::vector<std::string>& interfaces,
                    std::vector<vpp_interface_sample_t>& samples) override
            {
                std::unique_lock<std::mutex> lock(m_mutex);

                m_sampleCount++;
                m_lastInterfaces = interfaces;

                m_cv.notify_all();

                while (m_block)
                {
                    m_cv.wait(lock);
                }

                samples.assign(interfaces.size(), m_sample);

                return m_result;
            }

            virtual void disconnect() override
            {
                m_disconnected = true;
            }

            void waitForSamples(
                    uint64_t count)
            {
                std::unique_lock<std::mutex> lock(m_mutex);

                m_cv.wait_for(lock, std::chrono::seconds(5), [&]() { return m_sampleCount >= count; });
            }

            uint64_t getSampleCount()
            {
                std::lock_guard<std::mutex> lock(m_mutex);

                return m_sampleCount;
            }

            std::vector<std::string> getLastInterfaces()
            {
                std::lock_guard<std::mutex> lock(m_mutex);

                return m_lastInterfaces;
            }

            void setResult(
                    SampleResult result)
            {
                std::lock_guard<std::mutex> lock(m_mutex);

                m_result = result;
            }

            void setSample(
                    const vpp_interface_sample_t& sample)
            {
                std::lock_guard<std::mutex> lock(m_mutex);

                m_sample = sample;
            }

        public:

            std::mutex m_mutex;
            std::condition_variable m_cv;
            bool m_block = false;
            bool m_disconnected = false;
            uint64_t m_sampleCount = 0;
            SampleResult m_result = SampleResult::OK;
            vpp_interface_sample_t m_sample = vpp_interface_sample_t();
            std::vector<std::string> m_lastInterfaces;
    };

    /** Recording sink that can block inside send() to exercise the fence. */
    class FakeSink:
        public VppHftSink
    {
        public:

            virtual SendResult send(
                    const uint8_t *data,
                    size_t size) override
            {
                std::unique_lock<std::mutex> lock(m_mutex);

                m_inSend = true;

                m_cv.notify_all();

                while (m_block)
                {
                    m_cv.wait(lock);
                }

                if (m_result == SendResult::OK)
                {
                    m_messages.push_back(std::vector<uint8_t>(data, data + size));
                }

                m_inSend = false;

                m_cv.notify_all();

                return m_result;
            }

            virtual void close() override
            {
                m_closed = true;
            }

            void waitForMessages(
                    size_t count)
            {
                std::unique_lock<std::mutex> lock(m_mutex);

                m_cv.wait_for(lock, std::chrono::seconds(5), [&]() { return m_messages.size() >= count; });
            }

            void waitUntilInSend()
            {
                std::unique_lock<std::mutex> lock(m_mutex);

                m_cv.wait_for(lock, std::chrono::seconds(5), [&]() { return m_inSend; });
            }

            void block()
            {
                std::lock_guard<std::mutex> lock(m_mutex);

                m_block = true;
            }

            void unblock()
            {
                {
                    std::lock_guard<std::mutex> lock(m_mutex);

                    m_block = false;
                }

                m_cv.notify_all();
            }

            size_t getMessageCount()
            {
                std::lock_guard<std::mutex> lock(m_mutex);

                return m_messages.size();
            }

            void setResult(
                    SendResult result)
            {
                std::lock_guard<std::mutex> lock(m_mutex);

                m_result = result;
            }

            std::vector<std::vector<uint8_t>> getMessages()
            {
                std::lock_guard<std::mutex> lock(m_mutex);

                return m_messages;
            }

        public:

            std::mutex m_mutex;
            std::condition_variable m_cv;
            bool m_block = false;
            bool m_inSend = false;
            bool m_closed = false;
            SendResult m_result = SendResult::OK;
            std::vector<std::vector<uint8_t>> m_messages;
    };

    vpp_interface_sample_t makeCompleteSample()
    {
        vpp_interface_sample_t sample = vpp_interface_sample_t();

        sample.stats.rx_bytes = 111;
        sample.stats.tx_bytes = 222;
        sample.stats.drops = 333;
        sample.stats.tx_error = 444;

        sample.present = VPP_INTF_STAT_PRESENT_RX |
                         VPP_INTF_STAT_PRESENT_TX |
                         VPP_INTF_STAT_PRESENT_DROPS |
                         VPP_INTF_STAT_PRESENT_TX_ERROR;

        return sample;
    }

    std::shared_ptr<VppHftStreamConfig> makeStreamConfig(
            uint16_t templateId = TamIpfixBuilder::MIN_TEMPLATE_ID,
            int64_t intervalUs = 1000,
            sai_object_id_t telemetryTypeId = TEL_TYPE_ID)
    {
        auto config = std::make_shared<VppHftStreamConfig>();

        config->telemetryTypeId = telemetryTypeId;
        config->templateId = templateId;
        config->observationDomainId = OBSERVATION_DOMAIN;
        config->pollingInterval = std::chrono::microseconds(intervalUs);
        config->interfaces.push_back("bobm0");

        const sai_stat_id_t statIds[] = {
            SAI_PORT_STAT_IF_IN_OCTETS,
            SAI_PORT_STAT_IF_IN_DISCARDS,
            SAI_PORT_STAT_IF_OUT_OCTETS,
            SAI_PORT_STAT_IF_OUT_ERRORS,
        };

        std::vector<TamIpfixBuilder::Field> templateFields;

        for (auto statId: statIds)
        {
            VppHftCounterField field;

            field.label = 1;
            field.portId = PORT_ID;
            field.statId = statId;
            field.vppInterfaceName = "bobm0";
            field.interfaceIndex = 0;

            config->fields.push_back(field);

            TamIpfixBuilder::Field templateField;

            templateField.label = 1;
            templateField.objectType = static_cast<uint32_t>(SAI_OBJECT_TYPE_PORT);
            templateField.statId = static_cast<uint32_t>(statId);

            templateFields.push_back(templateField);
        }

        std::string error;

        EXPECT_TRUE(TamIpfixBuilder::buildTemplateMessage(
                    config->templateId,
                    config->observationDomainId,
                    EXPORT_TIME,
                    templateFields,
                    config->templateMessage,
                    error)) << error;

        return config;
    }

    uint16_t readU16(
            const std::vector<uint8_t>& message,
            size_t offset)
    {
        return static_cast<uint16_t>(
                (static_cast<uint16_t>(message.at(offset)) << 8) | message.at(offset + 1));
    }

    uint32_t readU32(
            const std::vector<uint8_t>& message,
            size_t offset)
    {
        return (static_cast<uint32_t>(message.at(offset)) << 24) |
               (static_cast<uint32_t>(message.at(offset + 1)) << 16) |
               (static_cast<uint32_t>(message.at(offset + 2)) << 8) |
               static_cast<uint32_t>(message.at(offset + 3));
    }

    uint64_t readU64(
            const std::vector<uint8_t>& message,
            size_t offset)
    {
        uint64_t value = 0;

        for (size_t i = 0; i < 8; i++)
        {
            value = (value << 8) | message.at(offset + i);
        }

        return value;
    }
}

// ---------------------------------------------------------------------------
// Streaming statistics capability
// ---------------------------------------------------------------------------

TEST(VppHftCapability, PortStatIdsAreStableAndSupported)
{
    // The golden IPFIX bytes below encode these SAI values directly, so a
    // change of the SAI enumeration must fail loudly here.
    EXPECT_EQ(0u, static_cast<uint32_t>(SAI_PORT_STAT_IF_IN_OCTETS));
    EXPECT_EQ(3u, static_cast<uint32_t>(SAI_PORT_STAT_IF_IN_DISCARDS));
    EXPECT_EQ(9u, static_cast<uint32_t>(SAI_PORT_STAT_IF_OUT_OCTETS));
    EXPECT_EQ(13u, static_cast<uint32_t>(SAI_PORT_STAT_IF_OUT_ERRORS));
    EXPECT_EQ(1u, static_cast<uint32_t>(SAI_OBJECT_TYPE_PORT));

    EXPECT_EQ(4u, VppHftExporter::supportedPortStats().size());

    EXPECT_TRUE(VppHftExporter::isSupportedPortStat(SAI_PORT_STAT_IF_IN_OCTETS));
    EXPECT_TRUE(VppHftExporter::isSupportedPortStat(SAI_PORT_STAT_IF_IN_DISCARDS));
    EXPECT_TRUE(VppHftExporter::isSupportedPortStat(SAI_PORT_STAT_IF_OUT_OCTETS));
    EXPECT_TRUE(VppHftExporter::isSupportedPortStat(SAI_PORT_STAT_IF_OUT_ERRORS));

    // Aggregate packet vectors are not a truthful unicast source.
    EXPECT_FALSE(VppHftExporter::isSupportedPortStat(SAI_PORT_STAT_IF_IN_UCAST_PKTS));
    EXPECT_FALSE(VppHftExporter::isSupportedPortStat(SAI_PORT_STAT_IF_OUT_UCAST_PKTS));
    EXPECT_FALSE(VppHftExporter::isSupportedPortStat(SAI_PORT_STAT_IF_IN_ERRORS));
}

TEST(VppHftCapability, TwoCallBufferContract)
{
    EXPECT_EQ(SAI_STATUS_INVALID_PARAMETER, VppHftExporter::queryPortStatsStCapability(nullptr));

    sai_stat_st_capability_list_t capability;

    capability.count = 0;
    capability.list = nullptr;

    EXPECT_EQ(SAI_STATUS_BUFFER_OVERFLOW, VppHftExporter::queryPortStatsStCapability(&capability));
    EXPECT_EQ(4u, capability.count);

    std::vector<sai_stat_st_capability_t> tooSmall(capability.count - 1);

    capability.count = static_cast<uint32_t>(tooSmall.size());
    capability.list = tooSmall.data();

    EXPECT_EQ(SAI_STATUS_BUFFER_OVERFLOW, VppHftExporter::queryPortStatsStCapability(&capability));
    EXPECT_EQ(4u, capability.count);

    std::vector<sai_stat_st_capability_t> list(capability.count);

    capability.count = static_cast<uint32_t>(list.size());
    capability.list = list.data();

    EXPECT_EQ(SAI_STATUS_SUCCESS, VppHftExporter::queryPortStatsStCapability(&capability));
    EXPECT_EQ(4u, capability.count);

    const sai_stat_id_t expected[] = {
        SAI_PORT_STAT_IF_IN_OCTETS,
        SAI_PORT_STAT_IF_IN_DISCARDS,
        SAI_PORT_STAT_IF_OUT_OCTETS,
        SAI_PORT_STAT_IF_OUT_ERRORS,
    };

    for (uint32_t i = 0; i < capability.count; i++)
    {
        EXPECT_EQ(expected[i], list[i].capability.stat_enum);
        EXPECT_EQ(static_cast<uint32_t>(SAI_STATS_MODE_READ), list[i].capability.stat_modes);
        EXPECT_EQ(10000000ULL, list[i].minimal_polling_interval);
    }
}

TEST(VppHftIpfix, TemplateUsesSaiTwoCallListContract)
{
    const std::vector<uint8_t> message = { 0x00, 0x0a, 0x00, 0x10 };

    sai_u8_list_t list;

    list.count = 0;
    list.list = nullptr;

    EXPECT_EQ(
            SAI_STATUS_BUFFER_OVERFLOW,
            VppHftExporter::copyTemplateToSaiList(message, list));
    EXPECT_EQ(message.size(), list.count);

    std::vector<uint8_t> tooSmall(message.size() - 1);

    list.count = static_cast<uint32_t>(tooSmall.size());
    list.list = tooSmall.data();

    EXPECT_EQ(
            SAI_STATUS_BUFFER_OVERFLOW,
            VppHftExporter::copyTemplateToSaiList(message, list));
    EXPECT_EQ(message.size(), list.count);

    std::vector<uint8_t> output(message.size());

    list.count = static_cast<uint32_t>(output.size());
    list.list = output.data();

    EXPECT_EQ(
            SAI_STATUS_SUCCESS,
            VppHftExporter::copyTemplateToSaiList(message, list));
    EXPECT_EQ(message.size(), list.count);
    EXPECT_EQ(message, output);
}

// ---------------------------------------------------------------------------
// IPFIX encoding
// ---------------------------------------------------------------------------

TEST(VppHftIpfix, TemplateGoldenBytes)
{
    std::vector<TamIpfixBuilder::Field> fields = {
        { 1, 1, 0 },
        { 1, 1, 3 },
        { 1, 1, 9 },
        { 1, 1, 13 },
    };

    std::vector<uint8_t> message;
    std::string error;

    ASSERT_TRUE(TamIpfixBuilder::buildTemplateMessage(256, OBSERVATION_DOMAIN, EXPORT_TIME, fields, message, error))
            << error;

    const std::vector<uint8_t> expected = {
        0x00, 0x0a,             // version 10
        0x00, 0x3c,             // message length 60
        0x11, 0x22, 0x33, 0x44, // export time
        0x00, 0x00, 0x00, 0x00, // sequence number, always 0 in a template
        0x00, 0x00, 0x00, 0x2a, // observation domain
        0x00, 0x02,             // template set id
        0x00, 0x2c,             // set length 44
        0x01, 0x00,             // template id 256
        0x00, 0x05,             // field count, 4 counters plus observation time
        0x01, 0x45, 0x00, 0x08, // observationTimeNanoseconds (325), length 8
        0x80, 0x01, 0x00, 0x08, 0x00, 0x01, 0x00, 0x00, // label 1, PORT, IF_IN_OCTETS
        0x80, 0x01, 0x00, 0x08, 0x00, 0x01, 0x00, 0x03, // label 1, PORT, IF_IN_DISCARDS
        0x80, 0x01, 0x00, 0x08, 0x00, 0x01, 0x00, 0x09, // label 1, PORT, IF_OUT_OCTETS
        0x80, 0x01, 0x00, 0x08, 0x00, 0x01, 0x00, 0x0d, // label 1, PORT, IF_OUT_ERRORS
    };

    EXPECT_EQ(expected, message);
}

TEST(VppHftIpfix, DataRecordGoldenBytes)
{
    std::vector<uint64_t> values = { 1, 2, 3, 4 };

    std::vector<uint8_t> message;
    std::string error;

    ASSERT_TRUE(TamIpfixBuilder::buildDataMessage(
                256,
                OBSERVATION_DOMAIN,
                EXPORT_TIME,
                7,
                0x0000112233445566ULL,
                values,
                message,
                error)) << error;

    const std::vector<uint8_t> expected = {
        0x00, 0x0a,
        0x00, 0x3c,             // message length 60
        0x11, 0x22, 0x33, 0x44, // export time
        0x00, 0x00, 0x00, 0x07, // sequence number
        0x00, 0x00, 0x00, 0x2a, // observation domain
        0x01, 0x00,             // set id equals the template id
        0x00, 0x2c,             // set length 44
        0x00, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, // observation time in ns
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04,
    };

    EXPECT_EQ(expected, message);
}

TEST(VppHftIpfix, EnterpriseNumberPacking)
{
    uint32_t enterpriseNumber = 0;

    ASSERT_TRUE(TamIpfixBuilder::packEnterpriseNumber(1, 13, enterpriseNumber));
    EXPECT_EQ(0x0001000dU, enterpriseNumber);

    // The high bit of each half is reserved for the SAI extension range flag.
    ASSERT_TRUE(TamIpfixBuilder::packEnterpriseNumber(0x7fff, 0x7fff, enterpriseNumber));
    EXPECT_EQ(0x7fff7fffU, enterpriseNumber);

    EXPECT_FALSE(TamIpfixBuilder::packEnterpriseNumber(0x10000, 1, enterpriseNumber));
    EXPECT_FALSE(TamIpfixBuilder::packEnterpriseNumber(1, 0x10000, enterpriseNumber));
}

TEST(VppHftIpfix, FieldValidation)
{
    std::string error;

    EXPECT_FALSE(TamIpfixBuilder::validateFields({}, error));

    EXPECT_FALSE(TamIpfixBuilder::validateFields({ { 0, 1, 0 } }, error));

    EXPECT_FALSE(TamIpfixBuilder::validateFields({ { 0x8000, 1, 0 } }, error));

    // One label per monitored object, repeated for each of its statistics.
    EXPECT_TRUE(TamIpfixBuilder::validateFields({ { 1, 1, 0 }, { 1, 1, 3 }, { 2, 1, 0 } }, error)) << error;

    EXPECT_FALSE(TamIpfixBuilder::validateFields({ { 1, 1, 0 }, { 1, 1, 0 } }, error));

    EXPECT_FALSE(TamIpfixBuilder::validateFields({ { 2, 1, 0 }, { 1, 1, 0 } }, error));

    EXPECT_FALSE(TamIpfixBuilder::validateFields({ { 1, 1, 3 }, { 1, 1, 0 } }, error));
}

TEST(VppHftIpfix, SizeAndTemplateIdLimits)
{
    std::vector<uint8_t> message;
    std::string error;

    EXPECT_FALSE(TamIpfixBuilder::buildTemplateMessage(255, 0, 0, { { 1, 1, 0 } }, message, error));
    EXPECT_TRUE(message.empty());

    EXPECT_FALSE(TamIpfixBuilder::buildDataMessage(255, 0, 0, 0, 0, { 1 }, message, error));
    EXPECT_TRUE(message.empty());

    EXPECT_FALSE(TamIpfixBuilder::buildDataMessage(256, 0, 0, 0, 0, {}, message, error));

    // 16 byte message header, 12 byte set and template header, 8 bytes per field
    const size_t maxFields = (0xffffu - 28) / 8;

    std::vector<TamIpfixBuilder::Field> fields;

    for (size_t i = 0; i < maxFields; i++)
    {
        TamIpfixBuilder::Field field;

        field.label = static_cast<uint16_t>(i + 1);
        field.objectType = 1;
        field.statId = 0;

        fields.push_back(field);
    }

    ASSERT_TRUE(TamIpfixBuilder::buildTemplateMessage(256, 0, 0, fields, message, error)) << error;
    EXPECT_LE(message.size(), 0xffffu);

    TamIpfixBuilder::Field extra;

    extra.label = static_cast<uint16_t>(maxFields + 1);
    extra.objectType = 1;
    extra.statId = 0;

    fields.push_back(extra);

    EXPECT_FALSE(TamIpfixBuilder::buildTemplateMessage(256, 0, 0, fields, message, error));
    EXPECT_TRUE(message.empty());

    EXPECT_EQ(0xffffu - 4u, VppHftNetlinkSender::MAX_PAYLOAD_SIZE);
}

// ---------------------------------------------------------------------------
// Counter mapping
// ---------------------------------------------------------------------------

TEST(VppHftMapping, SupportedStatsUseTheSharedVppSource)
{
    auto sample = makeCompleteSample();

    uint64_t value = 0;

    ASSERT_TRUE(VppHftExporter::mapPortStat(SAI_PORT_STAT_IF_IN_OCTETS, sample, value));
    EXPECT_EQ(111u, value);

    ASSERT_TRUE(VppHftExporter::mapPortStat(SAI_PORT_STAT_IF_OUT_OCTETS, sample, value));
    EXPECT_EQ(222u, value);

    // VPP reports one drop counter per interface for both directions.
    ASSERT_TRUE(VppHftExporter::mapPortStat(SAI_PORT_STAT_IF_IN_DISCARDS, sample, value));
    EXPECT_EQ(333u, value);

    ASSERT_TRUE(VppHftExporter::mapPortStat(SAI_PORT_STAT_IF_OUT_ERRORS, sample, value));
    EXPECT_EQ(444u, value);

    EXPECT_FALSE(VppHftExporter::mapPortStat(SAI_PORT_STAT_IF_IN_UCAST_PKTS, sample, value));
}

TEST(VppHftMapping, AbsentCounterIsNotSubstitutedWithZero)
{
    auto sample = makeCompleteSample();

    sample.present &= ~static_cast<uint32_t>(VPP_INTF_STAT_PRESENT_DROPS);

    uint64_t value = 0;

    EXPECT_FALSE(VppHftExporter::mapPortStat(SAI_PORT_STAT_IF_IN_DISCARDS, sample, value));
    EXPECT_TRUE(VppHftExporter::mapPortStat(SAI_PORT_STAT_IF_IN_OCTETS, sample, value));
}

TEST(VppHftMapping, SharedAccumulationHelpersAreReentrant)
{
    // The synchronous SwitchVpp port statistics path and the telemetry worker
    // call these helpers from different threads, so they must be stateless.
    auto worker = [](vpp_interface_stats_t *stats, uint32_t *present)
    {
        for (int i = 0; i < 10000; i++)
        {
            vpp_intf_stats_accumulate_two("rx", 1, 2, stats, present);
            vpp_intf_stats_accumulate_one("drops", 3, stats, present);
        }
    };

    vpp_interface_stats_t first;
    vpp_interface_stats_t second;

    uint32_t firstPresent = 0;
    uint32_t secondPresent = 0;

    memset(&first, 0, sizeof(first));
    memset(&second, 0, sizeof(second));

    std::thread a(worker, &first, &firstPresent);
    std::thread b(worker, &second, &secondPresent);

    a.join();
    b.join();

    EXPECT_EQ(10000u, first.rx);
    EXPECT_EQ(20000u, first.rx_bytes);
    EXPECT_EQ(30000u, first.drops);
    EXPECT_EQ(first.rx, second.rx);
    EXPECT_EQ(first.rx_bytes, second.rx_bytes);
    EXPECT_EQ(first.drops, second.drops);
    EXPECT_EQ(firstPresent, secondPresent);
    EXPECT_NE(0u, firstPresent & VPP_INTF_STAT_PRESENT_RX);
    EXPECT_NE(0u, firstPresent & VPP_INTF_STAT_PRESENT_DROPS);
}

// ---------------------------------------------------------------------------
// Exporter lifecycle
// ---------------------------------------------------------------------------

TEST(VppHftStatsReader, InterfacePatternsAreAnchoredAndEscaped)
{
    char *pattern = vpp_stats_reader_build_pattern("bobm0");

    ASSERT_NE(nullptr, pattern);

    // Anchored and terminated by the separator so "bobm1" cannot match
    // "/interfaces/bobm10/rx".
    EXPECT_STREQ("^/interfaces/bobm0/", pattern);

    free(pattern);

    // stat_segment_ls_r() compiles the pattern as a POSIX basic regular
    // expression, so a sub interface dot must be escaped.
    pattern = vpp_stats_reader_build_pattern("Gig0.100");

    ASSERT_NE(nullptr, pattern);

    EXPECT_STREQ("^/interfaces/Gig0\\.100/", pattern);

    free(pattern);
}

TEST(VppHftStatsReader, DumpedEntryNamesResolveToTheRequestedInterface)
{
    const char *names[] = { "bobm0", "bobm1" };

    const char *counter = nullptr;

    EXPECT_EQ(0u, vpp_stats_reader_resolve_interface("/interfaces/bobm0/rx", names, 2, &counter));
    EXPECT_STREQ("rx", counter);

    counter = nullptr;

    EXPECT_EQ(1u, vpp_stats_reader_resolve_interface("/interfaces/bobm1/tx-error", names, 2, &counter));
    EXPECT_STREQ("tx-error", counter);

    // A different interface, a different subtree and a malformed name are all
    // ignored rather than attributed to a requested interface.
    EXPECT_EQ(~0u, vpp_stats_reader_resolve_interface("/interfaces/bobm10/rx", names, 2, &counter));
    EXPECT_EQ(~0u, vpp_stats_reader_resolve_interface("/buffer-pools/default-numa-0/used", names, 2, &counter));
    EXPECT_EQ(~0u, vpp_stats_reader_resolve_interface("/interfaces/", names, 2, &counter));
}

TEST(VppHftExporterTest, StreamLifecycleEmitsOnlyWhileStarted)
{
    auto source = new FakeStatsSource();
    auto sink = new FakeSink();

    source->setSample(makeCompleteSample());

    VppHftExporter exporter {
            std::unique_ptr<VppHftStatsSource>(source),
            std::unique_ptr<VppHftSink>(sink) };

    ASSERT_TRUE(exporter.ownsStatsEndpoint());

    auto config = makeStreamConfig();

    ASSERT_EQ(SAI_STATUS_SUCCESS, exporter.commitStream(config));

    ASSERT_NE(nullptr, exporter.getStream(TEL_TYPE_ID));

    // A committed but stopped stream must not emit.
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    EXPECT_EQ(0u, sink->getMessageCount());

    ASSERT_EQ(SAI_STATUS_SUCCESS, exporter.startStream(TEL_TYPE_ID));

    sink->waitForMessages(2);

    ASSERT_GE(sink->getMessageCount(), 2u);

    EXPECT_EQ(std::vector<std::string>({ "bobm0" }), source->getLastInterfaces());

    exporter.stopStream(TEL_TYPE_ID);

    size_t afterStop = sink->getMessageCount();

    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    EXPECT_EQ(afterStop, sink->getMessageCount());

    // Restarting resumes emission from the same committed snapshot.
    ASSERT_EQ(SAI_STATUS_SUCCESS, exporter.startStream(TEL_TYPE_ID));

    sink->waitForMessages(afterStop + 1);

    EXPECT_GT(sink->getMessageCount(), afterStop);

    exporter.removeStream(TEL_TYPE_ID);

    EXPECT_EQ(nullptr, exporter.getStream(TEL_TYPE_ID));

    size_t afterRemove = sink->getMessageCount();

    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    EXPECT_EQ(afterRemove, sink->getMessageCount());

    EXPECT_EQ(SAI_STATUS_INVALID_PARAMETER, exporter.startStream(TEL_TYPE_ID));
}

TEST(VppHftExporterTest, EmittedRecordsMatchTheCommittedTemplate)
{
    auto source = new FakeStatsSource();
    auto sink = new FakeSink();

    source->setSample(makeCompleteSample());

    VppHftExporter exporter {
            std::unique_ptr<VppHftStatsSource>(source),
            std::unique_ptr<VppHftSink>(sink) };

    auto config = makeStreamConfig(300);

    ASSERT_EQ(SAI_STATUS_SUCCESS, exporter.commitStream(config));
    ASSERT_EQ(SAI_STATUS_SUCCESS, exporter.startStream(TEL_TYPE_ID));

    sink->waitForMessages(3);

    exporter.stopStream(TEL_TYPE_ID);

    auto messages = sink->getMessages();

    ASSERT_GE(messages.size(), 3u);

    for (size_t i = 0; i < messages.size(); i++)
    {
        const auto& message = messages[i];

        // 16 byte header, 4 byte set header, observation time and four counters
        ASSERT_EQ(60u, message.size());

        EXPECT_EQ(10u, readU16(message, 0));
        EXPECT_EQ(60u, readU16(message, 2));

        // The data set id equals the committed template id.
        EXPECT_EQ(config->templateId, readU16(message, 16));
        EXPECT_EQ(44u, readU16(message, 18));

        EXPECT_EQ(OBSERVATION_DOMAIN, readU32(message, 12));

        // The sequence number counts previously emitted data records.
        EXPECT_EQ(static_cast<uint32_t>(i), readU32(message, 8));

        EXPECT_NE(0u, readU64(message, 20));

        EXPECT_EQ(111u, readU64(message, 28));
        EXPECT_EQ(333u, readU64(message, 36));
        EXPECT_EQ(222u, readU64(message, 44));
        EXPECT_EQ(444u, readU64(message, 52));
    }
}

TEST(VppHftExporterTest, StopWaitsForTheInProgressSend)
{
    auto source = new FakeStatsSource();
    auto sink = new FakeSink();

    source->setSample(makeCompleteSample());

    VppHftExporter exporter {
            std::unique_ptr<VppHftStatsSource>(source),
            std::unique_ptr<VppHftSink>(sink) };

    auto config = makeStreamConfig();

    ASSERT_EQ(SAI_STATUS_SUCCESS, exporter.commitStream(config));

    sink->block();

    ASSERT_EQ(SAI_STATUS_SUCCESS, exporter.startStream(TEL_TYPE_ID));

    sink->waitUntilInSend();

    std::atomic<bool> stopped(false);

    std::thread stopper([&]()
            {
                exporter.stopStream(TEL_TYPE_ID);
                stopped.store(true);
            });

    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // The send fence is held by the worker, so stop must not have returned.
    EXPECT_FALSE(stopped.load());

    sink->unblock();

    stopper.join();

    EXPECT_TRUE(stopped.load());

    size_t afterStop = sink->getMessageCount();

    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    EXPECT_EQ(afterStop, sink->getMessageCount());

    ASSERT_EQ(SAI_STATUS_SUCCESS, exporter.startStream(TEL_TYPE_ID));

    sink->waitForMessages(afterStop + 1);

    exporter.stopStream(TEL_TYPE_ID);

    auto messages = sink->getMessages();

    ASSERT_GE(messages.size(), 2u);
    EXPECT_EQ(0u, readU32(messages[0], 8));
    EXPECT_EQ(1u, readU32(messages[1], 8));
}

TEST(VppHftExporterTest, PollingIntervalUpdateKeepsRunningStreamActive)
{
    auto source = new FakeStatsSource();
    auto sink = new FakeSink();

    source->setSample(makeCompleteSample());

    VppHftExporter exporter {
            std::unique_ptr<VppHftStatsSource>(source),
            std::unique_ptr<VppHftSink>(sink) };

    auto config = makeStreamConfig(
            TamIpfixBuilder::MIN_TEMPLATE_ID,
            60LL * 1000LL * 1000LL);

    ASSERT_EQ(SAI_STATUS_SUCCESS, exporter.commitStream(config));
    ASSERT_EQ(SAI_STATUS_SUCCESS, exporter.startStream(TEL_TYPE_ID));
    ASSERT_EQ(SAI_STATUS_SUCCESS, exporter.updatePollingIntervals(
                { TEL_TYPE_ID },
                std::chrono::milliseconds(10)));

    sink->waitForMessages(1);

    EXPECT_GE(sink->getMessageCount(), 1u);

    auto updated = exporter.getStream(TEL_TYPE_ID);

    ASSERT_NE(nullptr, updated);
    EXPECT_EQ(std::chrono::milliseconds(10), updated->pollingInterval);

    exporter.stopStream(TEL_TYPE_ID);
}

TEST(VppHftExporterTest, PollingIntervalUpdatePreservesStoppedState)
{
    auto source = new FakeStatsSource();
    auto sink = new FakeSink();

    source->setSample(makeCompleteSample());

    VppHftExporter exporter {
            std::unique_ptr<VppHftStatsSource>(source),
            std::unique_ptr<VppHftSink>(sink) };

    auto config = makeStreamConfig();

    ASSERT_EQ(SAI_STATUS_SUCCESS, exporter.commitStream(config));
    ASSERT_EQ(SAI_STATUS_SUCCESS, exporter.updatePollingIntervals(
                { TEL_TYPE_ID },
                std::chrono::milliseconds(10)));

    std::this_thread::sleep_for(std::chrono::milliseconds(30));
    EXPECT_EQ(0u, sink->getMessageCount());

    ASSERT_EQ(SAI_STATUS_SUCCESS, exporter.startStream(TEL_TYPE_ID));
    sink->waitForMessages(1);
    EXPECT_GE(sink->getMessageCount(), 1u);

    exporter.stopStream(TEL_TYPE_ID);
}

TEST(VppHftExporterTest, PollingIntervalBulkUpdateRejectsAtomically)
{
    auto source = new FakeStatsSource();
    auto sink = new FakeSink();

    VppHftExporter exporter {
            std::unique_ptr<VppHftStatsSource>(source),
            std::unique_ptr<VppHftSink>(sink) };

    auto first = makeStreamConfig(300, 1000, TEL_TYPE_ID);
    auto second = makeStreamConfig(301, 2000, TEL_TYPE_ID_2);

    ASSERT_EQ(SAI_STATUS_SUCCESS, exporter.commitStream(first));
    ASSERT_EQ(SAI_STATUS_SUCCESS, exporter.commitStream(second));

    EXPECT_EQ(SAI_STATUS_ITEM_NOT_FOUND, exporter.updatePollingIntervals(
                { TEL_TYPE_ID, static_cast<sai_object_id_t>(0xdeadbeef) },
                std::chrono::milliseconds(10)));

    EXPECT_EQ(std::chrono::microseconds(1000),
            exporter.getStream(TEL_TYPE_ID)->pollingInterval);
    EXPECT_EQ(std::chrono::microseconds(2000),
            exporter.getStream(TEL_TYPE_ID_2)->pollingInterval);
}

TEST(VppHftExporterTest, SequenceNumbersAreSharedByObservationDomain)
{
    auto source = new FakeStatsSource();
    auto sink = new FakeSink();

    source->setSample(makeCompleteSample());

    VppHftExporter exporter {
            std::unique_ptr<VppHftStatsSource>(source),
            std::unique_ptr<VppHftSink>(sink) };

    auto first = makeStreamConfig(300, 1000, TEL_TYPE_ID);
    auto second = makeStreamConfig(301, 1000, TEL_TYPE_ID_2);

    ASSERT_EQ(SAI_STATUS_SUCCESS, exporter.commitStream(first));
    ASSERT_EQ(SAI_STATUS_SUCCESS, exporter.commitStream(second));
    ASSERT_EQ(SAI_STATUS_SUCCESS, exporter.startStream(TEL_TYPE_ID));
    ASSERT_EQ(SAI_STATUS_SUCCESS, exporter.startStream(TEL_TYPE_ID_2));

    sink->waitForMessages(6);

    exporter.stopStream(TEL_TYPE_ID);
    exporter.stopStream(TEL_TYPE_ID_2);

    auto messages = sink->getMessages();

    ASSERT_GE(messages.size(), 6u);

    for (size_t i = 0; i < messages.size(); i++)
    {
        EXPECT_EQ(static_cast<uint32_t>(i), readU32(messages[i], 8));
    }
}

TEST(VppHftExporterTest, DroppedSendDoesNotConsumeSequenceNumber)
{
    auto source = new FakeStatsSource();
    auto sink = new FakeSink();

    source->setSample(makeCompleteSample());
    sink->setResult(VppHftSink::SendResult::DROPPED);

    VppHftExporter exporter {
            std::unique_ptr<VppHftStatsSource>(source),
            std::unique_ptr<VppHftSink>(sink) };

    auto config = makeStreamConfig();

    ASSERT_EQ(SAI_STATUS_SUCCESS, exporter.commitStream(config));
    ASSERT_EQ(SAI_STATUS_SUCCESS, exporter.startStream(TEL_TYPE_ID));

    source->waitForSamples(3);

    EXPECT_EQ(0u, sink->getMessageCount());

    sink->setResult(VppHftSink::SendResult::OK);
    sink->waitForMessages(1);

    exporter.stopStream(TEL_TYPE_ID);

    auto messages = sink->getMessages();

    ASSERT_FALSE(messages.empty());
    EXPECT_EQ(0u, readU32(messages.front(), 8));
}

TEST(VppHftExporterTest, TransientStatsFailuresDropSamples)
{
    auto source = new FakeStatsSource();
    auto sink = new FakeSink();

    source->setSample(makeCompleteSample());
    source->setResult(VppHftStatsSource::SampleResult::RETRY);

    VppHftExporter exporter {
            std::unique_ptr<VppHftStatsSource>(source),
            std::unique_ptr<VppHftSink>(sink) };

    auto config = makeStreamConfig();

    ASSERT_EQ(SAI_STATUS_SUCCESS, exporter.commitStream(config));
    ASSERT_EQ(SAI_STATUS_SUCCESS, exporter.startStream(TEL_TYPE_ID));

    source->waitForSamples(3);

    auto retryStatistics = exporter.getStatistics();

    EXPECT_EQ(0u, sink->getMessageCount());
    EXPECT_GE(retryStatistics.samplesDropped, 3u);

    // A statistics segment epoch change or a bounded access timeout must not
    // be counted as a connection failure.
    EXPECT_EQ(0u, retryStatistics.statsFailures);

    source->setResult(VppHftStatsSource::SampleResult::FAILED);

    source->waitForSamples(retryStatistics.samplesDropped + 3);

    EXPECT_GT(exporter.getStatistics().statsFailures, 0u);
    EXPECT_EQ(0u, sink->getMessageCount());

    exporter.stopStream(TEL_TYPE_ID);
}

TEST(VppHftExporterTest, AbsentCounterDropsTheWholeRecord)
{
    auto source = new FakeStatsSource();
    auto sink = new FakeSink();

    auto sample = makeCompleteSample();

    sample.present &= ~static_cast<uint32_t>(VPP_INTF_STAT_PRESENT_TX_ERROR);

    source->setSample(sample);

    VppHftExporter exporter {
            std::unique_ptr<VppHftStatsSource>(source),
            std::unique_ptr<VppHftSink>(sink) };

    auto config = makeStreamConfig();

    ASSERT_EQ(SAI_STATUS_SUCCESS, exporter.commitStream(config));
    ASSERT_EQ(SAI_STATUS_SUCCESS, exporter.startStream(TEL_TYPE_ID));

    source->waitForSamples(3);

    EXPECT_EQ(0u, sink->getMessageCount());
    EXPECT_GE(exporter.getStatistics().samplesDropped, 3u);

    exporter.stopStream(TEL_TYPE_ID);
}

TEST(VppHftExporterTest, RejectsIncompleteConfiguration)
{
    auto source = new FakeStatsSource();
    auto sink = new FakeSink();

    VppHftExporter exporter {
            std::unique_ptr<VppHftStatsSource>(source),
            std::unique_ptr<VppHftSink>(sink) };

    EXPECT_EQ(SAI_STATUS_INVALID_PARAMETER, exporter.commitStream(nullptr));

    auto config = makeStreamConfig();

    config->fields.clear();

    EXPECT_EQ(SAI_STATUS_INVALID_PARAMETER, exporter.commitStream(config));

    auto noInterval = makeStreamConfig();

    noInterval->pollingInterval = std::chrono::microseconds(0);

    EXPECT_EQ(SAI_STATUS_INVALID_PARAMETER, exporter.commitStream(noInterval));

    EXPECT_EQ(nullptr, exporter.getStream(TEL_TYPE_ID));

    EXPECT_EQ(SAI_STATUS_INVALID_PARAMETER, exporter.startStream(TEL_TYPE_ID));
}

TEST(VppHftExporterTest, TemplateIdsDoNotCollideWithLiveStreams)
{
    auto source = new FakeStatsSource();
    auto sink = new FakeSink();

    VppHftExporter exporter {
            std::unique_ptr<VppHftStatsSource>(source),
            std::unique_ptr<VppHftSink>(sink) };

    uint16_t first = exporter.allocateTemplateId();

    EXPECT_GE(first, TamIpfixBuilder::MIN_TEMPLATE_ID);

    auto config = makeStreamConfig(first);

    ASSERT_EQ(SAI_STATUS_SUCCESS, exporter.commitStream(config));

    uint16_t second = exporter.allocateTemplateId();

    EXPECT_NE(first, second);
    EXPECT_GE(second, TamIpfixBuilder::MIN_TEMPLATE_ID);
}

TEST(VppHftExporterTest, SecondInstanceFailsClosed)
{
    VppHftExporter first {
            std::unique_ptr<VppHftStatsSource>(new FakeStatsSource()),
            std::unique_ptr<VppHftSink>(new FakeSink()) };

    EXPECT_TRUE(first.ownsStatsEndpoint());

    {
        VppHftExporter second {
                std::unique_ptr<VppHftStatsSource>(new FakeStatsSource()),
                std::unique_ptr<VppHftSink>(new FakeSink()) };

        EXPECT_FALSE(second.ownsStatsEndpoint());

        // The fixed VPP statistics endpoint cannot be shared, so the second
        // instance refuses to stream instead of reading it ambiguously.
        EXPECT_EQ(SAI_STATUS_NOT_SUPPORTED, second.commitStream(makeStreamConfig()));
    }

    // The claim is released with the owning exporter.
    EXPECT_TRUE(first.ownsStatsEndpoint());
}

TEST(VppHftExporterTest, ShutdownJoinsTheWorkerWhileStreaming)
{
    auto source = new FakeStatsSource();
    auto sink = new FakeSink();

    source->setSample(makeCompleteSample());

    {
        VppHftExporter exporter {
                std::unique_ptr<VppHftStatsSource>(source),
                std::unique_ptr<VppHftSink>(sink) };

        auto config = makeStreamConfig();

        ASSERT_EQ(SAI_STATUS_SUCCESS, exporter.commitStream(config));
        ASSERT_EQ(SAI_STATUS_SUCCESS, exporter.startStream(TEL_TYPE_ID));

        sink->waitForMessages(1);

        exporter.shutdown();

        // shutdown is idempotent and the destructor must not join twice.
        exporter.shutdown();

        EXPECT_TRUE(sink->m_closed);
        EXPECT_TRUE(source->m_disconnected);

        size_t afterShutdown = sink->getMessageCount();

        std::this_thread::sleep_for(std::chrono::milliseconds(50));

        EXPECT_EQ(afterShutdown, sink->getMessageCount());
    }

    // A new exporter can claim the endpoint once the previous one is gone.
    VppHftExporter next {
            std::unique_ptr<VppHftStatsSource>(new FakeStatsSource()),
            std::unique_ptr<VppHftSink>(new FakeSink()) };

    EXPECT_TRUE(next.ownsStatsEndpoint());
}
