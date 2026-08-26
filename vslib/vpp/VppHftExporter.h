#pragma once

#include "TamIpfixBuilder.h"
#include "VppHftTypes.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <map>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <thread>
#include <vector>

namespace saivs
{
    /**
     * @brief High frequency telemetry exporter for the VPP platform.
     *
     * The exporter owns one worker thread that samples the VPP statistics
     * segment for every started TAM telemetry stream, encodes one IPFIX data
     * message per sample and publishes it to the SONiC telemetry Generic
     * Netlink family.
     *
     * Threading contract:
     *
     * - SAI create, set and remove calls run on the API thread and publish
     *   immutable stream configurations under m_stateMutex.
     * - The worker copies the shared configuration pointer, releases
     *   m_stateMutex, and never holds it during VPP statistics or netlink I/O.
     * - STOP and replacement first mark the stream generation inactive under
     *   m_stateMutex, then take the outbound send fence exclusively so they
     *   return only after a send that already started has completed.
     * - The worker takes the send fence in shared mode, rechecks the stream
     *   generation, and holds the fence through the send.
     *
     * The VPP statistics socket is a fixed process wide endpoint, so only one
     * exporter may own it. A second instance fails closed instead of sharing
     * the endpoint ambiguously.
     */
    class VppHftExporter
    {
        public:

            /**
             * Minimal polling interval advertised for PORT streaming
             * statistics, in nanoseconds. This is the 10 millisecond interval
             * that the SONiC high frequency telemetry tests configure.
             */
            static const uint64_t MIN_POLLING_INTERVAL_NS = 10ULL * 1000ULL * 1000ULL;

            /**
             * Bounded wait for a VPP writer that holds the statistics segment
             * in progress. Keeps one sample from spinning into the next
             * deadline.
             */
            static const uint64_t STATS_ACCESS_TIMEOUT_NS = 2ULL * 1000ULL * 1000ULL;

            /** Period of the aggregated operational counter log. */
            static const int64_t STATISTICS_LOG_PERIOD_SECONDS = 60;

        public:

            struct Statistics
            {
                uint64_t samplesSent = 0;
                uint64_t samplesDropped = 0;
                uint64_t statsFailures = 0;
                uint64_t sendFailures = 0;
                uint64_t overruns = 0;
            };

        public:

            /** Construct with the live VPP statistics reader and netlink sender. */
            VppHftExporter();

            /** Construct with injected collaborators, used by unit tests. */
            VppHftExporter(
                    std::unique_ptr<VppHftStatsSource> statsSource,
                    std::unique_ptr<VppHftSink> sink);

            VppHftExporter(
                    const VppHftExporter&) = delete;

            VppHftExporter& operator=(
                    const VppHftExporter&) = delete;

            virtual ~VppHftExporter();

        public: // capability and counter mapping

            /** PORT statistics with an exact VPP source, in ascending order. */
            static const std::vector<sai_stat_id_t>& supportedPortStats();

            static bool isSupportedPortStat(
                    sai_stat_id_t statId);

            /**
             * @brief Implement the SAI two call streaming capability contract
             * for SAI_OBJECT_TYPE_PORT.
             */
            static sai_status_t queryPortStatsStCapability(
                    sai_stat_st_capability_list_t *capability);

            /**
             * @brief Copy an IPFIX template using the SAI two call u8-list
             * contract.
             */
            static sai_status_t copyTemplateToSaiList(
                    const std::vector<uint8_t>& templateMessage,
                    sai_u8_list_t& list);

            /**
             * @brief Map one supported SAI PORT statistic onto a sampled VPP
             * interface.
             *
             * Returns false when the statistic is unsupported or when VPP did
             * not report the underlying counter, so the caller drops the whole
             * record instead of substituting zero.
             */
            static bool mapPortStat(
                    sai_stat_id_t statId,
                    const vpp_interface_sample_t& sample,
                    uint64_t& value);

        public: // stream lifecycle, called on the SAI API thread

            /**
             * @brief True when this exporter owns the fixed VPP statistics
             * endpoint. A second exporter in the same process owns nothing and
             * refuses to stream.
             */
            bool ownsStatsEndpoint() const;

            /**
             * @brief Allocate a template id that does not collide with a
             * currently configured stream.
             */
            uint16_t allocateTemplateId();

            /**
             * @brief Atomically install a validated configuration as the
             * committed, stopped snapshot of its telemetry type.
             *
             * Any previously running stream of the same telemetry type is
             * quiesced before the replacement becomes visible.
             */
            sai_status_t commitStream(
                    std::shared_ptr<const VppHftStreamConfig> config);

            /** Start periodic sampling of a committed stream. */
            sai_status_t startStream(
                    sai_object_id_t telemetryTypeId);

            /**
             * @brief Replace only the polling interval of a committed stream.
             *
             * A running stream remains running and its next deadline is
             * scheduled from the update time.
             */
            sai_status_t updatePollingIntervals(
                    const std::vector<sai_object_id_t>& telemetryTypeIds,
                    std::chrono::microseconds interval);

            /**
             * @brief Stop a stream and return only after an in progress send
             * has completed.
             */
            void stopStream(
                    sai_object_id_t telemetryTypeId);

            /** Stop a stream and drop its committed snapshot. */
            void removeStream(
                    sai_object_id_t telemetryTypeId);

            /** Committed snapshot of a telemetry type, or nullptr. */
            std::shared_ptr<const VppHftStreamConfig> getStream(
                    sai_object_id_t telemetryTypeId) const;

            /** Stop every stream, join the worker and release the transports. */
            void shutdown();

            Statistics getStatistics() const;

        private:

            struct StreamState
            {
                std::shared_ptr<const VppHftStreamConfig> config;
                bool running = false;
                /** Bumped on every commit, start, stop and remove. */
                uint64_t generation = 0;
                std::chrono::steady_clock::time_point nextDeadline;
            };

            /** One unit of work collected under m_stateMutex by the worker. */
            struct DueSample
            {
                sai_object_id_t telemetryTypeId;
                uint64_t generation;
                std::shared_ptr<const VppHftStreamConfig> config;
            };

        private:

            void startWorker();

            void workerMain();

            /** Sample, encode and publish one stream. Runs without m_stateMutex. */
            void processSample(
                    const DueSample& due);

            /**
             * @brief Mark a stream inactive, then drain any send that already
             * entered the fence.
             */
            void quiesceStream(
                    sai_object_id_t telemetryTypeId,
                    bool erase);

            void logStatistics();

        private:

            std::unique_ptr<VppHftStatsSource> m_statsSource;

            std::unique_ptr<VppHftSink> m_sink;

            mutable std::mutex m_stateMutex;
            std::mutex m_lifecycleMutex;
            std::condition_variable m_cv;

            /**
             * Outbound send fence. Shared while the worker publishes, taken
             * exclusively by stop and replacement.
             */
            std::shared_timed_mutex m_sendFence;

            std::map<sai_object_id_t, StreamState> m_streams;

            /** Number of successfully emitted records per observation domain. */
            std::map<uint32_t, uint32_t> m_sequenceNumbers;

            uint64_t m_generationCounter;

            uint16_t m_nextTemplateId;

            bool m_shutdown;

            bool m_workerStarted;

            std::thread m_worker;

            Statistics m_statistics;

            std::chrono::steady_clock::time_point m_nextStatisticsLog;

            bool m_ownsStatsEndpoint;

            /** Guards the fixed process wide VPP statistics endpoint. */
            static std::atomic<bool> m_statsEndpointClaimed;
    };
}
