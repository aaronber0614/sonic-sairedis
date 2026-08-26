#pragma once

extern "C" {
#include "sai.h"
}

#include "vppxlate/SaiIntfStats.h"
#include "vppxlate/SaiVppStatsReader.h"

#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

namespace saivs
{
    /**
     * @brief One resolved TAM counter subscription.
     *
     * The VPP interface name is resolved once, on the SAI API thread, while a
     * stream configuration is built. The exporter worker never performs a VPP
     * binary API lookup.
     */
    struct VppHftCounterField
    {
        uint16_t label;
        sai_object_id_t portId;
        sai_stat_id_t statId;
        std::string vppInterfaceName;
        /** Index into VppHftStreamConfig::interfaces. */
        uint32_t interfaceIndex;
    };

    /**
     * @brief Immutable exporter configuration for one TAM telemetry type.
     *
     * A configuration becomes visible to the worker only after it is complete,
     * so the worker never observes a partially built stream.
     */
    struct VppHftStreamConfig
    {
        sai_object_id_t telemetryTypeId = SAI_NULL_OBJECT_ID;
        uint16_t templateId = 0;
        uint32_t observationDomainId = 0;
        std::chrono::microseconds pollingInterval { 0 };

        /** Sorted by ascending label. */
        std::vector<VppHftCounterField> fields;

        /** Deduplicated VPP interface names sampled for this stream. */
        std::vector<std::string> interfaces;

        /** Committed IPFIX template message for this configuration. */
        std::vector<uint8_t> templateMessage;
    };

    /**
     * @brief Source of VPP interface counters for the exporter worker.
     *
     * Implemented by VppHftVppStatsSource against the persistent VPP
     * statistics reader, and by test doubles in unit tests.
     */
    class VppHftStatsSource
    {
        public:

            enum class SampleResult
            {
                /** Every requested interface was sampled. */
                OK,
                /** Transient failure, drop this sample and try the next one. */
                RETRY,
                /** Connection level failure, the source backs off internally. */
                FAILED,
            };

        public:

            virtual ~VppHftStatsSource() = default;

            /**
             * @brief Sample all interfaces of one stream in a single dump.
             *
             * "samples" is resized to interfaces.size() by the implementation.
             */
            virtual SampleResult sample(
                    const std::vector<std::string>& interfaces,
                    std::vector<vpp_interface_sample_t>& samples) = 0;

            virtual void disconnect() = 0;
    };

    /**
     * @brief Outbound transport for encoded IPFIX messages.
     */
    class VppHftSink
    {
        public:

            enum class SendResult
            {
                /** Message was accepted by the transport. */
                OK,
                /** Message was dropped, for example no listener or no buffer. */
                DROPPED,
                /** Transport failure, the sink reconnects on a later send. */
                FAILED,
            };

        public:

            virtual ~VppHftSink() = default;

            virtual SendResult send(
                    const uint8_t *data,
                    size_t size) = 0;

            virtual void close() = 0;
    };
}
