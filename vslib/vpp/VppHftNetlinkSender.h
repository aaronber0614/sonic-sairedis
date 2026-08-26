#pragma once

#include "VppHftTypes.h"

#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

namespace saivs
{
    /**
     * @brief Generic Netlink publisher for IPFIX messages.
     *
     * Sends complete IPFIX messages to the SONiC high frequency telemetry
     * Generic Netlink family, where the platform provider multicasts them to
     * countersyncd. The wire contract is:
     *
     *   netlink header
     *   Generic Netlink header, command PUBLISH
     *   netlink attribute header, type IPFIX
     *   complete IPFIX message
     *
     * The publish command is privileged, syncd supplies CAP_NET_ADMIN.
     *
     * One sender is owned by the exporter worker thread and is not safe for
     * concurrent use.
     */
    class VppHftNetlinkSender:
        public VppHftSink
    {
        public:

            /** Generic Netlink family registered by the platform provider. */
            static const char* const FAMILY_NAME;

            /** Family interface version. */
            static const uint8_t FAMILY_VERSION = 1;

            /** Publish one IPFIX message. */
            static const uint8_t CMD_PUBLISH = 1;

            /** Attribute carrying one complete IPFIX message. */
            static const uint16_t ATTR_IPFIX = 1;

            /**
             * Largest payload whose Netlink attribute header and data fit in
             * the 16 bit nla_len field.
             */
            static const size_t MAX_PAYLOAD_SIZE = 0xffffu - 4u;

            /** Bounded wait for the publish acknowledgement, in milliseconds. */
            static const int ACK_TIMEOUT_MS = 20;

            /** Delay before resolving a failed transport again. */
            static const int RECONNECT_BACKOFF_SECONDS = 1;

        public:

            VppHftNetlinkSender();

            VppHftNetlinkSender(
                    const VppHftNetlinkSender&) = delete;

            VppHftNetlinkSender& operator=(
                    const VppHftNetlinkSender&) = delete;

            virtual ~VppHftNetlinkSender();

        public:

            virtual SendResult send(
                    const uint8_t *data,
                    size_t size) override;

            virtual void close() override;

        public:

            /**
             * @brief Check whether the telemetry Generic Netlink family is
             * registered in the current network namespace.
             *
             * Used to fail closed on capability query when the platform
             * provider is not loaded.
             */
            static bool isFamilyAvailable();

        private:

            /** Open the socket and resolve the family id. */
            bool connect();

            bool openSocket();

            bool resolveFamilyId(
                    int fd,
                    uint32_t& sequence,
                    uint16_t& familyId);

            /**
             * @brief Wait for and interpret the publish acknowledgement.
             */
            SendResult waitForAck(
                    uint32_t sequence);

        private:

            int m_socket;

            uint16_t m_familyId;

            uint32_t m_sequence;

            /** Rate limits repeated transport failure logs. */
            uint64_t m_suppressedFailureLogs;

            std::chrono::steady_clock::time_point m_nextConnectAttempt;
    };
}
