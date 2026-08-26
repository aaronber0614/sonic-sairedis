#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace saivs
{
    /**
     * @brief Byte level IPFIX (RFC 7011) template and data message builder for
     * SAI TAM counter subscription streams.
     *
     * The encoding matches the layout consumed by the SONiC countersyncd IPFIX
     * parser: a template set with set ID 2, one leading
     * observationTimeNanoseconds field, and one enterprise specific field per
     * counter subscription whose information element identifier is
     * (0x8000 | label) and whose enterprise number packs the SAI object type in
     * the upper 16 bits and the SAI stat ID in the lower 16 bits.
     *
     * The builder works on plain integer types so it carries no VPP or SAI
     * runtime dependency and can be verified against golden bytes.
     */
    class TamIpfixBuilder
    {
        public:

            /** IPFIX version emitted by this builder. */
            static const uint16_t IPFIX_VERSION = 10;

            /** Set ID reserved by RFC 7011 for template sets. */
            static const uint16_t TEMPLATE_SET_ID = 2;

            /** Lowest template ID usable by a data set. */
            static const uint16_t MIN_TEMPLATE_ID = 256;

            /** IANA information element ID of observationTimeNanoseconds. */
            static const uint16_t OBSERVATION_TIME_ELEMENT_ID = 325;

            /** Every field emitted by this builder is an unsigned 64 bit value. */
            static const uint16_t FIELD_LENGTH = 8;

            /** Size of the IPFIX message header. */
            static const size_t MESSAGE_HEADER_SIZE = 16;

            /** Size of a set header. */
            static const size_t SET_HEADER_SIZE = 4;

            /**
             * Highest usable counter subscription label. The top bit of the
             * information element identifier signals that an enterprise number
             * follows, so only 15 bits are available for the label.
             */
            static const uint16_t MAX_LABEL = 0x7fff;

            /** Largest IPFIX message or set, both carry a 16 bit length. */
            static const size_t MAX_MESSAGE_SIZE = 0xffff;

        public:

            /**
             * @brief One counter subscription as it appears in the template.
             */
            struct Field
            {
                uint16_t label;
                uint32_t objectType;
                uint32_t statId;
            };

        public:

            /**
             * @brief Validate the field list of one stream.
             *
             * Orchagent assigns one label per monitored object and reuses it
             * for every statistic of that object, so labels repeat while the
             * (label, enterprise number) pair identifies a field.
             *
             * Rejects an empty list, a zero label, a label above MAX_LABEL, a
             * duplicate (label, enterprise number) pair, fields that are not
             * ordered by label then stat ID, and an object type or stat ID that
             * does not fit the enterprise number encoding.
             */
            static bool validateFields(
                    const std::vector<Field>& fields,
                    std::string& error);

            /**
             * @brief Build one IPFIX template message.
             */
            static bool buildTemplateMessage(
                    uint16_t templateId,
                    uint32_t observationDomainId,
                    uint32_t exportTimeSeconds,
                    const std::vector<Field>& fields,
                    std::vector<uint8_t>& message,
                    std::string& error);

            /**
             * @brief Build one IPFIX data message holding a single data record.
             *
             * sequenceNumber is the number of data records already emitted in
             * this observation domain. observationTimeNs is the sample time in
             * nanoseconds since the UNIX epoch.
             */
            static bool buildDataMessage(
                    uint16_t templateId,
                    uint32_t observationDomainId,
                    uint32_t exportTimeSeconds,
                    uint32_t sequenceNumber,
                    uint64_t observationTimeNs,
                    const std::vector<uint64_t>& values,
                    std::vector<uint8_t>& message,
                    std::string& error);

            /**
             * @brief Pack a SAI object type and stat ID into an IPFIX
             * enterprise number. Returns false when either identifier does not
             * fit in 16 bits.
             */
            static bool packEnterpriseNumber(
                    uint32_t objectType,
                    uint32_t statId,
                    uint32_t& enterpriseNumber);

        public: // network byte order encoding primitives

            static void appendU16(
                    std::vector<uint8_t>& buffer,
                    uint16_t value);

            static void appendU32(
                    std::vector<uint8_t>& buffer,
                    uint32_t value);

            static void appendU64(
                    std::vector<uint8_t>& buffer,
                    uint64_t value);
    };
}
