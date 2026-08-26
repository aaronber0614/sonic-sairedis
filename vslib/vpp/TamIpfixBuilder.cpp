#include "TamIpfixBuilder.h"

#include "swss/logger.h"

#include <set>
#include <utility>

using namespace saivs;

// C++14 requires out of line definitions for odr-used static const members.
const uint16_t TamIpfixBuilder::IPFIX_VERSION;
const uint16_t TamIpfixBuilder::TEMPLATE_SET_ID;
const uint16_t TamIpfixBuilder::MIN_TEMPLATE_ID;
const uint16_t TamIpfixBuilder::OBSERVATION_TIME_ELEMENT_ID;
const uint16_t TamIpfixBuilder::FIELD_LENGTH;
const uint16_t TamIpfixBuilder::MAX_LABEL;
const size_t TamIpfixBuilder::MESSAGE_HEADER_SIZE;
const size_t TamIpfixBuilder::SET_HEADER_SIZE;
const size_t TamIpfixBuilder::MAX_MESSAGE_SIZE;

void TamIpfixBuilder::appendU16(
        std::vector<uint8_t>& buffer,
        uint16_t value)
{
    buffer.push_back(static_cast<uint8_t>((value >> 8) & 0xff));
    buffer.push_back(static_cast<uint8_t>(value & 0xff));
}

void TamIpfixBuilder::appendU32(
        std::vector<uint8_t>& buffer,
        uint32_t value)
{
    buffer.push_back(static_cast<uint8_t>((value >> 24) & 0xff));
    buffer.push_back(static_cast<uint8_t>((value >> 16) & 0xff));
    buffer.push_back(static_cast<uint8_t>((value >> 8) & 0xff));
    buffer.push_back(static_cast<uint8_t>(value & 0xff));
}

void TamIpfixBuilder::appendU64(
        std::vector<uint8_t>& buffer,
        uint64_t value)
{
    for (int shift = 56; shift >= 0; shift -= 8)
    {
        buffer.push_back(static_cast<uint8_t>((value >> shift) & 0xff));
    }
}

bool TamIpfixBuilder::packEnterpriseNumber(
        uint32_t objectType,
        uint32_t statId,
        uint32_t& enterpriseNumber)
{
    SWSS_LOG_ENTER();

    if (objectType > 0xffff || statId > 0xffff)
    {
        return false;
    }

    enterpriseNumber = (objectType << 16) | statId;

    return true;
}

bool TamIpfixBuilder::validateFields(
        const std::vector<Field>& fields,
        std::string& error)
{
    SWSS_LOG_ENTER();

    if (fields.empty())
    {
        error = "no counter subscription fields";
        return false;
    }

    // Orchagent assigns one label per monitored object and reuses it for every
    // statistic of that object, so a label may repeat. What must be unique,
    // and deterministically ordered, is the (label, enterprise number) pair
    // that identifies one field of the template.
    std::set<std::pair<uint16_t, uint32_t>> seen;

    bool first = true;

    std::pair<uint16_t, uint32_t> previous(0, 0);

    for (auto& field: fields)
    {
        if (field.label == 0 || field.label > MAX_LABEL)
        {
            error = "counter subscription label " + std::to_string(field.label) +
                    " is outside the usable range 1.." + std::to_string(MAX_LABEL);
            return false;
        }

        uint32_t enterpriseNumber = 0;

        if (!packEnterpriseNumber(field.objectType, field.statId, enterpriseNumber))
        {
            error = "object type " + std::to_string(field.objectType) + " or stat id " +
                    std::to_string(field.statId) + " does not fit the IPFIX enterprise number";
            return false;
        }

        std::pair<uint16_t, uint32_t> key(field.label, enterpriseNumber);

        if (!seen.insert(key).second)
        {
            error = "duplicate counter subscription label " + std::to_string(field.label) +
                    " for stat id " + std::to_string(field.statId);
            return false;
        }

        if (!first && key < previous)
        {
            error = "counter subscription fields are not ordered by label and stat id";
            return false;
        }

        previous = key;
        first = false;
    }

    return true;
}

bool TamIpfixBuilder::buildTemplateMessage(
        uint16_t templateId,
        uint32_t observationDomainId,
        uint32_t exportTimeSeconds,
        const std::vector<Field>& fields,
        std::vector<uint8_t>& message,
        std::string& error)
{
    SWSS_LOG_ENTER();

    message.clear();

    if (templateId < MIN_TEMPLATE_ID)
    {
        error = "template id " + std::to_string(templateId) + " is below " +
                std::to_string(MIN_TEMPLATE_ID);
        return false;
    }

    if (!validateFields(fields, error))
    {
        return false;
    }

    // set header + template record header + observation time field + counter fields
    const size_t setLength = SET_HEADER_SIZE + 4 + 4 + fields.size() * 8;
    const size_t messageLength = MESSAGE_HEADER_SIZE + setLength;

    if (setLength > MAX_MESSAGE_SIZE || messageLength > MAX_MESSAGE_SIZE)
    {
        error = "template message of " + std::to_string(messageLength) +
                " bytes exceeds the IPFIX 16 bit length limit";
        return false;
    }

    // one observation time field plus one field per counter subscription
    const size_t fieldCount = fields.size() + 1;

    if (fieldCount > 0xffff)
    {
        error = "template field count " + std::to_string(fieldCount) +
                " exceeds the IPFIX 16 bit field count limit";
        return false;
    }

    message.reserve(messageLength);

    appendU16(message, IPFIX_VERSION);
    appendU16(message, static_cast<uint16_t>(messageLength));
    appendU32(message, exportTimeSeconds);
    appendU32(message, 0); // sequence number is always zero in a template message
    appendU32(message, observationDomainId);

    appendU16(message, TEMPLATE_SET_ID);
    appendU16(message, static_cast<uint16_t>(setLength));

    appendU16(message, templateId);
    appendU16(message, static_cast<uint16_t>(fieldCount));

    appendU16(message, OBSERVATION_TIME_ELEMENT_ID);
    appendU16(message, FIELD_LENGTH);

    for (auto& field: fields)
    {
        uint32_t enterpriseNumber = 0;

        // already validated above
        packEnterpriseNumber(field.objectType, field.statId, enterpriseNumber);

        appendU16(message, static_cast<uint16_t>(0x8000 | field.label));
        appendU16(message, FIELD_LENGTH);
        appendU32(message, enterpriseNumber);
    }

    if (message.size() != messageLength)
    {
        error = "internal error, encoded template message size mismatch";
        message.clear();
        return false;
    }

    return true;
}

bool TamIpfixBuilder::buildDataMessage(
        uint16_t templateId,
        uint32_t observationDomainId,
        uint32_t exportTimeSeconds,
        uint32_t sequenceNumber,
        uint64_t observationTimeNs,
        const std::vector<uint64_t>& values,
        std::vector<uint8_t>& message,
        std::string& error)
{
    SWSS_LOG_ENTER();

    message.clear();

    if (templateId < MIN_TEMPLATE_ID)
    {
        error = "template id " + std::to_string(templateId) + " is below " +
                std::to_string(MIN_TEMPLATE_ID);
        return false;
    }

    if (values.empty())
    {
        error = "no counter values to encode";
        return false;
    }

    // set header + observation time + counter values
    const size_t setLength = SET_HEADER_SIZE + 8 + values.size() * 8;
    const size_t messageLength = MESSAGE_HEADER_SIZE + setLength;

    if (setLength > MAX_MESSAGE_SIZE || messageLength > MAX_MESSAGE_SIZE)
    {
        error = "data message of " + std::to_string(messageLength) +
                " bytes exceeds the IPFIX 16 bit length limit";
        return false;
    }

    message.reserve(messageLength);

    appendU16(message, IPFIX_VERSION);
    appendU16(message, static_cast<uint16_t>(messageLength));
    appendU32(message, exportTimeSeconds);
    appendU32(message, sequenceNumber);
    appendU32(message, observationDomainId);

    appendU16(message, templateId);
    appendU16(message, static_cast<uint16_t>(setLength));

    appendU64(message, observationTimeNs);

    for (auto value: values)
    {
        appendU64(message, value);
    }

    if (message.size() != messageLength)
    {
        error = "internal error, encoded data message size mismatch";
        message.clear();
        return false;
    }

    return true;
}
