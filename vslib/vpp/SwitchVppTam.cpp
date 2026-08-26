/*
 * VPP specific SAI TAM handling for high frequency telemetry.
 *
 * SwitchVpp overrides the generic create, set and remove entry points, so the
 * TAM object types are dispatched explicitly here. The shared SwitchStateBase
 * special cases (default object lists on TAM and TAM telemetry, and the
 * telemetry type configuration change notification) are preserved.
 */

#include "SwitchVpp.h"
#include "VppHftNetlinkSender.h"

#include "meta/sai_serialize.h"

#include "swss/logger.h"

#include <algorithm>
#include <ctime>
#include <map>

using namespace saivs;

sai_status_t SwitchVpp::createTamCounterSubscription(
        _In_ sai_object_id_t object_id,
        _In_ sai_object_id_t switch_id,
        _In_ uint32_t attr_count,
        _In_ const sai_attribute_t *attr_list)
{
    SWSS_LOG_ENTER();

    auto sid = sai_serialize_object_id(object_id);

    CHECK_STATUS(create_internal(
                SAI_OBJECT_TYPE_TAM_COUNTER_SUBSCRIPTION,
                sid,
                switch_id,
                attr_count,
                attr_list));

    auto telType = sai_metadata_get_attr_by_id(
            SAI_TAM_COUNTER_SUBSCRIPTION_ATTR_TEL_TYPE,
            attr_count,
            attr_list);

    if (telType != nullptr)
    {
        markHftConfigDirty(telType->value.oid);
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t SwitchVpp::removeTamCounterSubscription(
        _In_ sai_object_id_t object_id)
{
    SWSS_LOG_ENTER();

    sai_object_id_t telTypeId = SAI_NULL_OBJECT_ID;

    sai_attribute_t attr;

    attr.id = SAI_TAM_COUNTER_SUBSCRIPTION_ATTR_TEL_TYPE;

    if (get(SAI_OBJECT_TYPE_TAM_COUNTER_SUBSCRIPTION, object_id, 1, &attr) == SAI_STATUS_SUCCESS)
    {
        telTypeId = attr.value.oid;
    }

    CHECK_STATUS(remove_internal(
                SAI_OBJECT_TYPE_TAM_COUNTER_SUBSCRIPTION,
                sai_serialize_object_id(object_id)));

    if (telTypeId != SAI_NULL_OBJECT_ID)
    {
        markHftConfigDirty(telTypeId);
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t SwitchVpp::removeTamTelType(
        _In_ sai_object_id_t object_id)
{
    SWSS_LOG_ENTER();

    sai_status_t status = remove_internal(
            SAI_OBJECT_TYPE_TAM_TEL_TYPE,
            sai_serialize_object_id(object_id));

    if (status != SAI_STATUS_SUCCESS)
    {
        return status;
    }

    // Quiesce after the SAI object is removed. The send fence still guarantees
    // that no record of this telemetry type can be emitted after remove
    // returns, while a failed state removal leaves the existing stream intact.
    if (m_hftExporter)
    {
        m_hftExporter->removeStream(object_id);
    }

    m_hftDirtyTelTypes.erase(object_id);

    return SAI_STATUS_SUCCESS;
}

void SwitchVpp::markHftConfigDirty(
        _In_ sai_object_id_t tam_tel_type_id)
{
    SWSS_LOG_ENTER();

    if (tam_tel_type_id == SAI_NULL_OBJECT_ID)
    {
        return;
    }

    m_hftDirtyTelTypes.insert(tam_tel_type_id);

    SWSS_LOG_INFO("counter subscriptions of %s changed, a new CREATE_CONFIG is required",
            sai_serialize_object_id(tam_tel_type_id).c_str());
}

sai_status_t SwitchVpp::setTamTelTypeVpp(
        _In_ sai_object_id_t tam_tel_type_id,
        _In_ const sai_attribute_t *attr)
{
    SWSS_LOG_ENTER();

    if (attr == nullptr)
    {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    auto sid = sai_serialize_object_id(tam_tel_type_id);

    if (attr->id != SAI_TAM_TEL_TYPE_ATTR_STATE)
    {
        return set_internal(SAI_OBJECT_TYPE_TAM_TEL_TYPE, sid, attr);
    }

    if (!m_hftExporter)
    {
        SWSS_LOG_ERROR("high frequency telemetry exporter is not available");

        return SAI_STATUS_NOT_SUPPORTED;
    }

    sai_attribute_t previousState;

    previousState.id = SAI_TAM_TEL_TYPE_ATTR_STATE;
    previousState.value.s32 = SAI_TAM_TEL_TYPE_STATE_STOP_STREAM;

    sai_status_t previousStateStatus = get(
            SAI_OBJECT_TYPE_TAM_TEL_TYPE,
            tam_tel_type_id,
            1,
            &previousState);

    // STATE has a SAI default of STOP_STREAM. SwitchVpp stores only explicit
    // attributes, so the first transition can legitimately find no stored
    // value.
    if (previousStateStatus != SAI_STATUS_SUCCESS &&
        previousStateStatus != SAI_STATUS_ITEM_NOT_FOUND)
    {
        return previousStateStatus;
    }

    switch (attr->value.s32)
    {
        case SAI_TAM_TEL_TYPE_STATE_STOP_STREAM:
        {
            sai_status_t status = set_internal(SAI_OBJECT_TYPE_TAM_TEL_TYPE, sid, attr);

            if (status != SAI_STATUS_SUCCESS)
            {
                return status;
            }

            // The send fence guarantees that no record from the old
            // generation can be emitted after this call returns.
            m_hftExporter->stopStream(tam_tel_type_id);

            return SAI_STATUS_SUCCESS;
        }

        case SAI_TAM_TEL_TYPE_STATE_CREATE_CONFIG:
        {
            std::shared_ptr<VppHftStreamConfig> config;

            // On failure the previous SAI state, the previously committed
            // snapshot and the previously committed template are all left
            // untouched, and no configuration change notification is sent.
            CHECK_STATUS(buildHftStreamConfig(tam_tel_type_id, config));

            sai_status_t status = set_internal(SAI_OBJECT_TYPE_TAM_TEL_TYPE, sid, attr);

            if (status != SAI_STATUS_SUCCESS)
            {
                return status;
            }

            status = m_hftExporter->commitStream(config);

            if (status != SAI_STATUS_SUCCESS)
            {
                sai_status_t rollbackStatus = set_internal(
                        SAI_OBJECT_TYPE_TAM_TEL_TYPE,
                        sid,
                        &previousState);

                if (rollbackStatus != SAI_STATUS_SUCCESS)
                {
                    SWSS_LOG_ERROR("failed to restore the state of %s after stream commit "
                            "failed: %s",
                            sid.c_str(),
                            sai_serialize_status(rollbackStatus).c_str());
                }

                return status;
            }

            m_hftDirtyTelTypes.erase(tam_tel_type_id);

            send_tam_tel_type_config_change(tam_tel_type_id);

            return SAI_STATUS_SUCCESS;
        }

        case SAI_TAM_TEL_TYPE_STATE_START_STREAM:
        {
            if (m_hftExporter->getStream(tam_tel_type_id) == nullptr)
            {
                SWSS_LOG_ERROR("cannot start %s, no configuration was committed", sid.c_str());

                return SAI_STATUS_INVALID_PARAMETER;
            }

            if (m_hftDirtyTelTypes.count(tam_tel_type_id) != 0)
            {
                SWSS_LOG_WARN("starting %s with a stream committed before the last counter "
                        "subscription change", sid.c_str());
            }

            sai_status_t status = set_internal(SAI_OBJECT_TYPE_TAM_TEL_TYPE, sid, attr);

            if (status != SAI_STATUS_SUCCESS)
            {
                return status;
            }

            status = m_hftExporter->startStream(tam_tel_type_id);

            if (status != SAI_STATUS_SUCCESS)
            {
                sai_status_t rollbackStatus = set_internal(
                        SAI_OBJECT_TYPE_TAM_TEL_TYPE,
                        sid,
                        &previousState);

                if (rollbackStatus != SAI_STATUS_SUCCESS)
                {
                    SWSS_LOG_ERROR("failed to restore the state of %s after stream start "
                            "failed: %s",
                            sid.c_str(),
                            sai_serialize_status(rollbackStatus).c_str());
                }
            }

            return status;
        }

        default:

            SWSS_LOG_ERROR("unsupported TAM telemetry type state %d on %s",
                    attr->value.s32,
                    sid.c_str());

            return SAI_STATUS_INVALID_PARAMETER;
    }
}

sai_status_t SwitchVpp::setTamReportVpp(
        _In_ sai_object_id_t tam_report_id,
        _In_ const sai_attribute_t *attr)
{
    SWSS_LOG_ENTER();

    if (attr == nullptr)
    {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    auto sid = sai_serialize_object_id(tam_report_id);

    if (attr->id != SAI_TAM_REPORT_ATTR_REPORT_INTERVAL)
    {
        return set_internal(SAI_OBJECT_TYPE_TAM_REPORT, sid, attr);
    }

    uint64_t requestedNs = VppHftExporter::MIN_POLLING_INTERVAL_NS;

    if (attr->value.u32 != 0)
    {
        requestedNs = static_cast<uint64_t>(attr->value.u32) * 1000ULL;
    }

    if (requestedNs < VppHftExporter::MIN_POLLING_INTERVAL_NS)
    {
        SWSS_LOG_ERROR("requested polling interval of %u us is below the advertised VPP "
                "minimum of %llu us",
                attr->value.u32,
                static_cast<unsigned long long>(
                    VppHftExporter::MIN_POLLING_INTERVAL_NS / 1000ULL));

        return SAI_STATUS_INVALID_PARAMETER;
    }

    sai_attribute_t unit;

    unit.id = SAI_TAM_REPORT_ATTR_REPORT_INTERVAL_UNIT;

    sai_status_t unitStatus = get(
            SAI_OBJECT_TYPE_TAM_REPORT,
            tam_report_id,
            1,
            &unit);

    if (unitStatus == SAI_STATUS_SUCCESS &&
        unit.value.s32 != SAI_TAM_REPORT_INTERVAL_UNIT_USEC)
    {
        return SAI_STATUS_NOT_SUPPORTED;
    }

    if (unitStatus != SAI_STATUS_SUCCESS)
    {
        return unitStatus;
    }

    sai_attribute_t previous;

    previous.id = SAI_TAM_REPORT_ATTR_REPORT_INTERVAL;

    sai_status_t previousStatus = get(
            SAI_OBJECT_TYPE_TAM_REPORT,
            tam_report_id,
            1,
            &previous);

    uint64_t previousNs = VppHftExporter::MIN_POLLING_INTERVAL_NS;

    if (previousStatus == SAI_STATUS_SUCCESS && previous.value.u32 != 0)
    {
        previousNs = static_cast<uint64_t>(previous.value.u32) * 1000ULL;
    }

    sai_attribute_t expect;

    expect.id = SAI_TAM_TEL_TYPE_ATTR_REPORT_ID;
    expect.value.oid = tam_report_id;

    std::vector<sai_object_id_t> telemetryTypes;

    findObjects(SAI_OBJECT_TYPE_TAM_TEL_TYPE, expect, telemetryTypes);

    auto interval = std::chrono::microseconds(
            static_cast<int64_t>(requestedNs / 1000ULL));

    std::vector<sai_object_id_t> committedTypes;

    for (auto telemetryType: telemetryTypes)
    {
        if (m_hftExporter && m_hftExporter->getStream(telemetryType) != nullptr)
        {
            committedTypes.push_back(telemetryType);
        }
    }

    if (!committedTypes.empty())
    {
        CHECK_STATUS(m_hftExporter->updatePollingIntervals(committedTypes, interval));
    }

    sai_status_t status = set_internal(SAI_OBJECT_TYPE_TAM_REPORT, sid, attr);

    if (status != SAI_STATUS_SUCCESS && !committedTypes.empty())
    {
        sai_status_t rollbackStatus = m_hftExporter->updatePollingIntervals(
                committedTypes,
                std::chrono::microseconds(
                    static_cast<int64_t>(previousNs / 1000ULL)));

        if (rollbackStatus != SAI_STATUS_SUCCESS)
        {
            SWSS_LOG_ERROR("failed to roll back HFT polling intervals after TAM report update "
                    "failed: %s",
                    sai_serialize_status(rollbackStatus).c_str());
        }
    }

    return status;
}

sai_status_t SwitchVpp::getTamTelTypePollingInterval(
        _In_ sai_object_id_t tam_tel_type_id,
        _Out_ std::chrono::microseconds& interval)
{
    SWSS_LOG_ENTER();

    interval = std::chrono::microseconds(
            static_cast<int64_t>(VppHftExporter::MIN_POLLING_INTERVAL_NS / 1000ULL));

    sai_attribute_t attr;

    attr.id = SAI_TAM_TEL_TYPE_ATTR_REPORT_ID;

    if (get(SAI_OBJECT_TYPE_TAM_TEL_TYPE, tam_tel_type_id, 1, &attr) != SAI_STATUS_SUCCESS ||
        attr.value.oid == SAI_NULL_OBJECT_ID)
    {
        SWSS_LOG_ERROR("TAM telemetry type %s has no report object",
                sai_serialize_object_id(tam_tel_type_id).c_str());

        return SAI_STATUS_INVALID_PARAMETER;
    }

    sai_object_id_t reportId = attr.value.oid;

    attr.id = SAI_TAM_REPORT_ATTR_TYPE;

    if (get(SAI_OBJECT_TYPE_TAM_REPORT, reportId, 1, &attr) != SAI_STATUS_SUCCESS ||
        attr.value.s32 != SAI_TAM_REPORT_TYPE_IPFIX)
    {
        SWSS_LOG_ERROR("TAM report %s is not an IPFIX report",
                sai_serialize_object_id(reportId).c_str());

        return SAI_STATUS_NOT_SUPPORTED;
    }

    attr.id = SAI_TAM_REPORT_ATTR_REPORT_INTERVAL_UNIT;

    if (get(SAI_OBJECT_TYPE_TAM_REPORT, reportId, 1, &attr) == SAI_STATUS_SUCCESS &&
        attr.value.s32 != SAI_TAM_REPORT_INTERVAL_UNIT_USEC)
    {
        SWSS_LOG_ERROR("TAM report %s does not use microsecond report intervals",
                sai_serialize_object_id(reportId).c_str());

        return SAI_STATUS_NOT_SUPPORTED;
    }

    attr.id = SAI_TAM_REPORT_ATTR_REPORT_INTERVAL;

    if (get(SAI_OBJECT_TYPE_TAM_REPORT, reportId, 1, &attr) != SAI_STATUS_SUCCESS ||
        attr.value.u32 == 0)
    {
        SWSS_LOG_NOTICE("TAM report %s has no report interval, using the advertised minimum",
                sai_serialize_object_id(reportId).c_str());

        return SAI_STATUS_SUCCESS;
    }

    const uint64_t requestedNs = static_cast<uint64_t>(attr.value.u32) * 1000ULL;

    if (requestedNs < VppHftExporter::MIN_POLLING_INTERVAL_NS)
    {
        SWSS_LOG_ERROR("requested polling interval of %u us is below the advertised VPP "
                "minimum of %llu us",
                attr.value.u32,
                static_cast<unsigned long long>(VppHftExporter::MIN_POLLING_INTERVAL_NS / 1000ULL));

        return SAI_STATUS_INVALID_PARAMETER;
    }

    interval = std::chrono::microseconds(static_cast<int64_t>(attr.value.u32));

    return SAI_STATUS_SUCCESS;
}

sai_status_t SwitchVpp::buildHftStreamConfig(
        _In_ sai_object_id_t tam_tel_type_id,
        _Out_ std::shared_ptr<VppHftStreamConfig>& config)
{
    SWSS_LOG_ENTER();

    config = nullptr;

    auto sid = sai_serialize_object_id(tam_tel_type_id);

    sai_attribute_t attr;

    attr.id = SAI_TAM_TEL_TYPE_ATTR_TAM_TELEMETRY_TYPE;

    CHECK_STATUS(get(SAI_OBJECT_TYPE_TAM_TEL_TYPE, tam_tel_type_id, 1, &attr));

    if (attr.value.s32 != SAI_TAM_TELEMETRY_TYPE_COUNTER_SUBSCRIPTION)
    {
        SWSS_LOG_ERROR("TAM telemetry type %s is not a counter subscription stream", sid.c_str());

        return SAI_STATUS_NOT_SUPPORTED;
    }

    auto candidate = std::make_shared<VppHftStreamConfig>();

    candidate->telemetryTypeId = tam_tel_type_id;
    candidate->observationDomainId = static_cast<uint32_t>(m_switch_id & 0xffffffffULL);

    CHECK_STATUS(getTamTelTypePollingInterval(tam_tel_type_id, candidate->pollingInterval));

    sai_attribute_t expect;

    expect.id = SAI_TAM_COUNTER_SUBSCRIPTION_ATTR_TEL_TYPE;
    expect.value.oid = tam_tel_type_id;

    std::vector<sai_object_id_t> subscriptions;

    findObjects(SAI_OBJECT_TYPE_TAM_COUNTER_SUBSCRIPTION, expect, subscriptions);

    if (subscriptions.empty())
    {
        SWSS_LOG_ERROR("TAM telemetry type %s has no counter subscription", sid.c_str());

        return SAI_STATUS_INVALID_PARAMETER;
    }

    std::map<std::string, uint32_t> interfaceIndexes;

    for (auto subscription: subscriptions)
    {
        auto subscriptionId = sai_serialize_object_id(subscription);

        attr.id = SAI_TAM_COUNTER_SUBSCRIPTION_ATTR_OBJECT_ID;

        CHECK_STATUS(get(SAI_OBJECT_TYPE_TAM_COUNTER_SUBSCRIPTION, subscription, 1, &attr));

        sai_object_id_t monitoredObject = attr.value.oid;

        if (objectTypeQuery(monitoredObject) != SAI_OBJECT_TYPE_PORT)
        {
            SWSS_LOG_ERROR("counter subscription %s monitors %s, only PORT streaming is supported",
                    subscriptionId.c_str(),
                    sai_serialize_object_id(monitoredObject).c_str());

            return SAI_STATUS_NOT_SUPPORTED;
        }

        attr.id = SAI_TAM_COUNTER_SUBSCRIPTION_ATTR_STAT_ID;

        CHECK_STATUS(get(SAI_OBJECT_TYPE_TAM_COUNTER_SUBSCRIPTION, subscription, 1, &attr));

        sai_stat_id_t statId = attr.value.u32;

        if (!VppHftExporter::isSupportedPortStat(statId))
        {
            SWSS_LOG_ERROR("counter subscription %s requests unsupported PORT statistic %u",
                    subscriptionId.c_str(),
                    statId);

            return SAI_STATUS_NOT_SUPPORTED;
        }

        attr.id = SAI_TAM_COUNTER_SUBSCRIPTION_ATTR_STATS_MODE;

        if (get(SAI_OBJECT_TYPE_TAM_COUNTER_SUBSCRIPTION, subscription, 1, &attr) == SAI_STATUS_SUCCESS &&
            attr.value.s32 != SAI_STATS_MODE_READ)
        {
            SWSS_LOG_ERROR("counter subscription %s requests a statistics mode other than "
                    "SAI_STATS_MODE_READ", subscriptionId.c_str());

            return SAI_STATUS_NOT_SUPPORTED;
        }

        attr.id = SAI_TAM_COUNTER_SUBSCRIPTION_ATTR_LABEL;

        CHECK_STATUS(get(SAI_OBJECT_TYPE_TAM_COUNTER_SUBSCRIPTION, subscription, 1, &attr));

        if (attr.value.u64 == 0 || attr.value.u64 > TamIpfixBuilder::MAX_LABEL)
        {
            SWSS_LOG_ERROR("counter subscription %s uses label %llu which is outside 1..%u",
                    subscriptionId.c_str(),
                    static_cast<unsigned long long>(attr.value.u64),
                    static_cast<unsigned int>(TamIpfixBuilder::MAX_LABEL));

            return SAI_STATUS_INVALID_PARAMETER;
        }

        VppHftCounterField field;

        field.label = static_cast<uint16_t>(attr.value.u64);
        field.portId = monitoredObject;
        field.statId = statId;
        field.interfaceIndex = 0;

        if (!port_to_hwifname(monitoredObject, field.vppInterfaceName))
        {
            SWSS_LOG_ERROR("counter subscription %s monitors port %s which has no VPP interface",
                    subscriptionId.c_str(),
                    sai_serialize_object_id(monitoredObject).c_str());

            return SAI_STATUS_INVALID_PARAMETER;
        }

        auto existing = interfaceIndexes.find(field.vppInterfaceName);

        if (existing == interfaceIndexes.end())
        {
            field.interfaceIndex = static_cast<uint32_t>(candidate->interfaces.size());
            interfaceIndexes[field.vppInterfaceName] = field.interfaceIndex;
            candidate->interfaces.push_back(field.vppInterfaceName);
        }
        else
        {
            field.interfaceIndex = existing->second;
        }

        candidate->fields.push_back(field);
    }

    // Deterministic template and record ordering: label first, then stat id,
    // because orchagent reuses one label for every statistic of an object.
    std::sort(
            candidate->fields.begin(),
            candidate->fields.end(),
            [](const VppHftCounterField& a, const VppHftCounterField& b)
            {
                if (a.label != b.label)
                {
                    return a.label < b.label;
                }

                return a.statId < b.statId;
            });

    std::vector<TamIpfixBuilder::Field> templateFields;

    templateFields.reserve(candidate->fields.size());

    for (auto& field: candidate->fields)
    {
        TamIpfixBuilder::Field templateField;

        templateField.label = field.label;
        templateField.objectType = static_cast<uint32_t>(SAI_OBJECT_TYPE_PORT);
        templateField.statId = static_cast<uint32_t>(field.statId);

        templateFields.push_back(templateField);
    }

    std::string error;

    candidate->templateId = m_hftExporter->allocateTemplateId();

    if (!TamIpfixBuilder::buildTemplateMessage(
                candidate->templateId,
                candidate->observationDomainId,
                static_cast<uint32_t>(time(nullptr)),
                templateFields,
                candidate->templateMessage,
                error))
    {
        SWSS_LOG_ERROR("failed to build the IPFIX template of %s: %s", sid.c_str(), error.c_str());

        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (candidate->templateMessage.size() > VppHftNetlinkSender::MAX_PAYLOAD_SIZE)
    {
        SWSS_LOG_ERROR("IPFIX template for %s exceeds the Generic Netlink payload limit",
                sid.c_str());

        return SAI_STATUS_INVALID_PARAMETER;
    }

    config = candidate;

    SWSS_LOG_NOTICE("built high frequency telemetry configuration for %s with %zu counters",
            sid.c_str(),
            candidate->fields.size());

    return SAI_STATUS_SUCCESS;
}

sai_status_t SwitchVpp::refreshTamTelIpfixTemplates(
        _In_ sai_object_id_t tam_tel_type_id)
{
    SWSS_LOG_ENTER();

    auto sid = sai_serialize_object_id(tam_tel_type_id);

    std::shared_ptr<const VppHftStreamConfig> config;

    if (m_hftExporter)
    {
        config = m_hftExporter->getStream(tam_tel_type_id);
    }

    if (config == nullptr || config->templateMessage.empty())
    {
        // A removed or never successfully configured stream must not expose a
        // stale template, so drop any previously stored value.
        auto& objectHash = m_objectHash.at(SAI_OBJECT_TYPE_TAM_TEL_TYPE);

        auto object = objectHash.find(sid);

        if (object != objectHash.end())
        {
            auto meta = sai_metadata_get_attr_metadata(
                    SAI_OBJECT_TYPE_TAM_TEL_TYPE,
                    SAI_TAM_TEL_TYPE_ATTR_IPFIX_TEMPLATES);

            if (meta != nullptr)
            {
                object->second.erase(meta->attridname);
            }
        }

        SWSS_LOG_ERROR("no IPFIX template is committed for %s", sid.c_str());

        return SAI_STATUS_ITEM_NOT_FOUND;
    }

    // Store the committed bytes so the shared get path applies the normal
    // two call u8list overflow and success contract.
    std::vector<uint8_t> templateMessage(config->templateMessage);

    sai_attribute_t attr;

    attr.id = SAI_TAM_TEL_TYPE_ATTR_IPFIX_TEMPLATES;
    attr.value.u8list.count = static_cast<uint32_t>(templateMessage.size());
    attr.value.u8list.list = templateMessage.data();

    return set_internal(SAI_OBJECT_TYPE_TAM_TEL_TYPE, sid, &attr);
}
