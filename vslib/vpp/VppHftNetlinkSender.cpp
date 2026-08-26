#include "VppHftNetlinkSender.h"

#include "swss/logger.h"

#include <linux/genetlink.h>
#include <linux/netlink.h>

#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <chrono>
#include <cstring>

using namespace saivs;

const char* const VppHftNetlinkSender::FAMILY_NAME = "sonic_stel";

// C++14 requires out of line definitions for odr-used static const members.
const uint8_t VppHftNetlinkSender::FAMILY_VERSION;
const uint8_t VppHftNetlinkSender::CMD_PUBLISH;
const uint16_t VppHftNetlinkSender::ATTR_IPFIX;
const size_t VppHftNetlinkSender::MAX_PAYLOAD_SIZE;
const int VppHftNetlinkSender::ACK_TIMEOUT_MS;
const int VppHftNetlinkSender::RECONNECT_BACKOFF_SECONDS;

namespace
{
    /**
     * Receive buffer with netlink message alignment. Using a union avoids
     * casting a byte buffer to struct nlmsghdr.
     */
    union NetlinkReceiveBuffer
    {
        struct nlmsghdr hdr;
        char raw[8192];
    };

    /** Log at most one transport failure per this many suppressed failures. */
    constexpr uint64_t FAILURE_LOG_INTERVAL = 100;

    sockaddr_nl kernelAddress()
    {
        sockaddr_nl addr;

        memset(&addr, 0, sizeof(addr));

        addr.nl_family = AF_NETLINK;

        return addr;
    }
}

VppHftNetlinkSender::VppHftNetlinkSender():
    m_socket(-1),
    m_familyId(0),
    m_sequence(0),
    m_suppressedFailureLogs(0),
    m_nextConnectAttempt(std::chrono::steady_clock::time_point::min())
{
    SWSS_LOG_ENTER();
}

VppHftNetlinkSender::~VppHftNetlinkSender()
{
    SWSS_LOG_ENTER();

    close();
}

void VppHftNetlinkSender::close()
{
    SWSS_LOG_ENTER();

    if (m_socket >= 0)
    {
        ::close(m_socket);
        m_socket = -1;
    }

    m_familyId = 0;
}

bool VppHftNetlinkSender::openSocket()
{
    SWSS_LOG_ENTER();

    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_GENERIC);

    if (fd < 0)
    {
        SWSS_LOG_ERROR("failed to open NETLINK_GENERIC socket: %s", strerror(errno));

        return false;
    }

    sockaddr_nl local;

    memset(&local, 0, sizeof(local));

    local.nl_family = AF_NETLINK;

    if (bind(fd, reinterpret_cast<struct sockaddr*>(&local), sizeof(local)) < 0)
    {
        SWSS_LOG_ERROR("failed to bind NETLINK_GENERIC socket: %s", strerror(errno));

        ::close(fd);

        return false;
    }

    m_socket = fd;

    return true;
}

bool VppHftNetlinkSender::resolveFamilyId(
        int fd,
        uint32_t& sequence,
        uint16_t& familyId)
{
    SWSS_LOG_ENTER();

    const size_t nameLength = strlen(FAMILY_NAME) + 1;
    const size_t attrLength = NLA_HDRLEN + nameLength;
    const size_t genlLength = GENL_HDRLEN + NLA_ALIGN(attrLength);
    const size_t messageLength = NLMSG_LENGTH(genlLength);

    std::vector<uint64_t> storage((messageLength + sizeof(uint64_t) - 1) / sizeof(uint64_t), 0);

    char *base = reinterpret_cast<char*>(storage.data());

    struct nlmsghdr nlh;

    memset(&nlh, 0, sizeof(nlh));

    sequence++;

    nlh.nlmsg_len = static_cast<uint32_t>(messageLength);
    nlh.nlmsg_type = GENL_ID_CTRL;
    nlh.nlmsg_flags = NLM_F_REQUEST;
    nlh.nlmsg_seq = sequence;
    nlh.nlmsg_pid = 0;

    memcpy(base, &nlh, sizeof(nlh));

    struct genlmsghdr genlh;

    memset(&genlh, 0, sizeof(genlh));

    genlh.cmd = CTRL_CMD_GETFAMILY;
    genlh.version = 1;

    memcpy(base + NLMSG_HDRLEN, &genlh, sizeof(genlh));

    struct nlattr nla;

    memset(&nla, 0, sizeof(nla));

    nla.nla_len = static_cast<uint16_t>(attrLength);
    nla.nla_type = CTRL_ATTR_FAMILY_NAME;

    memcpy(base + NLMSG_HDRLEN + GENL_HDRLEN, &nla, sizeof(nla));
    memcpy(base + NLMSG_HDRLEN + GENL_HDRLEN + NLA_HDRLEN, FAMILY_NAME, nameLength);

    sockaddr_nl kernel = kernelAddress();

    ssize_t sent;

    do
    {
        sent = sendto(
                fd,
                base,
                messageLength,
                0,
                reinterpret_cast<struct sockaddr*>(&kernel),
                sizeof(kernel));
    }
    while (sent < 0 && errno == EINTR);

    if (sent < 0)
    {
        SWSS_LOG_WARN("failed to request Generic Netlink family %s: %s",
                FAMILY_NAME,
                strerror(errno));

        return false;
    }

    struct pollfd pfd;

    pfd.fd = fd;
    pfd.events = POLLIN;
    pfd.revents = 0;

    const auto deadline = std::chrono::steady_clock::now() +
            std::chrono::milliseconds(ACK_TIMEOUT_MS);

    int ready;

    do
    {
        const auto now = std::chrono::steady_clock::now();

        if (now >= deadline)
        {
            ready = 0;
            break;
        }

        const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
                deadline - now);

        ready = poll(&pfd, 1, static_cast<int>(remaining.count() + 1));
    }
    while (ready < 0 && errno == EINTR);

    if (ready <= 0)
    {
        SWSS_LOG_WARN("no reply while resolving Generic Netlink family %s", FAMILY_NAME);

        return false;
    }

    NetlinkReceiveBuffer buffer;

    memset(&buffer, 0, sizeof(buffer));

    ssize_t received;

    do
    {
        received = recv(fd, buffer.raw, sizeof(buffer.raw), MSG_TRUNC);
    }
    while (received < 0 && errno == EINTR);

    if (received < 0)
    {
        SWSS_LOG_WARN("failed to receive Generic Netlink family reply: %s", strerror(errno));

        return false;
    }

    if (static_cast<size_t>(received) > sizeof(buffer.raw))
    {
        SWSS_LOG_WARN("received a truncated Generic Netlink family response");

        return false;
    }

    size_t length = static_cast<size_t>(received);

    struct nlmsghdr *nh = &buffer.hdr;

    for (; NLMSG_OK(nh, length); nh = NLMSG_NEXT(nh, length))
    {
        if (nh->nlmsg_type == NLMSG_ERROR)
        {
            if (nh->nlmsg_len < NLMSG_LENGTH(sizeof(struct nlmsgerr)))
            {
                SWSS_LOG_WARN("received a truncated Generic Netlink family error response");

                return false;
            }

            struct nlmsgerr err;

            memcpy(&err, NLMSG_DATA(nh), sizeof(err));

            SWSS_LOG_NOTICE("Generic Netlink family %s is not registered: %s",
                    FAMILY_NAME,
                    strerror(err.error < 0 ? -err.error : err.error));

            return false;
        }

        if (nh->nlmsg_type != GENL_ID_CTRL)
        {
            continue;
        }

        size_t attributeLength = NLMSG_PAYLOAD(nh, GENL_HDRLEN);

        const char *attributes =
                reinterpret_cast<const char*>(NLMSG_DATA(nh)) + GENL_HDRLEN;

        size_t offset = 0;

        while (offset + NLA_HDRLEN <= attributeLength)
        {
            struct nlattr attribute;

            memcpy(&attribute, attributes + offset, sizeof(attribute));

            const size_t attributeSize = static_cast<size_t>(attribute.nla_len);

            if (attribute.nla_len < NLA_HDRLEN ||
                offset + attributeSize > attributeLength)
            {
                break;
            }

            if (attribute.nla_type == CTRL_ATTR_FAMILY_ID &&
                attributeSize >= NLA_HDRLEN + sizeof(uint16_t))
            {
                uint16_t id = 0;

                memcpy(&id, attributes + offset + NLA_HDRLEN, sizeof(id));

                if (id == 0)
                {
                    SWSS_LOG_WARN("Generic Netlink family %s reported id 0", FAMILY_NAME);

                    return false;
                }

                familyId = id;

                return true;
            }

            offset += static_cast<size_t>(NLA_ALIGN(attribute.nla_len));
        }
    }

    SWSS_LOG_WARN("Generic Netlink family %s id was not present in the reply", FAMILY_NAME);

    return false;
}

bool VppHftNetlinkSender::connect()
{
    SWSS_LOG_ENTER();

    if (m_socket < 0 && !openSocket())
    {
        return false;
    }

    if (m_familyId != 0)
    {
        return true;
    }

    if (!resolveFamilyId(m_socket, m_sequence, m_familyId))
    {
        close();

        return false;
    }

    SWSS_LOG_NOTICE("resolved Generic Netlink family %s to id %u", FAMILY_NAME, m_familyId);

    return true;
}

VppHftSink::SendResult VppHftNetlinkSender::waitForAck(
        uint32_t sequence)
{
    SWSS_LOG_ENTER();

    const auto deadline = std::chrono::steady_clock::now() +
            std::chrono::milliseconds(ACK_TIMEOUT_MS);

    while (true)
    {
        auto now = std::chrono::steady_clock::now();

        if (now >= deadline)
        {
            SWSS_LOG_INFO("timed out waiting for the IPFIX publish acknowledgement");

            return SendResult::DROPPED;
        }

        auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
                deadline - now);

        struct pollfd pfd;

        pfd.fd = m_socket;
        pfd.events = POLLIN;
        pfd.revents = 0;

        int ready = poll(&pfd, 1, static_cast<int>(remaining.count() + 1));

        if (ready == 0)
        {
            SWSS_LOG_INFO("timed out waiting for the IPFIX publish acknowledgement");

            return SendResult::DROPPED;
        }

        if (ready < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }

            SWSS_LOG_WARN("poll failed while waiting for the IPFIX publish acknowledgement: %s",
                    strerror(errno));

            return SendResult::FAILED;
        }

        NetlinkReceiveBuffer buffer;

        memset(&buffer, 0, sizeof(buffer));

        ssize_t received = recv(m_socket, buffer.raw, sizeof(buffer.raw), MSG_TRUNC);

        if (received < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }

            if (errno == ENOBUFS)
            {
                // Kernel dropped notifications for this socket, the sample is
                // lost but the socket stays usable.
                return SendResult::DROPPED;
            }

            SWSS_LOG_WARN("failed to receive the IPFIX publish acknowledgement: %s",
                    strerror(errno));

            return SendResult::FAILED;
        }

        if (static_cast<size_t>(received) > sizeof(buffer.raw))
        {
            SWSS_LOG_WARN("received a truncated IPFIX publish response");

            return SendResult::FAILED;
        }

        size_t length = static_cast<size_t>(received);

        struct nlmsghdr *nh = &buffer.hdr;

        for (; NLMSG_OK(nh, length); nh = NLMSG_NEXT(nh, length))
        {
            if (nh->nlmsg_seq != sequence)
            {
                continue;
            }

            if (nh->nlmsg_type != NLMSG_ERROR)
            {
                continue;
            }

            if (nh->nlmsg_len < NLMSG_LENGTH(sizeof(struct nlmsgerr)))
            {
                SWSS_LOG_WARN("received a truncated IPFIX publish acknowledgement");

                return SendResult::FAILED;
            }

            struct nlmsgerr err;

            memcpy(&err, NLMSG_DATA(nh), sizeof(err));

            if (err.error == 0)
            {
                return SendResult::OK;
            }

            int code = err.error < 0 ? -err.error : err.error;

            if (code == ESRCH || code == ENOBUFS)
            {
                // No listener has joined the multicast group, or the kernel
                // could not queue the message. Both lose one sample only.
                return SendResult::DROPPED;
            }

            SWSS_LOG_WARN("IPFIX publish was rejected by the kernel: %s", strerror(code));

            return SendResult::FAILED;
        }

        SWSS_LOG_INFO("ignored an unrelated Generic Netlink message while waiting for sequence %u",
                sequence);
    }
}

VppHftSink::SendResult VppHftNetlinkSender::send(
        const uint8_t *data,
        size_t size)
{
    SWSS_LOG_ENTER();

    if (data == nullptr || size == 0 || size > MAX_PAYLOAD_SIZE)
    {
        SWSS_LOG_ERROR("refusing to publish an IPFIX message of %zu bytes", size);

        return SendResult::FAILED;
    }

    const auto now = std::chrono::steady_clock::now();

    if (now < m_nextConnectAttempt)
    {
        m_suppressedFailureLogs++;

        return SendResult::FAILED;
    }

    if (!connect())
    {
        m_nextConnectAttempt = now +
                std::chrono::seconds(RECONNECT_BACKOFF_SECONDS);

        if (m_suppressedFailureLogs++ % FAILURE_LOG_INTERVAL == 0)
        {
            SWSS_LOG_WARN("Generic Netlink family %s is unavailable, dropped %llu samples",
                    FAMILY_NAME,
                    static_cast<unsigned long long>(m_suppressedFailureLogs));
        }

        return SendResult::FAILED;
    }

    m_nextConnectAttempt = std::chrono::steady_clock::time_point::min();

    const size_t attrLength = NLA_HDRLEN + size;
    const size_t genlLength = GENL_HDRLEN + NLA_ALIGN(attrLength);
    const size_t messageLength = NLMSG_LENGTH(genlLength);

    std::vector<uint64_t> storage((messageLength + sizeof(uint64_t) - 1) / sizeof(uint64_t), 0);

    char *base = reinterpret_cast<char*>(storage.data());

    struct nlmsghdr nlh;

    memset(&nlh, 0, sizeof(nlh));

    m_sequence++;

    uint32_t sequence = m_sequence;

    nlh.nlmsg_len = static_cast<uint32_t>(messageLength);
    nlh.nlmsg_type = m_familyId;
    nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nlh.nlmsg_seq = sequence;
    nlh.nlmsg_pid = 0;

    memcpy(base, &nlh, sizeof(nlh));

    struct genlmsghdr genlh;

    memset(&genlh, 0, sizeof(genlh));

    genlh.cmd = CMD_PUBLISH;
    genlh.version = FAMILY_VERSION;

    memcpy(base + NLMSG_HDRLEN, &genlh, sizeof(genlh));

    struct nlattr nla;

    memset(&nla, 0, sizeof(nla));

    nla.nla_len = static_cast<uint16_t>(attrLength);
    nla.nla_type = ATTR_IPFIX;

    memcpy(base + NLMSG_HDRLEN + GENL_HDRLEN, &nla, sizeof(nla));
    memcpy(base + NLMSG_HDRLEN + GENL_HDRLEN + NLA_HDRLEN, data, size);

    sockaddr_nl kernel = kernelAddress();

    ssize_t sent;

    do
    {
        sent = sendto(
                m_socket,
                base,
                messageLength,
                0,
                reinterpret_cast<struct sockaddr*>(&kernel),
                sizeof(kernel));
    }
    while (sent < 0 && errno == EINTR);

    if (sent < 0)
    {
        int code = errno;

        if (code == EAGAIN || code == ENOBUFS || code == ESRCH)
        {
            return SendResult::DROPPED;
        }

        SWSS_LOG_WARN("failed to publish an IPFIX message: %s", strerror(code));

        // The socket or the family is no longer usable, force a re-resolve on
        // a later sample rather than retrying this one at sampling cadence.
        close();
        m_nextConnectAttempt = std::chrono::steady_clock::now() +
                std::chrono::seconds(RECONNECT_BACKOFF_SECONDS);

        return SendResult::FAILED;
    }

    SendResult result = waitForAck(sequence);

    if (result == SendResult::FAILED)
    {
        close();
        m_nextConnectAttempt = std::chrono::steady_clock::now() +
                std::chrono::seconds(RECONNECT_BACKOFF_SECONDS);
    }

    return result;
}

bool VppHftNetlinkSender::isFamilyAvailable()
{
    SWSS_LOG_ENTER();

    VppHftNetlinkSender probe;

    return probe.connect();
}
