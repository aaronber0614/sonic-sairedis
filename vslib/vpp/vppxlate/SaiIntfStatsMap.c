/*
 *------------------------------------------------------------------
 * SaiIntfStatsMap.c
 *
 * Shared mapping from VPP interface statistics segment counter names onto
 * vpp_interface_stats_t. The synchronous SAI port statistics path and the
 * high frequency telemetry reader both use these helpers so that one VPP
 * counter name keeps exactly one meaning.
 *
 * This file intentionally has no VPP dependency so the mapping can be unit
 * tested on its own.
 *
 * Copyright (c) 2023 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *------------------------------------------------------------------
 */

#include <string.h>

#include "SaiIntfStats.h"

#define DROPS "drops"
#define PUNT "punt"
#define IP4 "ip4"
#define IP6 "ip6"
#define RX_NO_BUF "rx-no-buf"
#define RX_MISS "rx-miss"
#define RX_ERROR "rx-error"
#define TX_ERROR "tx-error"
#define MPLS "mpls"
#define RX "rx"
#define RX_UNICAST "rx-unicast"
#define RX_MULTICAST "rx-multicast"
#define RX_BROADCAST "rx-broadcast"
#define TX "tx"
#define TX_UNICAST "tx-unicast"
#define TX_MULTICAST "tx-multicast"
#define TX_BROADCAST "tx-broadcast"

#define MARK_PRESENT(present, bit) \
  do { if (present) { *(present) |= (bit); } } while (0)

void vpp_intf_stats_accumulate_one (const char *stat_name, uint64_t count,
				    vpp_interface_stats_t *st_p,
				    uint32_t *present)
{
  if (!strncmp(stat_name, DROPS, sizeof(DROPS)))
    {
      st_p->drops += count;
      MARK_PRESENT(present, VPP_INTF_STAT_PRESENT_DROPS);
    }
  else if (!strncmp(stat_name, PUNT, sizeof(PUNT)))
    {
      st_p->punt += count;
      MARK_PRESENT(present, VPP_INTF_STAT_PRESENT_PUNT);
    }
  else if (!strncmp(stat_name, IP4, sizeof(IP4)))
    {
      st_p->ip4 += count;
      MARK_PRESENT(present, VPP_INTF_STAT_PRESENT_IP4);
    }
  else if (!strncmp(stat_name, IP6, sizeof(IP6)))
    {
      st_p->ip6 += count;
      MARK_PRESENT(present, VPP_INTF_STAT_PRESENT_IP6);
    }
  else if (!strncmp(stat_name, RX_NO_BUF, sizeof(RX_NO_BUF)))
    {
      st_p->rx_no_buf += count;
      MARK_PRESENT(present, VPP_INTF_STAT_PRESENT_RX_NO_BUF);
    }
  else if (!strncmp(stat_name, RX_MISS, sizeof(RX_MISS)))
    {
      st_p->rx_miss += count;
      MARK_PRESENT(present, VPP_INTF_STAT_PRESENT_RX_MISS);
    }
  else if (!strncmp(stat_name, RX_ERROR, sizeof(RX_ERROR)))
    {
      st_p->rx_error += count;
      MARK_PRESENT(present, VPP_INTF_STAT_PRESENT_RX_ERROR);
    }
  else if (!strncmp(stat_name, TX_ERROR, sizeof(TX_ERROR)))
    {
      st_p->tx_error += count;
      MARK_PRESENT(present, VPP_INTF_STAT_PRESENT_TX_ERROR);
    }
  else if (!strncmp(stat_name, MPLS, sizeof(MPLS)))
    {
      st_p->mpls += count;
      MARK_PRESENT(present, VPP_INTF_STAT_PRESENT_MPLS);
    }
}

void vpp_intf_stats_accumulate_two (const char *stat_name, uint64_t count1,
				    uint64_t count2,
				    vpp_interface_stats_t *st_p,
				    uint32_t *present)
{
  if (!strncmp(stat_name, RX, sizeof(RX)))
    {
      st_p->rx += count1;
      st_p->rx_bytes += count2;
      MARK_PRESENT(present, VPP_INTF_STAT_PRESENT_RX);
    }
  else if (!strncmp(stat_name, TX, sizeof(TX)))
    {
      st_p->tx += count1;
      st_p->tx_bytes += count2;
      MARK_PRESENT(present, VPP_INTF_STAT_PRESENT_TX);
    }
  else if (!strncmp(stat_name, RX_UNICAST, sizeof(RX_UNICAST)))
    {
      st_p->rx_unicast += count1;
      st_p->rx_unicast_bytes += count2;
      MARK_PRESENT(present, VPP_INTF_STAT_PRESENT_RX_UNICAST);
    }
  else if (!strncmp(stat_name, RX_MULTICAST, sizeof(RX_MULTICAST)))
    {
      st_p->rx_multicast += count1;
      st_p->rx_multicast_bytes += count2;
      MARK_PRESENT(present, VPP_INTF_STAT_PRESENT_RX_MULTICAST);
    }
  else if (!strncmp(stat_name, RX_BROADCAST, sizeof(RX_BROADCAST)))
    {
      st_p->rx_broadcast += count1;
      st_p->rx_broadcast_bytes += count2;
      MARK_PRESENT(present, VPP_INTF_STAT_PRESENT_RX_BROADCAST);
    }
  else if (!strncmp(stat_name, TX_UNICAST, sizeof(TX_UNICAST)))
    {
      st_p->tx_unicast += count1;
      st_p->tx_unicast_bytes += count2;
      MARK_PRESENT(present, VPP_INTF_STAT_PRESENT_TX_UNICAST);
    }
  else if (!strncmp(stat_name, TX_MULTICAST, sizeof(TX_MULTICAST)))
    {
      st_p->tx_multicast += count1;
      st_p->tx_multicast_bytes += count2;
      MARK_PRESENT(present, VPP_INTF_STAT_PRESENT_TX_MULTICAST);
    }
  else if (!strncmp(stat_name, TX_BROADCAST, sizeof(TX_BROADCAST)))
    {
      st_p->tx_broadcast += count1;
      st_p->tx_broadcast_bytes += count2;
      MARK_PRESENT(present, VPP_INTF_STAT_PRESENT_TX_BROADCAST);
    }
}


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
