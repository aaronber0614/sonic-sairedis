/*
 *------------------------------------------------------------------
 * SaiIntfStats.h
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

#ifndef _SAI_INTF_STATS_H_
#define _SAI_INTF_STATS_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct vpp_interface_stats_ {
  uint64_t drops;
  uint64_t punt;
  uint64_t ip4;
  uint64_t ip6;
  uint64_t rx_no_buf;
  uint64_t rx_miss;
  uint64_t rx_error;
  uint64_t tx_error;
  uint64_t mpls;

  uint64_t rx;
  uint64_t rx_bytes;
  uint64_t rx_unicast;
  uint64_t rx_unicast_bytes;
  uint64_t rx_multicast;
  uint64_t rx_multicast_bytes;
  uint64_t rx_broadcast;
  uint64_t rx_broadcast_bytes;

  uint64_t tx;
  uint64_t tx_bytes;
  uint64_t tx_unicast;
  uint64_t tx_unicast_bytes;
  uint64_t tx_multicast;
  uint64_t tx_multicast_bytes;
  uint64_t tx_broadcast;
  uint64_t tx_broadcast_bytes;

} vpp_interface_stats_t;

/*
 * Bit per VPP interface counter observed while accumulating a statistics
 * dump. A consumer that must not substitute zero for an absent counter
 * checks the corresponding bit before using the value.
 */
#define VPP_INTF_STAT_PRESENT_DROPS        (1u << 0)
#define VPP_INTF_STAT_PRESENT_PUNT         (1u << 1)
#define VPP_INTF_STAT_PRESENT_IP4          (1u << 2)
#define VPP_INTF_STAT_PRESENT_IP6          (1u << 3)
#define VPP_INTF_STAT_PRESENT_RX_NO_BUF    (1u << 4)
#define VPP_INTF_STAT_PRESENT_RX_MISS      (1u << 5)
#define VPP_INTF_STAT_PRESENT_RX_ERROR     (1u << 6)
#define VPP_INTF_STAT_PRESENT_TX_ERROR     (1u << 7)
#define VPP_INTF_STAT_PRESENT_MPLS         (1u << 8)
#define VPP_INTF_STAT_PRESENT_RX           (1u << 9)
#define VPP_INTF_STAT_PRESENT_RX_UNICAST   (1u << 10)
#define VPP_INTF_STAT_PRESENT_RX_MULTICAST (1u << 11)
#define VPP_INTF_STAT_PRESENT_RX_BROADCAST (1u << 12)
#define VPP_INTF_STAT_PRESENT_TX           (1u << 13)
#define VPP_INTF_STAT_PRESENT_TX_UNICAST   (1u << 14)
#define VPP_INTF_STAT_PRESENT_TX_MULTICAST (1u << 15)
#define VPP_INTF_STAT_PRESENT_TX_BROADCAST (1u << 16)

int vpp_intf_stats_query(const char *intf_name, vpp_interface_stats_t *stats);

/*
 * Shared accumulation of one VPP statistics-segment entry into
 * vpp_interface_stats_t. The synchronous query path and the high frequency
 * telemetry reader both use these helpers so a VPP counter name keeps one
 * meaning. "present" is optional and receives VPP_INTF_STAT_PRESENT_* bits.
 */
void vpp_intf_stats_accumulate_one(const char *stat_name, uint64_t count,
                                   vpp_interface_stats_t *stats,
                                   uint32_t *present);

void vpp_intf_stats_accumulate_two(const char *stat_name, uint64_t count1,
                                   uint64_t count2,
                                   vpp_interface_stats_t *stats,
                                   uint32_t *present);

#ifdef __cplusplus
}
#endif

#endif
