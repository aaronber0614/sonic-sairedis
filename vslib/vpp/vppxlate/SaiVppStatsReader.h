/*
 *------------------------------------------------------------------
 * SaiVppStatsReader.h
 *
 * Persistent, reentrant VPP statistics segment reader used by the high
 * frequency telemetry exporter.
 *
 * Unlike vpp_stats_dump(), which connects, lists, dumps and disconnects on
 * every query, a reader owns one stat_client_main_t for the lifetime of the
 * exporter worker thread, caches the statistics directory indices while the
 * VPP statistics epoch is stable, and performs one bounded dump per sample.
 * It carries no process-global mutable initialization state, so it can be
 * used concurrently with the synchronous vpp_intf_stats_query() path.
 *
 * Copyright (c) 2026 Microsoft Open Technologies, Inc.
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

#ifndef _SAI_VPP_STATS_READER_H_
#define _SAI_VPP_STATS_READER_H_

#include <stdint.h>

#include "SaiIntfStats.h"

#ifdef __cplusplus
extern "C" {
#endif

/* One sampled interface. "present" carries VPP_INTF_STAT_PRESENT_* bits for
 * the counters that were actually returned by VPP for this interface. */
typedef struct vpp_interface_sample_
{
    vpp_interface_stats_t stats;
    uint32_t present;
} vpp_interface_sample_t;

/* Sample completed, every requested interface was dumped. */
#define VPP_STATS_READER_OK       0
/* Transient condition (directory epoch change or bounded access timeout).
 * The caller drops this sample and retries on the next one. The reader stays
 * connected. */
#define VPP_STATS_READER_RETRY    1
/* Socket or shared memory mapping failure. The reader is disconnected and
 * applies a bounded backoff before the next connect attempt. */
#define VPP_STATS_READER_ERROR  (-1)

typedef struct vpp_stats_reader_ vpp_stats_reader_t;

/*
 * Create a reader. "access_timeout_nsec" bounds how long a sample waits for a
 * VPP writer that holds the statistics segment in progress; 0 means the VPP
 * default of an unbounded spin and must not be used by a periodic worker.
 * Returns NULL on allocation failure.
 */
vpp_stats_reader_t *vpp_stats_reader_create(uint64_t access_timeout_nsec);

void vpp_stats_reader_destroy(vpp_stats_reader_t *reader);

/*
 * Sample "n_ifnames" VPP interfaces in one directory dump. "out" must have
 * room for n_ifnames entries and is fully overwritten on VPP_STATS_READER_OK.
 */
int vpp_stats_reader_sample(vpp_stats_reader_t *reader,
                            const char *const *ifnames,
                            uint32_t n_ifnames,
                            vpp_interface_sample_t *out);

void vpp_stats_reader_disconnect(vpp_stats_reader_t *reader);

int vpp_stats_reader_is_connected(const vpp_stats_reader_t *reader);

/*
 * Pure helpers, exposed for unit tests.
 *
 * vpp_stats_reader_build_pattern() returns a malloc'd anchored POSIX basic
 * regular expression that matches every statistics entry of one interface, or
 * NULL on allocation failure. The caller frees it.
 *
 * vpp_stats_reader_resolve_interface() maps a dumped entry name of the form
 * "/interfaces/<name>/<counter>" to the index of <name> in the requested set
 * and sets *counter_name. It returns ~0u when the entry belongs to another
 * interface.
 */
char *vpp_stats_reader_build_pattern(const char *ifname);

uint32_t vpp_stats_reader_resolve_interface(const char *entry_name,
                                            const char *const *ifnames,
                                            uint32_t n_ifnames,
                                            const char **counter_name);

#ifdef __cplusplus
}
#endif

#endif /* _SAI_VPP_STATS_READER_H_ */
