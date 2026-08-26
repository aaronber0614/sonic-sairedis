/*
 *------------------------------------------------------------------
 * SaiVppStatsReader.c
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

#include <vpp-api/client/stat_client.h>
#include <vlib/vlib.h>

#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../SaiVppLog.h"
#include "SaiIntfStats.h"
#include "SaiVppStatsReader.h"

#define INTF_PREFIX "/interfaces/"
#define INTF_PREFIX_LEN (sizeof(INTF_PREFIX) - 1)

/*
 * A listing that fails to access the statistics segment this many times in a
 * row is treated as a broken mapping and forces a reconnect.
 */
#define MAX_CONSECUTIVE_ACCESS_FAILURES 10

#define CONNECT_BACKOFF_MIN_NSEC (100ULL * 1000ULL * 1000ULL)   /* 100ms */
#define CONNECT_BACKOFF_MAX_NSEC (5ULL * 1000ULL * 1000ULL * 1000ULL) /* 5s */

struct vpp_stats_reader_
{
  stat_client_main_t sm;
  int connected;
  uint64_t timeout;

  /* Directory indices cached while the VPP statistics epoch is stable. */
  uint32_t *dir;
  /* Interface set that produced "dir", stored as NUL separated names. */
  char *dir_key;
  size_t dir_key_len;

  uint32_t consecutive_access_failures;

  uint64_t next_connect_nsec;
  uint64_t connect_backoff_nsec;
};

static uint64_t monotonic_nsec (void)
{
  struct timespec ts;

  clock_gettime (CLOCK_MONOTONIC, &ts);

  return (uint64_t) ts.tv_sec * 1000000000ULL + (uint64_t) ts.tv_nsec;
}

static int is_bre_special (char c)
{
  return c == '.' || c == '*' || c == '[' || c == ']' || c == '^' ||
	 c == '$' || c == '\\';
}

/*
 * stat_segment_ls_r() compiles each pattern as a POSIX basic regular
 * expression, so interface names must be escaped before they are embedded in
 * one. The pattern is anchored and keeps the trailing separator so that
 * "bobm1" cannot match "/interfaces/bobm10/rx".
 */
char *vpp_stats_reader_build_pattern (const char *ifname)
{
  size_t len = strlen (ifname);
  /* "^" + prefix + escaped name + "/" + NUL */
  char *pattern = (char *) malloc (1 + INTF_PREFIX_LEN + 2 * len + 2);
  size_t pos = 0;
  size_t i;

  if (!pattern)
    return NULL;

  pattern[pos++] = '^';
  memcpy (pattern + pos, INTF_PREFIX, INTF_PREFIX_LEN);
  pos += INTF_PREFIX_LEN;

  for (i = 0; i < len; i++)
    {
      if (is_bre_special (ifname[i]))
	pattern[pos++] = '\\';
      pattern[pos++] = ifname[i];
    }

  pattern[pos++] = '/';
  pattern[pos] = '\0';

  return pattern;
}

static void free_dir (vpp_stats_reader_t *reader)
{
  if (reader->dir)
    {
      vec_free (reader->dir);
      reader->dir = NULL;
    }

  free (reader->dir_key);
  reader->dir_key = NULL;
  reader->dir_key_len = 0;
}

/* Serialize the requested interface names so a changed request set can be
 * detected without re-listing on every sample. */
static char *build_dir_key (const char *const *ifnames, uint32_t n_ifnames,
			    size_t *key_len)
{
  size_t total = 0;
  uint32_t i;
  char *key;
  size_t pos = 0;

  for (i = 0; i < n_ifnames; i++)
    total += strlen (ifnames[i]) + 1;

  key = (char *) malloc (total ? total : 1);

  if (!key)
    return NULL;

  for (i = 0; i < n_ifnames; i++)
    {
      size_t len = strlen (ifnames[i]) + 1;
      memcpy (key + pos, ifnames[i], len);
      pos += len;
    }

  *key_len = total;

  return key;
}

static int connect_reader (vpp_stats_reader_t *reader)
{
  uint64_t now = monotonic_nsec ();

  if (now < reader->next_connect_nsec)
    return VPP_STATS_READER_ERROR;

  if (stat_segment_connect_r (STAT_SEGMENT_SOCKET_FILE, &reader->sm))
    {
      if (reader->connect_backoff_nsec < CONNECT_BACKOFF_MIN_NSEC)
	reader->connect_backoff_nsec = CONNECT_BACKOFF_MIN_NSEC;
      else if (reader->connect_backoff_nsec < CONNECT_BACKOFF_MAX_NSEC)
	reader->connect_backoff_nsec *= 2;

      if (reader->connect_backoff_nsec > CONNECT_BACKOFF_MAX_NSEC)
	reader->connect_backoff_nsec = CONNECT_BACKOFF_MAX_NSEC;

      reader->next_connect_nsec = now + reader->connect_backoff_nsec;

      return VPP_STATS_READER_ERROR;
    }

  stat_segment_set_timeout_nsec (&reader->sm, reader->timeout);

  reader->connected = 1;
  reader->connect_backoff_nsec = 0;
  reader->next_connect_nsec = 0;
  reader->consecutive_access_failures = 0;

  return VPP_STATS_READER_OK;
}

/*
 * Rebuild the cached directory indices. Returns VPP_STATS_READER_OK when
 * "dir" is usable, VPP_STATS_READER_RETRY when the listing produced nothing
 * usable this round, and VPP_STATS_READER_ERROR when the segment could not be
 * accessed repeatedly.
 */
static int refresh_dir (vpp_stats_reader_t *reader, const char *const *ifnames,
			uint32_t n_ifnames)
{
  uint8_t **patterns = 0;
  uint32_t i;
  uint32_t *dir;
  int rv = VPP_STATS_READER_OK;

  free_dir (reader);

  for (i = 0; i < n_ifnames; i++)
    {
      char *pattern = vpp_stats_reader_build_pattern (ifnames[i]);

      if (!pattern)
	{
	  SAIVPP_ERROR("out of memory building VPP stats pattern");
	  rv = VPP_STATS_READER_ERROR;
	  goto done;
	}

      vec_add1 (patterns, (uint8_t *) pattern);
    }

  dir = stat_segment_ls_r (patterns, &reader->sm);

  if (!dir)
    {
      reader->consecutive_access_failures++;

      if (reader->consecutive_access_failures >=
	  MAX_CONSECUTIVE_ACCESS_FAILURES)
	{
	  SAIVPP_ERROR("VPP statistics segment inaccessible for %u "
		       "consecutive listings, reconnecting",
		       reader->consecutive_access_failures);
	  rv = VPP_STATS_READER_ERROR;
	}
      else
	{
	  rv = VPP_STATS_READER_RETRY;
	}

      goto done;
    }

  reader->consecutive_access_failures = 0;

  if (vec_len (dir) == 0)
    {
      /* None of the requested interfaces exist in the segment yet. */
      vec_free (dir);
      rv = VPP_STATS_READER_RETRY;
      goto done;
    }

  reader->dir = dir;
  reader->dir_key = build_dir_key (ifnames, n_ifnames, &reader->dir_key_len);

  if (!reader->dir_key)
    {
      SAIVPP_ERROR("out of memory caching VPP stats directory key");
      free_dir (reader);
      rv = VPP_STATS_READER_ERROR;
    }

done:
  for (i = 0; i < vec_len (patterns); i++)
    free (patterns[i]);

  vec_free (patterns);

  if (rv == VPP_STATS_READER_ERROR)
    vpp_stats_reader_disconnect (reader);

  return rv;
}

static int dir_matches_request (const vpp_stats_reader_t *reader,
				const char *const *ifnames, uint32_t n_ifnames)
{
  size_t pos = 0;
  uint32_t i;

  if (!reader->dir || !reader->dir_key)
    return 0;

  for (i = 0; i < n_ifnames; i++)
    {
      size_t len = strlen (ifnames[i]) + 1;

      if (pos + len > reader->dir_key_len)
	return 0;

      if (memcmp (reader->dir_key + pos, ifnames[i], len))
	return 0;

      pos += len;
    }

  return pos == reader->dir_key_len;
}

/*
 * Resolve "/interfaces/<name>/<counter>" to the index of <name> in the
 * requested set. Returns ~0 when the entry belongs to another interface.
 */
uint32_t vpp_stats_reader_resolve_interface (const char *entry_name,
					     const char *const *ifnames,
					     uint32_t n_ifnames,
					     const char **counter_name)
{
  const char *last_slash;
  size_t name_len;
  uint32_t i;

  if (strncmp (entry_name, INTF_PREFIX, INTF_PREFIX_LEN))
    return ~0u;

  last_slash = strrchr (entry_name, '/');

  if (!last_slash || last_slash <= entry_name + INTF_PREFIX_LEN)
    return ~0u;

  name_len = (size_t) (last_slash - (entry_name + INTF_PREFIX_LEN));

  for (i = 0; i < n_ifnames; i++)
    {
      if (strlen (ifnames[i]) == name_len &&
	  !memcmp (ifnames[i], entry_name + INTF_PREFIX_LEN, name_len))
	{
	  *counter_name = last_slash + 1;
	  return i;
	}
    }

  return ~0u;
}

vpp_stats_reader_t *vpp_stats_reader_create (uint64_t access_timeout_nsec)
{
  vpp_stats_reader_t *reader =
    (vpp_stats_reader_t *) calloc (1, sizeof (*reader));

  if (!reader)
    return NULL;

  reader->timeout = access_timeout_nsec;

  return reader;
}

void vpp_stats_reader_destroy (vpp_stats_reader_t *reader)
{
  if (!reader)
    return;

  vpp_stats_reader_disconnect (reader);

  free (reader);
}

void vpp_stats_reader_disconnect (vpp_stats_reader_t *reader)
{
  if (!reader)
    return;

  free_dir (reader);

  if (reader->connected)
    {
      stat_segment_disconnect_r (&reader->sm);
      reader->connected = 0;
    }
}

int vpp_stats_reader_is_connected (const vpp_stats_reader_t *reader)
{
  return reader && reader->connected;
}

int vpp_stats_reader_sample (vpp_stats_reader_t *reader,
			     const char *const *ifnames, uint32_t n_ifnames,
			     vpp_interface_sample_t *out)
{
  stat_segment_data_t *res;
  uint32_t i, j, k;

  if (!reader || !ifnames || !out || n_ifnames == 0)
    return VPP_STATS_READER_ERROR;

  if (!reader->connected)
    {
      int rv = connect_reader (reader);

      if (rv != VPP_STATS_READER_OK)
	return rv;
    }

  if (!dir_matches_request (reader, ifnames, n_ifnames))
    {
      int rv = refresh_dir (reader, ifnames, n_ifnames);

      if (rv != VPP_STATS_READER_OK)
	return rv;
    }

  res = stat_segment_dump_r (reader->dir, &reader->sm);

  if (!res)
    {
      /*
       * The directory epoch moved or the segment could not be read within the
       * bounded access timeout. Drop this sample, refresh the cached indices
       * and continue without disconnecting.
       */
      int rv = refresh_dir (reader, ifnames, n_ifnames);

      return rv == VPP_STATS_READER_ERROR ? VPP_STATS_READER_ERROR
					  : VPP_STATS_READER_RETRY;
    }

  memset (out, 0, sizeof (*out) * n_ifnames);

  for (i = 0; i < vec_len (res); i++)
    {
      const char *counter_name = NULL;
      uint32_t idx;

      if (!res[i].name)
	continue;

      idx = vpp_stats_reader_resolve_interface (res[i].name, ifnames,
						n_ifnames, &counter_name);

      if (idx == ~0u)
	continue;

      switch (res[i].type)
	{
	case STAT_DIR_TYPE_COUNTER_VECTOR_SIMPLE:
	  if (res[i].simple_counter_vec == 0)
	    continue;
	  for (k = 0; k < vec_len (res[i].simple_counter_vec); k++)
	    for (j = 0; j < vec_len (res[i].simple_counter_vec[k]); j++)
	      vpp_intf_stats_accumulate_one (counter_name,
					     res[i].simple_counter_vec[k][j],
					     &out[idx].stats,
					     &out[idx].present);
	  break;

	case STAT_DIR_TYPE_COUNTER_VECTOR_COMBINED:
	  if (res[i].combined_counter_vec == 0)
	    continue;
	  for (k = 0; k < vec_len (res[i].combined_counter_vec); k++)
	    for (j = 0; j < vec_len (res[i].combined_counter_vec[k]); j++)
	      vpp_intf_stats_accumulate_two (
		counter_name, res[i].combined_counter_vec[k][j].packets,
		res[i].combined_counter_vec[k][j].bytes, &out[idx].stats,
		&out[idx].present);
	  break;

	default:
	  break;
	}
    }

  stat_segment_data_free (res);

  return VPP_STATS_READER_OK;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
