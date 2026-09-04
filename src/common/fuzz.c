/*
 * Frame mutation hooks for fuzzing hostapd's transmit paths
 * Copyright (c) 2025, Noam Rathaus <rathaus@gmail.com>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "utils/includes.h"

#include "utils/common.h"
#include "utils/json.h"
#include "ieee802_11_defs.h"
#include "wpa_common.h"
#include "fuzz.h"

#define TABLE_SIZE 1024

struct fuzz_entry {
	char *key;
	s64 value;
	struct fuzz_entry *next;
};

static struct fuzz_entry *case_ids[TABLE_SIZE] = { NULL };


static unsigned int fuzz_hash(const char *s)
{
	unsigned int h = 5381;

	while (*s)
		h = (h * 33) ^ *s++;

	return h % TABLE_SIZE;
}


static struct fuzz_entry * fuzz_dict_get(const char *key)
{
	struct fuzz_entry *e;

	for (e = case_ids[fuzz_hash(key)]; e; e = e->next) {
		if (os_strcmp(e->key, key) == 0)
			return e;
	}

	return NULL;
}


/*
 * Insert 'key' if absent, otherwise update the existing entry in place.
 * Returns the entry, or NULL if a new one could not be allocated.
 */
static struct fuzz_entry * fuzz_dict_set(const char *key, s64 val)
{
	unsigned int h = fuzz_hash(key);
	struct fuzz_entry *e = fuzz_dict_get(key);

	if (e) {
		e->value = val;
		return e;
	}

	e = os_zalloc(sizeof(*e));
	if (!e)
		return NULL;

	e->key = os_strdup(key);
	if (!e->key) {
		os_free(e);
		return NULL;
	}

	e->value = val;
	e->next = case_ids[h];
	case_ids[h] = e;

	return e;
}


int fuzz_env_int(const char *name, int fallback)
{
	const char *val = getenv(name);
	char *end;
	long n;

	if (!val || *val == '\0')
		return fallback;

	n = strtol(val, &end, 0);
	if (*end != '\0') {
		wpa_printf(MSG_INFO, "[fuzz] ignoring malformed %s='%s'",
			   name, val);
		return fallback;
	}

	return (int) n;
}


/*
 * Per-target resume. Target names come from the call sites and contain spaces,
 * colons and punctuation ("auth-sae", "SAE: TESTING - commit override"), so
 * fold them into an environment variable name: uppercase, everything that is
 * not alphanumeric becomes '_'. Falls back to the global FUZZ_START_CASE.
 *
 *   FUZZ_START_AUTH_SAE=1234 ./hostapd ...
 */
static int fuzz_start_case(const char *target)
{
	const int global = fuzz_env_int("FUZZ_START_CASE", 0);
	char name[128];
	size_t i;

	os_snprintf(name, sizeof(name), "FUZZ_START_%s", target);

	for (i = 0; name[i]; i++) {
		unsigned char c = (unsigned char) name[i];

		if (c >= 'a' && c <= 'z')
			name[i] = c - 'a' + 'A';
		else if (!((c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')))
			name[i] = '_';
	}

	return fuzz_env_int(name, global);
}


/*
 * Runtime kill-switch. A CONFIG_FUZZ binary is still a working AP with
 * FUZZ_DISABLE=1, which is how you confirm a failure comes from the mutation
 * rather than from the configuration. Resolved once.
 */
int fuzz_enabled(void)
{
	static int enabled = -1;

	if (enabled < 0)
		enabled = fuzz_env_int("FUZZ_DISABLE", 0) == 0;

	return enabled;
}


enum mut_kind {
	MUT_SET_INTERESTING = 0,
	MUT_BIT_FLIP = 1,
	MUT_BYTE_XOR = 2
};

static const u8 interesting_values[] = { 0x00, 0x01, 0x7F, 0x80, 0xFF };

#define NUM_INTERESTING ARRAY_SIZE(interesting_values)

/* Cases per kind, per byte offset. The XOR masks deliberately start at 1: a
 * mask of 0 is a no-op and would log a mutation that changed nothing. */
#define CASES_MUT_SET_INTERESTING NUM_INTERESTING
#define CASES_MUT_BIT_FLIP 8
#define CASES_MUT_BYTE_XOR 255

/*
 * Every byte offset gets the full set of mutations before the sweep advances to
 * the next offset, so a crash localises to one field. case_id maps onto
 * (offset, kind, param) exactly once -- no duplicates, and no kind is cut short
 * by another kind's range.
 *
 * To sweep breadth-first instead (all offsets at one mutation, then the next
 * mutation), swap the idx/rem derivation in apply_mutation_int() to
 * idx = case_id % fuzz_len and rem = case_id / fuzz_len. Note that this
 * renumbers every case, so recorded case_ids from one order do not replay
 * under the other.
 */
#define CASES_PER_OFFSET \
	(CASES_MUT_SET_INTERESTING + CASES_MUT_BIT_FLIP + CASES_MUT_BYTE_XOR)

/* First case_id handed out for a target; negative values are not fuzzed, so
 * this gives each target a warm-up period of unmutated frames. */
#define FUZZ_FIRST_CASE_ID (-9)

/*
 * A frame whose hexdump is being held back until the caller finishes building
 * it (see apply_mutation_defer_log()). hostapd is single-threaded, so one
 * pending slot is enough.
 */
static struct wpabuf *pending_log = NULL;


static void fuzz_emit(struct wpabuf *json, const u8 *buf, size_t len)
{
	size_t hexdump_size = 2 * len + 1;
	char *hexdump = os_malloc(hexdump_size);

	if (!hexdump) {
		wpabuf_free(json);
		return;
	}

	/* Use len, as we want the whole buffer (with HDRs) */
	wpa_snprintf_hex(hexdump, hexdump_size, buf, len);

	json_add_string(json, "data", hexdump);
	json_end_object(json);
	wpa_printf(MSG_INFO, "[fuzz] %s", (char *) wpabuf_head(json));

	wpabuf_free(json);
	os_free(hexdump);
}


void fuzz_log_sent_frame(const u8 *buf, size_t len)
{
	struct wpabuf *json = pending_log;

	if (!json)
		return;

	pending_log = NULL;
	fuzz_emit(json, buf, len);
}


static void apply_mutation_int(const char *target, enum fuzz_frame_type type,
			       u8 *reply, size_t len, int defer_log)
{
	struct fuzz_entry *case_entry;
	size_t non_fuzzed_header_size = 0, fuzz_len, idx;
	struct wpabuf *json_output;
	enum mut_kind kind;
	u8 *relevant_reply, *b;
	s64 case_id, case_max, rem;
	u64 param;

	if (!fuzz_enabled())
		return;

	if (len == 0)
		return;

	if (!reply)
		return;

	/* A frame mutated on a previous call was abandoned before it could be
	 * sent (an error path between mutation and transmission). Drop its
	 * held-back log rather than attaching it to this frame. */
	if (pending_log) {
		wpa_printf(MSG_INFO,
			   "[fuzz] previous frame was never sent, dropping its log");
		wpabuf_free(pending_log);
		pending_log = NULL;
	}

	case_entry = fuzz_dict_get(target);
	if (!case_entry) {
		/* Resuming skips the warm-up: when replaying a crash you want
		 * the mutation on the first frame, not nine clean ones. */
		int start = fuzz_start_case(target);

		case_id = start > 0 ? start : FUZZ_FIRST_CASE_ID;
		if (!fuzz_dict_set(target, case_id))
			return;
		if (start > 0) {
			wpa_printf(MSG_INFO,
				   "[fuzz] resuming target '%s' at case %d",
				   target, start);
		}
	} else {
		case_id = case_entry->value + 1;
		case_entry->value = case_id;
	}

	if (type == FUZZ_TYPE_IEEE80211_MGMT) {
		/* Skip the whole 802.11 header: mutating bssid or seq_ctrl only
		 * gets the frame dropped by the peer before it is parsed. */
		non_fuzzed_header_size = IEEE80211_HDRLEN;
	}

	/* Nothing left to fuzz once the header is skipped; guard against the
	 * subtraction below wrapping around. */
	if (len <= non_fuzzed_header_size)
		return;

	relevant_reply = reply + non_fuzzed_header_size;
	fuzz_len = len - non_fuzzed_header_size;

	/* Total number of distinct cases for a frame of this length. */
	case_max = (s64) fuzz_len * CASES_PER_OFFSET;

	if (case_id > case_max)
		case_id = case_max; /* lock it to max value */

	json_output = wpabuf_alloc(1000);
	if (!json_output)
		return;

	json_start_object(json_output, NULL);
	json_add_string(json_output, "msg", "progress");
	json_value_sep(json_output);
	json_add_int(json_output, "case_id", case_id);
	json_value_sep(json_output);
	json_add_int(json_output, "case_max", case_max);
	json_value_sep(json_output);
	json_add_string(json_output, "target", target);
	json_end_object(json_output);
	wpa_printf(MSG_INFO, "[fuzz] %s", (char *) wpabuf_head(json_output));
	wpabuf_free(json_output);

	if (case_id < 0 || case_id >= case_max)
		return;

	/* Deterministic (offset, kind, param) selection: see CASES_PER_OFFSET */
	idx = case_id / CASES_PER_OFFSET;
	rem = case_id % CASES_PER_OFFSET;

	if (rem < (s64) CASES_MUT_SET_INTERESTING) {
		kind = MUT_SET_INTERESTING;
		param = rem;
	} else if (rem < (s64) (CASES_MUT_SET_INTERESTING +
				CASES_MUT_BIT_FLIP)) {
		kind = MUT_BIT_FLIP;
		param = rem - CASES_MUT_SET_INTERESTING;
	} else {
		kind = MUT_BYTE_XOR;
		param = rem - CASES_MUT_SET_INTERESTING - CASES_MUT_BIT_FLIP;
	}

	b = relevant_reply + idx;

	/* Sized from len because the frame is hexdumped in full (headers
	 * included) -- wpabuf overflow calls abort(), which would look like a
	 * target crash. */
	json_output = wpabuf_alloc(2 * len + 256);
	if (!json_output)
		return;

	json_start_object(json_output, NULL);
	json_add_string(json_output, "msg", "fuzz");
	json_value_sep(json_output);
	json_add_string(json_output, "target", target);
	json_value_sep(json_output);
	json_add_int(json_output, "idx", idx);
	json_value_sep(json_output);

	switch (kind) {
	case MUT_SET_INTERESTING: {
		u8 v = interesting_values[param];

		json_add_string(json_output, "type", "MUT_SET_INTERESTING");
		json_value_sep(json_output);
		json_add_int(json_output, "v", v);
		json_value_sep(json_output);
		json_add_int(json_output, "before", *b);
		json_value_sep(json_output);

		*b = v;

		json_add_int(json_output, "after", *b);
		json_value_sep(json_output);
		break;
	}
	case MUT_BIT_FLIP: {
		u8 bit = (u8) param;

		json_add_string(json_output, "type", "MUT_BIT_FLIP");
		json_value_sep(json_output);
		json_add_int(json_output, "bit", bit);
		json_value_sep(json_output);
		json_add_int(json_output, "before", *b);
		json_value_sep(json_output);

		*b ^= 1U << bit;

		json_add_int(json_output, "after", *b);
		json_value_sep(json_output);
		break;
	}
	case MUT_BYTE_XOR: {
		/* param is 0-based, masks run 1..255 */
		u8 mask = (u8) (param + 1);

		json_add_string(json_output, "type", "MUT_BYTE_XOR");
		json_value_sep(json_output);
		json_add_int(json_output, "mask", mask);
		json_value_sep(json_output);
		json_add_int(json_output, "before", *b);
		json_value_sep(json_output);

		*b ^= mask;

		json_add_int(json_output, "after", *b);
		json_value_sep(json_output);
		break;
	}
	}

	if (defer_log)
		pending_log = json_output;
	else
		fuzz_emit(json_output, reply, len);
}


void apply_mutation(const char *target, enum fuzz_frame_type type, u8 *reply,
		    size_t len)
{
	apply_mutation_int(target, type, reply, len, 0);
}


void apply_mutation_defer_log(const char *target, enum fuzz_frame_type type,
			      u8 *reply, size_t len)
{
	apply_mutation_int(target, type, reply, len, 1);
}
