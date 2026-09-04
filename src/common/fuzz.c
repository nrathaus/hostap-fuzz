#include "utils/includes.h"
#include "ieee802_11_defs.h"
#include "fuzz.h"

#include "utils/common.h"

#include "utils/json.h"

#include "wpa_common.h"

#define TABLE_SIZE 1024

typedef struct Entry
{
	char *key;
	int64_t value;
	struct Entry *next;
} Entry;

static Entry *case_ids[TABLE_SIZE] = {0};

unsigned int hash(const char *s)
{
	unsigned int h = 5381;
	while (*s)
		h = (h * 33) ^ *s++;
	return h % TABLE_SIZE;
}

Entry *dict_get(const char *key)
{
	unsigned int h = hash(key);
	for (Entry *e = case_ids[h]; e; e = e->next)
		if (strcmp(e->key, key) == 0)
			return e;

	return NULL;
}

/*
 * Insert 'key' if absent, otherwise update the existing entry in place.
 * Returns the entry, or NULL if a new one could not be allocated.
 */
Entry *dict_set(const char *key, int64_t val)
{
	unsigned int h = hash(key);
	Entry *e = dict_get(key);

	if (e)
	{
		e->value = val;
		return e;
	}

	e = malloc(sizeof(Entry));
	if (e == NULL)
		return NULL;

	e->key = strdup(key);
	if (e->key == NULL)
	{
		free(e);
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

	if (val == NULL || *val == '\0')
		return fallback;

	n = strtol(val, &end, 0);
	if (*end != '\0')
	{
		wpa_printf(MSG_INFO, "[fuzz] ignoring malformed %s='%s'",
			   name, val);
		return fallback;
	}

	return (int)n;
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

	for (i = 0; name[i]; i++)
	{
		unsigned char c = (unsigned char)name[i];

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

enum MutKind
{
	MUT_SET_INTERESTING = 0,
	MUT_BIT_FLIP = 1,
	MUT_BYTE_XOR = 2
};

static const uint8_t interesting_values[] = {
	0x00, 0x01, 0x7F, 0x80, 0xFF};

#define NUM_INTERESTING (sizeof(interesting_values) / sizeof(interesting_values[0]))

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

static void fuzz_emit(struct wpabuf *json, const uint8_t *buf, size_t len)
{
	const size_t hexdump_size = 2 * len + 1;
	char *hexdump = os_malloc(hexdump_size);

	if (hexdump == NULL)
	{
		wpabuf_free(json);
		return;
	}

	/* Use len, as we want the whole buffer (with HDRs) */
	wpa_snprintf_hex(hexdump, hexdump_size, buf, len);

	json_add_string(json, "data", hexdump);
	json_end_object(json);
	wpa_printf(MSG_INFO, "[fuzz] %s", (char *)wpabuf_head(json));

	wpabuf_free(json);
	os_free(hexdump);
}

void fuzz_log_sent_frame(const uint8_t *buf, size_t len)
{
	struct wpabuf *json = pending_log;

	if (json == NULL)
		return;

	pending_log = NULL;
	fuzz_emit(json, buf, len);
}

static void apply_mutation_int(const char *target, int type, uint8_t *reply,
			       size_t len, int defer_log)
{
	if (!fuzz_enabled())
		return;

	if (len == 0)
		return;

	if (reply == NULL)
		return;

	/* A frame mutated on a previous call was abandoned before it could be
	 * sent (an error path between mutation and transmission). Drop its
	 * held-back log rather than attaching it to this frame. */
	if (pending_log)
	{
		wpa_printf(MSG_INFO,
			   "[fuzz] previous frame was never sent, dropping its log");
		wpabuf_free(pending_log);
		pending_log = NULL;
	}

	int64_t case_id;
	Entry *case_entry = dict_get(target);

	if (case_entry == NULL)
	{
		/* Resuming skips the warm-up: when replaying a crash you want
		 * the mutation on the first frame, not nine clean ones. */
		int start = fuzz_start_case(target);

		case_id = start > 0 ? start : FUZZ_FIRST_CASE_ID;
		if (start > 0)
			wpa_printf(MSG_INFO,
				   "[fuzz] resuming target '%s' at case %d",
				   target, start);
		if (dict_set(target, case_id) == NULL)
			return;
	}
	else
	{
		case_id = case_entry->value + 1;
		case_entry->value = case_id;
	}

	size_t non_fuzzed_header_size = 0;
	if (type == 1) // ieee80211_mgmt
	{
		/* Skip the whole 802.11 header: mutating bssid or seq_ctrl only
		 * gets the frame dropped by the peer before it is parsed. */
		non_fuzzed_header_size = IEEE80211_HDRLEN;
	}
	if (type == 2) // ieee802_1x_hdr
	{
		// No need to "move"
	}

	/* Nothing left to fuzz once the header is skipped; guard against the
	 * subtraction below wrapping around. */
	if (len <= non_fuzzed_header_size)
		return;

	uint8_t *const relevant_reply = reply + non_fuzzed_header_size;
	const size_t fuzz_len = len - non_fuzzed_header_size;

	/* Total number of distinct cases for a frame of this length. */
	const int64_t case_max = (int64_t)fuzz_len * CASES_PER_OFFSET;

	if (case_id > case_max)
	{
		// Lock it to max value
		case_id = case_max;
	}

	struct wpabuf *json_output = wpabuf_alloc(1000);
	if (json_output == NULL)
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
	wpa_printf(MSG_INFO, "[fuzz] %s", (char *)wpabuf_head(json_output));
	wpabuf_free(json_output);

	if (case_id < 0 || case_id >= case_max)
		return;

	/* Deterministic (offset, kind, param) selection: see CASES_PER_OFFSET. */
	const size_t idx = case_id / CASES_PER_OFFSET;
	const int64_t rem = case_id % CASES_PER_OFFSET;

	enum MutKind kind;
	uint64_t param;

	if (rem < (int64_t)CASES_MUT_SET_INTERESTING)
	{
		kind = MUT_SET_INTERESTING;
		param = rem;
	}
	else if (rem < (int64_t)(CASES_MUT_SET_INTERESTING + CASES_MUT_BIT_FLIP))
	{
		kind = MUT_BIT_FLIP;
		param = rem - CASES_MUT_SET_INTERESTING;
	}
	else
	{
		kind = MUT_BYTE_XOR;
		param = rem - CASES_MUT_SET_INTERESTING - CASES_MUT_BIT_FLIP;
	}

	uint8_t *b = relevant_reply + idx;

	/* Sized from len because the frame is hexdumped in full (headers
	 * included) -- wpabuf overflow calls abort(), which would look like a
	 * target crash. */
	json_output = wpabuf_alloc(2 * len + 256);
	if (json_output == NULL)
		return;

	json_start_object(json_output, NULL);
	json_add_string(json_output, "msg", "fuzz");
	json_value_sep(json_output);
	json_add_string(json_output, "target", target);
	json_value_sep(json_output);
	json_add_int(json_output, "idx", idx);
	json_value_sep(json_output);

	switch (kind)
	{
	case MUT_SET_INTERESTING:
	{
		uint8_t v = interesting_values[param];

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
	case MUT_BIT_FLIP:
	{
		uint8_t bit = (uint8_t)param;

		json_add_string(json_output, "type", "MUT_BIT_FLIP");
		json_value_sep(json_output);
		json_add_int(json_output, "bit", bit);
		json_value_sep(json_output);
		json_add_int(json_output, "before", *b);
		json_value_sep(json_output);

		*b ^= (1u << bit);

		json_add_int(json_output, "after", *b);
		json_value_sep(json_output);

		break;
	}
	case MUT_BYTE_XOR:
	{
		/* param is 0-based, masks run 1..255 */
		uint8_t mask = (uint8_t)(param + 1);

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

void apply_mutation(const char *target, int type, uint8_t *reply, size_t len)
{
	apply_mutation_int(target, type, reply, len, 0);
}

void apply_mutation_defer_log(const char *target, int type, uint8_t *reply,
			      size_t len)
{
	apply_mutation_int(target, type, reply, len, 1);
}
