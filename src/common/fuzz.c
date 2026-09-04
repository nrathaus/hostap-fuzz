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

enum MutKind
{
	MUT_SET_INTERESTING = 0,
	MUT_BIT_FLIP = 1,
	MUT_BYTE_XOR = 2
};

#define MAX_CASES_MUT_SET_INTERESTING 5
#define MAX_CASES_MUT_BIT_FLIP 8
#define MAX_CASES_MUT_BYTE_XOR 255

/* First case_id handed out for a target; negative values are not fuzzed, so
 * this gives each target a warm-up period of unmutated frames. */
#define FUZZ_FIRST_CASE_ID (-9)

static const uint8_t interesting_values[] = {
	0x00, 0x01, 0x7F, 0x80, 0xFF};

static const size_t NUM_INTERESTING = sizeof(interesting_values) / sizeof(interesting_values[0]);

#define NUM_MUT_KINDS 3

void apply_mutation(const char *target, int type, uint8_t *reply, size_t len)
{
	if (len == 0)
		return;

	if (reply == NULL)
		return;

	int64_t case_id;
	Entry *case_entry = dict_get(target);

	if (case_entry == NULL)
	{
		// wpa_printf(MSG_INFO, "case_entry for: '%s' not found", target);
		case_id = FUZZ_FIRST_CASE_ID;
		if (dict_set(target, case_id) == NULL)
			return;
	}
	else
	{
		// wpa_printf(MSG_INFO, "case_entry for: '%s' found, value: %ld", target, case_entry->value);
		case_id = case_entry->value + 1;
		case_entry->value = case_id;
	}

	uint8_t *relevant_reply = reply;
	size_t non_fuzzed_header_size = 0;
	if (type == 1) // ieee80211_mgmt
	{
		non_fuzzed_header_size =
			sizeof(((struct ieee80211_mgmt *)reply)->frame_control) +
			sizeof(((struct ieee80211_mgmt *)reply)->duration) +
			sizeof(((struct ieee80211_mgmt *)reply)->da) +
			sizeof(((struct ieee80211_mgmt *)reply)->sa);
		relevant_reply = (uint8_t *)reply + non_fuzzed_header_size;
	}
	if (type == 2) // ieee802_1x_hdr
	{
		// No need to "move"
	}

	/* Nothing left to fuzz once the header is skipped; guard against the
	 * subtraction below wrapping around. */
	if (len <= non_fuzzed_header_size)
		return;

	const size_t fuzz_len = len - non_fuzzed_header_size;

	// Deterministic index selection
	size_t idx = case_id % fuzz_len;

	// Deterministic mutation kind
	enum MutKind kind = (enum MutKind)((case_id / fuzz_len) % NUM_MUT_KINDS);

	// Parameter for bit/value selection
	uint64_t param = case_id / (fuzz_len * NUM_MUT_KINDS);

	uint8_t *b = relevant_reply + idx;

	int64_t case_max = 100000;
	switch (kind)
	{
	case MUT_SET_INTERESTING:
	{
		case_max = MAX_CASES_MUT_SET_INTERESTING * fuzz_len;
		break;
	}
	case MUT_BIT_FLIP:
	{
		case_max = MAX_CASES_MUT_BIT_FLIP * fuzz_len;
		break;
	}
	case MUT_BYTE_XOR:
	{
		case_max = MAX_CASES_MUT_BYTE_XOR * fuzz_len;
		break;
	}
	default:
		break;
	}

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

	if (case_id < 0 || case_id == case_max)
		return;

	/* The frame is hexdumped in full (headers included), so both buffers
	 * have to be sized from 'len' rather than a fixed guess -- wpabuf
	 * overflow calls abort(), which would look like a target crash. */
	const size_t hexdump_size = 2 * len + 1;
	char *hexdump = os_malloc(hexdump_size);
	if (hexdump == NULL)
		return;

	json_output = wpabuf_alloc(hexdump_size + 256);
	if (json_output == NULL)
	{
		os_free(hexdump);
		return;
	}

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
		uint8_t v = interesting_values[param % NUM_INTERESTING];

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
		uint8_t bit = (uint8_t)(param % 8);

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
		uint8_t mask = (uint8_t)(param & 0xFF);

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

	// Use len, as we want the whole buffer (with HDRs)
	wpa_snprintf_hex(hexdump, hexdump_size, reply, len);

	json_add_string(json_output, "data", hexdump);

	json_end_object(json_output);
	wpa_printf(MSG_INFO, "[fuzz] %s", (char *)wpabuf_head(json_output));
	wpabuf_free(json_output);
	os_free(hexdump);
}
