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
	int value;
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

void dict_set(const char *key, int val)
{
	unsigned int h = hash(key);
	Entry *e = malloc(sizeof(Entry));
	e->key = strdup(key);
	e->value = val;
	e->next = case_ids[h];
	case_ids[h] = e;
}

Entry *dict_get(const char *key)
{
	unsigned int h = hash(key);
	for (Entry *e = case_ids[h]; e; e = e->next)
		if (strcmp(e->key, key) == 0)
			return e;

	return NULL;
}

enum MutKind
{
	MUT_SET_INTERESTING = 0,
	MUT_BIT_FLIP = 1,
	MUT_BYTE_XOR = 2
};

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

	struct wpabuf *json_output = NULL;

	int64_t case_id = -10;
	Entry *case_entry = NULL;
	if (NULL == (case_entry = dict_get(target)))
	{
		// wpa_printf(MSG_INFO, "case_entry for: '%s' not found", target);
		dict_set(target, -10);
	}
	else
	{
		case_id = case_entry->value;
		// wpa_printf(MSG_INFO, "case_entry for: '%s' found, value: %ld", target, case_id);
	}

	case_id++;
	dict_set(target, case_id);

	json_output = wpabuf_alloc(1000);
	json_start_object(json_output, NULL);
	json_add_string(json_output, "msg", "progress");
	json_value_sep(json_output);
	json_add_int(json_output, "case_id", case_id);
	json_value_sep(json_output);
	json_add_string(json_output, "target", target);
	json_end_object(json_output);
	wpa_printf(MSG_INFO, "[fuzz] %s", (char *)wpabuf_head(json_output));
	wpabuf_free(json_output);

	if (case_id < 0)
		return;

	// Deterministic index selection
	size_t idx = case_id % (len - non_fuzzed_header_size);

	// Deterministic mutation kind
	enum MutKind kind =
		(enum MutKind)((case_id / (len - non_fuzzed_header_size)) % NUM_MUT_KINDS);

	// Parameter for bit/value selection
	uint64_t param = case_id / ((len - non_fuzzed_header_size) * NUM_MUT_KINDS);

	uint8_t *b = relevant_reply + idx;

	json_output = wpabuf_alloc(1000);
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

	char hexdump[1000] = {0};
	for (int i = 0; i < len; i++) // Use len, as we want the whole buffer (with HDRs)
		sprintf(hexdump + strlen(hexdump), "%02x", ((uint8_t *)reply)[i]);

	json_add_string(json_output, "data", hexdump);

	json_end_object(json_output);
	wpa_printf(MSG_INFO, "[fuzz] %s", (char *)wpabuf_head(json_output));
	wpabuf_free(json_output);
}
