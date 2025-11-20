#include "utils/includes.h"
#include "ieee802_11_defs.h"
#include "fuzz.h"

#include "utils/common.h"

#include "utils/json.h"

#include "wpa_common.h"

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

static int64_t case_id = -10;

void apply_mutation(char *target, int type, uint8_t *reply, size_t len)
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
			sizeof(((struct ieee80211_mgmt *) reply)->frame_control) +
			sizeof(((struct ieee80211_mgmt *) reply)->duration) +
			sizeof(((struct ieee80211_mgmt *) reply)->da) +
			sizeof(((struct ieee80211_mgmt *) reply)->sa);
		relevant_reply = (uint8_t *)reply + non_fuzzed_header_size;
	}
	if (type == 2) // ieee802_1x_hdr
	{
		// No need to "move"
	}

	struct wpabuf *json_output = NULL;
	case_id++;

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
