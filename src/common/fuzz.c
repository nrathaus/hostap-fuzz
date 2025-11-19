#include "utils/includes.h"
#include "fuzz.h"

#include "utils/common.h"
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

void apply_mutation(uint8_t *buf, size_t len, uint64_t case_id)
{
	if (len == 0)
		return;

	// Deterministic index selection
	size_t idx = case_id % len;

	// Deterministic mutation kind
	enum MutKind kind =
		(enum MutKind)((case_id / len) % NUM_MUT_KINDS);

	// Parameter for bit/value selection
	uint64_t param = case_id / (len * NUM_MUT_KINDS);

	uint8_t *b = buf + idx;

	switch (kind)
	{
	case MUT_SET_INTERESTING:
	{
		uint8_t v = interesting_values[param % NUM_INTERESTING];

		wpa_printf(MSG_INFO, "MUT_SET_INTERESTING idx=%ld b=%02x v=%02x", idx, *b, v);
		*b = v;
		break;
	}
	case MUT_BIT_FLIP:
	{
		uint8_t bit = (uint8_t)(param % 8);
		wpa_printf(MSG_INFO, "MUT_BIT_FLIP idx=%ld b=%02x", idx, *b);

		*b ^= (1u << bit);

		wpa_printf(MSG_INFO, "MUT_BIT_FLIP idx=%ld after b=%02x", idx, *b);
		break;
	}
	case MUT_BYTE_XOR:
	{
		uint8_t mask = (uint8_t)(param & 0xFF);
		wpa_printf(MSG_INFO, "MUT_BYTE_XOR idx=%ld b=%02x", idx, *b);

		*b ^= mask;

		wpa_printf(MSG_INFO, "MUT_BYTE_XOR idx=%ld after b=%02x", idx, *b);
		break;
	}
	}
}
