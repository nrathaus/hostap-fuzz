#include <stdint.h>
#include <stddef.h>
#include <string.h>

enum MutKind {
    MUT_SET_INTERESTING = 0,
    MUT_BIT_FLIP        = 1,
    MUT_BYTE_XOR        = 2
};

static const uint8_t interesting_values[] = {
    0x00, 0x01, 0x7F, 0x80, 0xFF
};
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

    uint8_t *b = &buf[idx];

    switch (kind) {
    case MUT_SET_INTERESTING: {
        uint8_t v = interesting_values[param % NUM_INTERESTING];
        *b = v;
        break;
    }
    case MUT_BIT_FLIP: {
        uint8_t bit = (uint8_t)(param % 8);
        *b ^= (1u << bit);
        break;
    }
    case MUT_BYTE_XOR: {
        uint8_t mask = (uint8_t)(param & 0xFF);
        *b ^= mask;
        break;
    }
    }
}
