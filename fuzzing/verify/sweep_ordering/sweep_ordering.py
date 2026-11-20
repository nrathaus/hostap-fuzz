#!/usr/bin/python3
"""
What a bounded fuzzing run reaches under each sweep ordering.

Needs nothing but python3: it models the case_id -> (offset, mask) mapping in
apply_mutation_int() rather than driving a build, so a claim about the sweep
can be checked without one.

    python3 -I sweep_ordering.py

Both the superseded 268-case offset and the 255-case one that replaced it are
modelled here, because the argument for the change is a comparison between
them: the old one spent 13 of every 268 cases re-sending a value it had already
sent at that offset, and this script is what checked that over all 256 possible
original bytes.
"""

INTERESTING = (0x00, 0x01, 0x7F, 0x80, 0xFF)

#  The superseded scheme: 5 "set the byte to an interesting value" cases, then
#  8 single-bit flips, then XOR masks 1..255.
OLD_CASES_SET_INTERESTING = len(INTERESTING)
OLD_CASES_BIT_FLIP = 8
OLD_CASES_BYTE_XOR = 255
OLD_CASES_PER_OFFSET = (OLD_CASES_SET_INTERESTING + OLD_CASES_BIT_FLIP +
                        OLD_CASES_BYTE_XOR)

#  The current one: the XOR masks alone, which already are every value a byte
#  can be changed to. See fuzz_xor_mask() for the order.
CASES_PER_OFFSET = 255


def old_split_kind(rem):
    """(kind, param) from the remainder, as the superseded C did."""
    if rem < OLD_CASES_SET_INTERESTING:
        return "set_interesting", rem
    if rem < OLD_CASES_SET_INTERESTING + OLD_CASES_BIT_FLIP:
        return "bit_flip", rem - OLD_CASES_SET_INTERESTING
    return "byte_xor", rem - OLD_CASES_SET_INTERESTING - OLD_CASES_BIT_FLIP


def old_value_at(original, rem):
    """The byte the superseded scheme left behind, or None for a no-op."""
    kind, param = old_split_kind(rem)
    if kind == "set_interesting":
        value = INTERESTING[param]
    elif kind == "bit_flip":
        value = original ^ (1 << param)
    else:
        value = original ^ (param + 1)
    return None if value == original else value


def mask_schedule(original):
    """The 255 masks in the order fuzz_xor_mask() applies them."""
    schedule, emitted = [], {0}
    for rule in (
            [original ^ v for v in INTERESTING],
            [1 << b for b in range(8)],
            list(range(1, 256)),
    ):
        for mask in rule:
            if mask in emitted:
                continue
            emitted.add(mask)
            schedule.append(mask)
    return schedule


def depth_first(case_id, fuzz_len, per_offset=CASES_PER_OFFSET):
    """Every mutation of one offset before the next offset is touched."""
    return case_id // per_offset, case_id % per_offset


def breadth_first(case_id, fuzz_len, per_offset=CASES_PER_OFFSET):
    """Default: one mutation across every offset before the next mutation."""
    return case_id % fuzz_len, case_id // fuzz_len


def offsets_reached(order, budget, fuzz_len, per_offset=CASES_PER_OFFSET):
    return {order(c, fuzz_len, per_offset)[0] for c in range(budget)}


def distinct_values_at_one_offset(original, old):
    """How many DISTINCT byte values one offset's cases produce."""
    if old:
        return len({old_value_at(original, rem)
                    for rem in range(OLD_CASES_PER_OFFSET)} - {None})
    return len({original ^ mask for mask in mask_schedule(original)})


def main():
    #  A probe response as the fork sweeps it: the body left after the 24-byte
    #  802.11 header is excluded, measured on a live run.
    fuzz_len = 83
    print(f"frame body {fuzz_len} bytes, {CASES_PER_OFFSET} cases per offset, "
          f"{fuzz_len * CASES_PER_OFFSET:,} declared "
          f"(was {fuzz_len * OLD_CASES_PER_OFFSET:,} at "
          f"{OLD_CASES_PER_OFFSET} per offset)")

    #  Where the information elements start: timestamp 8, beacon interval 2,
    #  capability 2. Everything before that is fixed fields.
    first_element = 12

    print("\nbudget      depth-first offsets      breadth-first offsets   "
          "reaches an element?")
    for budget in (105, 1000, 3216, 10000, 21165):
        d = offsets_reached(depth_first, budget, fuzz_len)
        b = offsets_reached(breadth_first, budget, fuzz_len)
        reach = ("depth " + ("yes" if max(d) >= first_element else "NO")
                 + ", breadth " + ("yes" if max(b) >= first_element else "NO"))
        print(f"{budget:>7,}   {len(d):>6} (max {max(d):>3})"
              f"        {len(b):>6} (max {max(b):>3})        {reach}")

    rate = 105 / 600.0
    print(f"\nat the one measured rate, {rate:.3f} cases/s:")
    for label, cases in (("clear the fixed fields",
                          first_element * CASES_PER_OFFSET),
                         ("whole frame", fuzz_len * CASES_PER_OFFSET)):
        print(f"  {label:<24} {cases:>7,} cases ="
              f" {cases / rate / 3600:6.1f} hours")

    print("\nredundancy at one offset, over all 256 possible original bytes:")
    for label, per_offset, old in (("superseded", OLD_CASES_PER_OFFSET, True),
                                   ("current   ", CASES_PER_OFFSET, False)):
        worst = min(distinct_values_at_one_offset(o, old) for o in range(256))
        best = max(distinct_values_at_one_offset(o, old) for o in range(256))
        print(f"  {label}  {per_offset} cases produce {worst} to {best} "
              f"distinct values, so {per_offset - best} to "
              f"{per_offset - worst} of them repeat one already sent")

    #  The order is the whole reason the interesting values and the bit flips
    #  could be dropped without losing what they were there for. Breadth-first
    #  these are passes over the whole frame, and a live run gets a handful.
    print("\nthe head of the order, over all 256 original bytes:")

    def leads(original):
        head = [original ^ m for m in mask_schedule(original)[:len(INTERESTING)]]
        return set(INTERESTING) - {original} <= set(head)

    print("  every interesting value the byte does not already hold is within"
          f" the first {len(INTERESTING)} cases: "
          f"{all(leads(o) for o in range(256))}")
    #  The byte already holding one of them is the case that does not exist:
    #  the old scheme logged it as a mutation that changed nothing, and here
    #  the freed slot goes to the next rule instead.
    spare = [o for o in range(256) if o in INTERESTING]
    print(f"  the {len(spare)} bytes that already hold one spend the spare "
          "case on a bit flip rather than on a no-op: "
          f"{all(mask_schedule(o)[len(INTERESTING) - 1] in {1 << b for b in range(8)} for o in spare)}")
    bit_flips = {1 << b for b in range(8)}
    print("  all 8 single-bit flips are within the first 13 cases: "
          f"{all(bit_flips <= set(mask_schedule(o)[:13]) for o in range(256))}")
    print("  every offset's 255 masks are exactly 1..255: "
          f"{all(sorted(mask_schedule(o)) == list(range(1, 256)) for o in range(256))}")


if __name__ == "__main__":
    main()
