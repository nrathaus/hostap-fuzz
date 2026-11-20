# Sweep breadth-first, so a run that cannot finish still reaches the elements

> **Both findings below have landed.** This file is the record of the
> investigation, so it is written against the tree as it was: a depth-first
> sweep of 268 cases per byte offset. `57b4332e7` made the sweep breadth-first,
> and the duplicate cases are gone -- see "Done" under the second finding.
> `FUZZING.md` is the current description.

`apply_mutation_int()` orders its sweep depth-first by byte offset: every one
of the 268 mutations at offset 0 runs before offset 1 is touched. That is the
right order for localising a crash to one field, and the wrong one for a run
bounded by anything other than the full space - which, against a real station,
every run is.

The result is that a bounded run fuzzes the fixed fields of a frame and never
reaches an information element, while reporting the whole space as its size.

## The gap, measured

`sweep_ordering.py` beside this file models the `case_id -> (offset, kind,
param)` mapping and needs nothing but `python3`, so the claim can be checked
before any code changes.

A probe response sweeps 22,244 cases over the 83 body bytes left once
`IEEE80211_HDRLEN` is excluded. Its body begins with timestamp (8), beacon
interval (2) and capability (2), so the first information element starts at
**offset 12, which is case 3,216**.

| budget | offsets reached, depth-first | offsets reached, breadth-first |
| ---: | --- | --- |
| 105 | **1** (max 0) | 83 (max 82) |
| 1,000 | **4** (max 3) | 83 (max 82) |
| 3,216 | **12** (max 11) | 83 (max 82) |
| 10,000 | 38 (max 37) | 83 (max 82) |
| 22,244 | 83 | 83 |

**A driving harness observed one target reach case 105 in about ten minutes**,
which is 0.175 cases/second - the rate is set by how fast the station
re-joins, not by how fast frames can be built. At that rate:

- **5.1 hours** to clear the fixed fields and reach the first element
- **35.3 hours** to finish one frame

So a run of any realistic length mutates a timestamp. Everything the SAE and
RSN parsing actually reads is behind an element that the sweep will not get to.

## Confirmed on hardware, 2026-11-18

The model above was written before the live run that tested it. The run was ten
minutes per phase against a MikroTik hAP ax² (the live-run results).
Predicted offset reached is `floor((cases - 1) / 268)`:

| target, phase | cases | offsets predicted | offsets measured |
| --- | ---: | ---: | ---: |
| `eapol`, held | 596 | 0-2 | **0-2** |
| `probe_resp`, control | 300 | 0-1 | **0-1** |
| `sae-send-commit`, control | 266 | 0 | **0** |
| `eapol`, control | 13 | 0 | **0** |

Exact in every case, so the mapping is modelled correctly and the script is a
sound oracle for the change.

The ax² is **5.7x faster** than the station the 0.175 cases/s figure came
from: `eapol` ran at **0.99 cases/s**. Even so, the best phase of the best run
reached **3 of the 121 bytes** of an EAPOL-Key frame. A faster station does not
fix this; it is the ordering.

What those 596 cases were spent on:

| offset | cases | field | what mutating it can tell you |
| ---: | ---: | --- | --- |
| 0 | 268 | EAPOL version | nothing: stations ignore it or drop the frame |
| 1 | 268 | EAPOL type (`0x03`) | nothing: any other value is not an EAPOL-Key |
| 2 | 60 | body length, high byte | truncation handling, the first real test |

**328 of 596 cases could only ever produce "frame rejected".** Meanwhile the key
data, the nonce, the RSN IE inside it - everything an implementation actually
parses - sits at offsets 11 and beyond and was never touched.

Breadth-first, the same 596 cases are **4.9 complete passes over all 121 bytes**.

This also explains an anomaly in that run: 174 associations produced only 92
completed handshakes. That is not a tolerance finding about the station. It is
offset 1 - 268 consecutive cases telling a supplicant that an EAPOL-Key frame
is some other EAPOL type. The sweep spent a quarter of the phase establishing
that a station rejects a frame it is required to reject.

## The ask

**Make the ordering selectable, and default it to breadth-first.** The change
is the two lines the code's own comment already names:

```c
/* today */
idx = case_id / CASES_PER_OFFSET;
rem = case_id % CASES_PER_OFFSET;

/* proposed default */
idx = case_id % fuzz_len;
rem = case_id / fuzz_len;
```

Keep the depth-first order reachable - it is what you want once a crash has
been seen and the question is which field caused it. An environment variable
in the style of the existing ones, say `FUZZ_SWEEP_DEPTH_FIRST=1`, keeps both
without a rebuild.

**Say which order a run used, in the `[fuzz]` output.** The orders renumber
every case, so a `case_id` recorded under one does not replay under the other.
A consumer that cannot tell them apart will replay the wrong frame and report
it as a non-reproducible crash. One field on the existing JSON is enough.

## Acceptance

```
python3 -I sweep_ordering.py
```

Against the current ordering the table above is what it prints. The change is
accepted when, with the new default, **every budget of at least `fuzz_len`
cases reaches every offset**, and the first element is reachable at a budget of
83 rather than 3,216. The script is the oracle for both orders, since it models
the mapping rather than the build.

On a live target, the same claim shows as a sweep whose reported offsets are
spread across the frame within the first minute, instead of climbing through
offset 0 for hours.

## A smaller thing found alongside

**13 of every 268 cases repeat a value already sent at that offset**, and it is
exactly 13 for every possible original byte - the script checks all 256.

`MUT_BYTE_XOR` already covers masks 1 to 255, which is every value a byte can
take other than the one it has. `MUT_BIT_FLIP` is `*b ^= 1U << bit` for bits 0
to 7, so all 8 of its cases are XOR masks already in that range. The five
`MUT_SET_INTERESTING` values are each either equal to the original - a case
that changes nothing - or one of the 255 the XOR sweep produces.

Dropping both kinds takes `CASES_PER_OFFSET` from 268 to 255 with no loss of
coverage, a 4.9% saving on every declared space. It is worth doing in the same
change as the ordering, since both renumber cases and doing them separately
means two renumberings.

**The interesting values are still worth reaching first**, which the ordering
change makes easy: with a breadth-first sweep the `rem` that selects the kind
advances slowest, so ordering the XOR masks to put `0x00`, `0x01`, `0x7F`,
`0x80` and `0xFF` at the front of the range gives the old first-five behaviour
for free.

### Done

`CASES_PER_OFFSET` is 255 and `MUT_SET_INTERESTING` and `MUT_BIT_FLIP` are
gone. `fuzz_xor_mask()` in `src/common/fuzz.c` is the order: the masks that set
the byte to one of the interesting values, then the single-bit flips, then
everything else ascending, skipping any mask an earlier rule already emitted.
The union is always 1..255, so the schedule is a permutation of the masks and
the offset's sweep is still exhaustive -- what varies with the original byte is
only how many masks each rule contributes.

One case that used to be a no-op is now useful: where the byte already holds an
interesting value, `orig ^ v` is 0, there is no "set it to that" case, and the
freed slot goes to a bit flip instead.

`sweep_ordering.py` models both schemes and reports the redundancy of each --
`268 cases produce 255 distinct values, so 13 repeat`, against `255 cases
produce 255 distinct values, so 0 repeat`, over all 256 original bytes.
`verify_ordering.py` and `fuzz_verify.py` check the built C: 255 per offset,
masks 1..255 exactly once each, 255 distinct resulting values with none
unchanged, the interesting values leading every offset, and all 8 single-bit
flips within its first 13 cases.

**This renumbered every case again**, on top of the ordering change, and the
`order` field does not distinguish a case-count change. A `case_id` recorded
before this does not replay after it, in either order.
