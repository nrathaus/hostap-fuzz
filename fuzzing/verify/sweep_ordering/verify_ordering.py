#!/usr/bin/python3
"""
Check the sweep ordering against a real CONFIG_FUZZ build.

sweep_ordering.py models the case_id -> offset mapping; this drives the C and
checks that the build agrees, that breadth-first is the default, that
FUZZ_SWEEP_DEPTH_FIRST=1 restores the old order, and that both orders cover the
identical case space.

    python3 fuzzing/verify/sweep_ordering/verify_ordering.py .

Build the checkout with CONFIG_FUZZ=y first.
"""

import importlib.util
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))

#  Reuse fuzz_verify's driver rather than cloning it: the two must not drift
#  apart in how they build or parse.
_spec = importlib.util.spec_from_file_location(
    "fuzz_verify", os.path.join(HERE, "..", "fuzz_verify", "fuzz_verify.py"))
fv = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(fv)

FRAME_LEN = fv.FRAME_LEN            # 34
FUZZABLE = fv.FUZZABLE              # 10 bytes left after the 802.11 header
PER_OFFSET = fv.CASES_PER_OFFSET    # 255
CASES = fv.CASES                    # 2550
WARMUP = fv.WARMUP


def sweep(harness, budget, **env):
    """Drive `budget` cases from case 0 and return the 'fuzz' messages."""
    messages, _frames, unparsed = fv.run(
        harness, ["auth-sae", FRAME_LEN, budget + WARMUP, "mgmt"],
        FUZZ_START_CASE=0, **env)
    return ([m for m in messages if m["msg"] == "fuzz"],
            [m for m in messages if m["msg"] == "progress"],
            unparsed)


def signature(m):
    """The (offset, kind, param) a case resolves to, however it is numbered."""
    return (m["idx"], m["type"], m.get("v"), m.get("bit"), m.get("mask"))


def main():
    root = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else ".")
    check = fv.Checker()

    with tempfile.TemporaryDirectory() as workdir:
        harness = fv.build(root, workdir, "sweep", fv.HARNESS)
        if not harness:
            return 2

        print("breadth-first is the default")
        muts, prog, unparsed = sweep(harness, CASES)
        check.ok(not unparsed, "every [fuzz] line is JSON with a msg",
                 str(unparsed[:2]))
        check.ok(all(m.get("order") == "breadth" for m in muts),
                 "every 'fuzz' message says order=breadth",
                 str({m.get("order") for m in muts}))
        check.ok(all(p.get("order") == "breadth" for p in prog),
                 "every 'progress' message says order=breadth",
                 str({p.get("order") for p in prog}))

        first = muts[:FUZZABLE]
        check.ok([m["idx"] for m in first] == list(range(FUZZABLE)),
                 f"the first {FUZZABLE} cases touch all {FUZZABLE} offsets, "
                 "in order", str([m["idx"] for m in first]))
        #  The interesting values no longer have a mutation kind of their own
        #  -- they are the masks the per-offset order starts with -- so this
        #  reads the value the byte was left with rather than the kind.
        check.ok(all(m["after"] == 0x00 for m in first),
                 "and all leave the byte at the first interesting value, 0x00",
                 str({m["after"] for m in first}))

        #  The README's headline: a budget far short of the space still spreads
        #  across the frame instead of climbing through offset 0.
        budget = 105
        reached = {m["idx"] for m in muts[:budget]}
        check.ok(reached == set(range(FUZZABLE)),
                 f"a budget of {budget} reaches every offset "
                 f"(depth-first reaches 1)", str(sorted(reached)))

        print("\nFUZZ_SWEEP_DEPTH_FIRST=1 restores the old order")
        dmuts, dprog, dunparsed = sweep(harness, CASES,
                                        FUZZ_SWEEP_DEPTH_FIRST=1)
        check.ok(not dunparsed, "every [fuzz] line is JSON with a msg",
                 str(dunparsed[:2]))
        check.ok(all(m.get("order") == "depth" for m in dmuts),
                 "every 'fuzz' message says order=depth",
                 str({m.get("order") for m in dmuts}))
        check.ok(all(p.get("order") == "depth" for p in dprog),
                 "every 'progress' message says order=depth",
                 str({p.get("order") for p in dprog}))
        check.ok({m["idx"] for m in dmuts[:PER_OFFSET]} == {0},
                 f"the first {PER_OFFSET} cases all sit at offset 0",
                 str(sorted({m["idx"] for m in dmuts[:PER_OFFSET]})))
        check.ok({m["idx"] for m in dmuts[:budget]} == {0},
                 f"and a budget of {budget} still reaches only offset 0")
        check.ok(fv.run(harness, ["auth-sae", FRAME_LEN, WARMUP + 1, "mgmt"],
                        FUZZ_START_CASE=0, FUZZ_SWEEP_DEPTH_FIRST=0)[0][-1]
                 .get("order") == "breadth",
                 "FUZZ_SWEEP_DEPTH_FIRST=0 is not depth-first")

        print("\nthe two orders cover the same cases")
        check.ok(len(muts) == CASES and len(dmuts) == CASES,
                 f"both sweep exactly {CASES} cases",
                 f"{len(muts)} and {len(dmuts)}")
        bset = {signature(m) for m in muts}
        dset = {signature(m) for m in dmuts}
        check.ok(len(bset) == CASES, "breadth-first has no duplicate case",
                 f"{len(bset)} distinct")
        check.ok(len(dset) == CASES, "depth-first has no duplicate case",
                 f"{len(dset)} distinct")
        check.ok(bset == dset, "and the two cover the identical case space",
                 f"{len(bset ^ dset)} cases differ")
        check.ok([signature(m) for m in muts] !=
                 [signature(m) for m in dmuts],
                 "in a different sequence -- which is why 'order' is reported")

        print("\nthe replay hazard the 'order' field exists for")
        case = 300
        b_one = sweep(harness, 1, FUZZ_START_AUTH_SAE=case)[0]
        d_one = sweep(harness, 1, FUZZ_START_AUTH_SAE=case,
                      FUZZ_SWEEP_DEPTH_FIRST=1)[0]
        check.ok(b_one and d_one and
                 signature(b_one[0]) != signature(d_one[0]),
                 f"case {case} is a different mutation under each order",
                 f"{signature(b_one[0] if b_one else {})} vs "
                 f"{signature(d_one[0] if d_one else {})}")
        again = sweep(harness, 1, FUZZ_START_AUTH_SAE=case)[0]
        check.ok(again and signature(again[0]) == signature(b_one[0]),
                 "but replays identically within one order")

    print()
    if check.failures:
        print(f"{len(check.failures)} of "
              f"{check.passes + len(check.failures)} checks FAIL")
        for f in check.failures:
            print(f"  - {f}")
        return 1
    print(f"{check.passes} of {check.passes} checks pass")
    return 0


if __name__ == "__main__":
    sys.exit(main())
