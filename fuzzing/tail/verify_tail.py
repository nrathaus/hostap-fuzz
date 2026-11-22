#!/usr/bin/env python3
"""W12 -- the span under test, at the end of the frame.

Section 0.2 keeps the oracle out of scope, and the free oracle is a process
that died. There is a class of defect that oracle cannot see at any mutation
power, and it is the class this product's parsers are built to have: every one
of them hands out pointers into the caller's buffer and copies nothing.
`ieee802_11_parse_elems()` alone fills 92 (pointer, length) pairs. A consumer
that reads one octet past the end of its span reads the next element's id --
same allocation, same page, no fault, nothing for a crash oracle to see and
nothing for a sanitizer either.

So the engine has a second case space in which the span under test is the LAST
thing in the frame. An over-read then crosses the frame boundary instead of
crossing into a sibling element.

**What this suite does NOT check, because it is not true.** It does not check
that such a read is detected, or even that it is detectable: whether a read
past the frame faults depends on the victim's allocator and on how its driver
handed the frame up. What is checked is the stimulus: that the span really is
last, that the frame really ends where it ends, and that the two case spaces
are told apart by the opset so a case_id from one never replays as the other.

    python3 fuzzing/tail/verify_tail.py [checkout]

Offline. Needs the checkout built with CONFIG_FUZZ=y, for the objects.
"""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def load_synth(root):
    """The synthesis harness, reused rather than copied.

    It already compiles fuzz.c against the tree's objects and already knows
    how to pair a returned frame with the message that describes it. A second
    copy of that would be a second thing to keep in step, and the first thing
    to go stale would be the frame layout both suites assert about.
    """
    sys.path.insert(0, os.path.join(root, "fuzzing", "synth"))
    import verify_synth as vs
    vs.load_shape_table(root)
    vs.load_minima(root)
    return vs


def groups(vs, body):
    """([(start, end)] of each walked group, where the walk stopped).

    Permissive, and deliberately so. A region that stops walking part way
    through still has real spans in the part that walked, and a frame cut to
    the end of the last one of them is a frame that PARSES, with the span
    under test at its end -- which is strictly better than leaving the whole
    thing to be discarded at the first malformed item. The strict walk is for
    deciding whether a region is a chain; this one is for finding where a
    span ends.

    Groups, not elements, for the reason the engine's insertion points are
    groups: a Fragment element continues the one before it and a consumer
    holding the defragmented buffer has a span that runs to the end of the
    run. Written here rather than imported so that what the engine did is
    checked against something, not against itself.
    """
    basic = {"hdr": 2, "len_off": 1, "len_width": 1, "len_le": False,
             "ext_off": 0, "ext_width": 0, "ext_le": False, "covers": False}
    out, pos, open_group = [], 0, False
    while pos < len(body):
        eid = body[pos]
        sh = vs.SHAPE_BY_ID.get(eid, basic)
        hdr = (sh["len_off"] + sh["len_width"]) if sh["covers"] else sh["hdr"]
        if pos + hdr > len(body):
            break
        dlen = int.from_bytes(
            body[pos + sh["len_off"]:pos + sh["len_off"] + sh["len_width"]],
            "little" if sh["len_le"] else "big")
        if pos + hdr + dlen > len(body):
            break
        cont = eid == FRAGMENT_ID and open_group and out
        if cont:
            out[-1] = (out[-1][0], pos + hdr + dlen)
            open_group = dlen != 0
        else:
            out.append((pos, pos + hdr + dlen))
            open_group = dlen == 255
        pos += hdr + dlen
    return out, pos


FRAGMENT_ID = 242


def main():
    root = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else ".")
    vs = load_synth(root)

    # The Fragment id from the generated header, not from the 242 above.
    global FRAGMENT_ID
    sys.path.insert(0, os.path.join(root, "fuzzing", "ledger"))
    import registries as reg
    for val, names in reg.extract(root)["element id"].items():
        if "WLAN_EID_FRAGMENT" in names:
            FRAGMENT_ID = val

    check = vs.Check()
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        binary = vs.build(root, tmp)
        if not binary:
            return 2
        check_two_case_spaces(vs, check, binary)
        check_span_is_last(vs, check, binary)
        check_octet_sweep_cuts(vs, check, binary)
        check_the_price(vs, check, binary)
        check_opt_in(vs, check, binary)
    print("\n%d of %d checks pass" % (check.passed,
                                      check.passed + check.failed))
    return 1 if check.failed else 0


def tail_run(vs, binary, target, n, **kw):
    env = dict(kw.pop("env", {}))
    env["FUZZ_TAIL"] = "1"
    return vs.run(binary, target, n, env=env, **kw)


def check_two_case_spaces(vs, check, binary):
    print("\nTwo case spaces, and the record says which")
    _, plain = vs.run(binary, "t-w12-a", 40)
    _, tail = tail_run(vs, binary, "t-w12-b", 40)
    ops_p = {m.get("opset") for m in plain if m.get("msg") == "progress"}
    ops_t = {m.get("opset") for m in tail if m.get("msg") == "progress"}
    check.ok(len(ops_p) == 1 and len(ops_t) == 1 and ops_p != ops_t,
             "the opset names the case space (%s vs %s)"
             % (sorted(ops_p), sorted(ops_t)))
    check.ok(all("/tail" in o for o in ops_t),
             "and says which of the two this is (%s)" % sorted(ops_t))
    check.ok(not any("/tail" in o for o in ops_p),
             "while the other does not claim to be it (%s)" % sorted(ops_p))

    # The same case_id really is a different frame, which is the hazard the
    # opset exists for rather than a decoration on it.
    fa, _ = vs.run(binary, "t-w12-same", 400)
    fb, _ = tail_run(vs, binary, "t-w12-same", 400)
    check.ok(fa != fb,
             "and the same case_id under the two of them is not the same "
             "frame")

    e = vs.elems(tail)
    check.ok(e and all(m.get("tail_mode") == 1 for m in e),
             "every element case says it is in the tail case space (%d)"
             % len(e))
    e = vs.elems(plain)
    check.ok(e and all(m.get("tail_mode") == 0 for m in e),
             "and every one in the other says it is not (%d)" % len(e))


def check_span_is_last(vs, check, binary):
    print("\nThe synthesised span is the last thing in the frame")
    frames, msgs = tail_run(vs, binary, "t-w12-last", 5000)
    cases = [(f, m) for f, m in vs.pair(frames, msgs)
             if m is not None and m.get("type") == "MUT_ELEM"]
    check.ok(cases, "element cases ran in the tail case space (%d)"
             % len(cases))

    notlast = [(m.get("dom"), m["at"], m["was"]) for _, m in cases
               if m["at"] != m["was"]]
    check.ok(not notlast,
             "every one of them went in at the end of the frame, whatever "
             "its own position axis said",
             str(notlast[:4]))

    onepos = {m["pos"] for _, m in cases}
    check.ok(onepos == {max(onepos)},
             "so the position axis takes exactly one value here (%s)"
             % sorted(onepos))

    # What the mitigation is actually for: the span a consumer is handed ends
    # at the end of the frame, or past it. Either way an over-read leaves the
    # buffer instead of landing in a sibling element.
    inside = []
    for (ret, data), m in cases:
        if m["len"] == m["was"]:
            continue
        sh = vs.SHAPE_BY_ID.get(m["eid"])
        hdr = ((sh["len_off"] + sh["len_width"]) if sh and sh["covers"]
               else (sh["hdr"] if sh else 2))
        if m.get("depth"):
            # The nesting domain's span under test is the INNER element,
            # which the builder puts at the end of the staged region with
            # its containers wrapped around the front of it. 'at' is where
            # the outermost container starts and would be the wrong answer
            # by exactly the containers' headers.
            start = m["nest_at"]
        else:
            # The LAST copy, which is the one at the end of the frame.
            one = (m["len"] - m["was"]) // max(m.get("copies", 1), 1)
            start = m["at"] + one * (m.get("copies", 1) - 1)
        if start + hdr + m["declared"] < m["len"]:
            inside.append((m.get("dom"), m["eid"], start, hdr,
                           m["declared"], m["len"]))
    check.ok(not inside,
             "and the span it declares ends at the frame's end or past it, "
             "never inside it with a sibling behind it",
             str(inside[:4]))


def check_octet_sweep_cuts(vs, check, binary):
    print("\nThe octet sweep cuts the frame after the element it hit")
    frames, msgs = tail_run(vs, binary, "t-w12-byte", 2500)
    cases = [(f, m) for f, m in vs.pair(frames, msgs)
             if m is not None and m.get("type") == "MUT_BYTE_XOR"]
    check.ok(cases, "octet cases ran (%d)" % len(cases))

    missing = [m for _, m in cases if m.get("cut") is None]
    check.ok(not missing, "every one of them reports what it cut",
             str(missing[:2]))

    cut = [m for _, m in cases if m["cut"]]
    check.ok(cut, "and some of them cut something (%d of %d)"
             % (len(cut), len(cases)))

    # Against this file's own walk, and of the MUTATED frame rather than the
    # frame as built. The span a consumer is handed comes from the length
    # octets it is given, so an octet case that changed one changed the span
    # -- and the cut has to land at the end of the span the victim will
    # actually read, not at the end of the one the builder wrote.
    wrong, checked, moved = [], 0, 0
    for (ret, data), m in cases:
        off = m["hdr"] + m["idx"]
        if off < vs.CHAIN_OFF:
            continue
        mutated = bytearray(vs.FRAME)
        mutated[off] ^= m["mask"]
        gs, stop = groups(vs, bytes(mutated[vs.CHAIN_OFF:]))
        checked += 1
        end = next((vs.CHAIN_OFF + b for a, b in gs
                    if vs.CHAIN_OFF + a <= off < vs.CHAIN_OFF + b), None)
        if end is None or off >= vs.CHAIN_OFF + stop:
            # The octet is past where the walk could get, so there is no
            # span to end the frame at and the engine must leave it alone.
            want = len(vs.FRAME)
        else:
            want = end if end < len(vs.FRAME) else len(vs.FRAME)
        if want != len(vs.FRAME):
            moved += 1
        if m["len"] != want:
            wrong.append((off, hex(m["mask"]), m["len"], want))
    check.ok(checked and not wrong,
             "the cut lands exactly at the end of the group the octet is "
             "in, by this file's own walk of the MUTATED frame (%d case(s))"
             % checked,
             str(wrong[:4]))
    check.ok(moved,
             "and the span it ends at is the one the mutation produced, not "
             "the one the builder wrote (%d case(s) where they differ)"
             % moved)

    fixed = [(m["idx"], m["cut"]) for _, m in cases
             if m["hdr"] + m["idx"] < vs.CHAIN_OFF and m["cut"]]
    check.ok(not fixed,
             "an octet in the fixed part of the frame is not cut after: it "
             "is read at a known offset and a known width, so there is no "
             "span to over-read",
             str(fixed[:4]))

    short = [(m["len"], ret) for (ret, data), m in cases
             if len(data) != m["len"] or ret != m["len"]]
    check.ok(not short,
             "and the frame emitted is exactly the length reported",
             str(short[:4]))

    # What is left is the frame as built, truncated, with the one octet the
    # case is about changed. A cut that also moved something would make the
    # as-built column -- the only record of what the configuration emits --
    # unrecoverable, and nothing else in this engine would notice.
    bad = []
    for (ret, data), m in cases:
        want = bytearray(vs.FRAME[:m["len"]])
        off = m["hdr"] + m["idx"]
        if off < len(want):
            want[off] ^= m["mask"]
        if bytes(data) != bytes(want):
            bad.append((m["idx"], m["cut"]))
    check.ok(not bad,
             "and what is left is a prefix of the frame as built, with one "
             "octet changed and nothing else moved",
             str(bad[:4]))


def check_the_price(vs, check, binary):
    print("\nThe price, stated")
    _, plain = vs.run(binary, "t-w12-price", 5000)
    _, tail = tail_run(vs, binary, "t-w12-price", 5000)
    pos_p = {m["pos"] for m in vs.elems(plain)}
    pos_t = {m["pos"] for m in vs.elems(tail)}
    check.ok(len(pos_p) > 1,
             "the other case space sweeps every insertion point (%s)"
             % sorted(pos_p))
    check.ok(len(pos_t) == 1,
             "and this one sweeps none of them -- position for reach, "
             "last-position for observability, run apart (%s)"
             % sorted(pos_t))

    # The W10 counter must not call the deliberate truncation breakage.
    sys.path.insert(0, os.path.join(os.path.dirname(HERE), "ledger"))
    from ledger import Ledger
    led = Ledger()
    led.feed({"msg": "inventory", "targets": ["t-w12-price"], "stages": []})
    for m in tail:
        led.feed(m)
    out = led.summary()
    check.ok(out is not None, "the ledger accepts a tail run")
    check.ok(led.tail_cases > 0,
             "and counts it as one (%d case(s))" % led.tail_cases)
    check.ok(led.absorbed == 0,
             "with no case called absorbed: pinning the span to the end is "
             "exactly what W10 asks for, not a violation of it (%d)"
             % led.absorbed)


def check_opt_in(vs, check, binary):
    print("\nA caller that cannot send a different length is not cut")
    frames, msgs = tail_run(vs, binary, "t-w12-noroom", 1500,
                            capacity=len(vs.FRAME))
    cases = [m for m in msgs
             if m.get("msg") == "fuzz" and m.get("type") == "MUT_BYTE_XOR"]
    check.ok(cases, "octet cases ran with no headroom (%d)" % len(cases))
    check.ok(all(m.get("cut") == 0 for m in cases),
             "and none of them cut the frame -- the same opt-in the length "
             "domain uses, because apply_mutation() returns void and a site "
             "that calls it sends what it built",
             str([m["cut"] for m in cases[:4]]))
    check.ok(all(len(f) == r for r, f in frames),
             "the frame emitted is still exactly the length returned")


if __name__ == "__main__":
    sys.exit(main())
