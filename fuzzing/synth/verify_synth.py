#!/usr/bin/env python3
"""Behavioural checks for element synthesis.

    python3 verify_synth.py /path/to/checkout

Needs no radio, no interface and no root: it compiles a small harness against
the checkout's own fuzz.o and drives the hook directly. Build the checkout with
CONFIG_FUZZ=y first.

The claim being established is the one the whole effort turns on. Rewriting an
element's id octet in place -- which the octet sweep already does, for all 255
values -- selects a different parse helper but leaves the length and the body
belonging to the element that was there, so most helpers reject within a line
or two. Reaching a helper's BODY means constructing an element. So what is
checked here is that every id in the registries is actually built and inserted,
that the chain's shape really changes, and that the ids arrive early rather
than at the end of a sweep no run will finish.

The last of those is the one worth being careful about: a domain that is
complete but unreachable is the same as a domain that is missing.
"""

import json
import os
import subprocess
import sys
import tempfile

PREFIX = "[fuzz] "

OBJECTS = [
    "src/common/fuzz.o",
    "src/utils/json.o",
    "src/utils/wpabuf.o",
    "src/utils/common.o",
    "src/utils/os_unix.o",
    "src/utils/base64.o",
    "src/utils/wpa_debug.o",
]

WARMUP = 9

HARNESS = """
#include "utils/includes.h"
#include "utils/common.h"
#include "common/fuzz.h"

int main(int argc, char *argv[])
{
\tconst char *target = argv[1];
\tsize_t len, capacity, chain_off;
\tint iterations, i;
\tu8 *frame, *base;
\tchar *hex;

\tif (argc < 6)
\t\treturn 2;

\tlen = os_strlen(argv[2]) / 2;
\tcapacity = (size_t) atoi(argv[3]);
\tchain_off = (size_t) atoi(argv[4]);
\titerations = atoi(argv[5]);

\tif (capacity < len)
\t\tcapacity = len;

\tframe = os_malloc(capacity ? capacity : 1);
\tbase = os_malloc(len ? len : 1);
\thex = os_malloc(2 * capacity + 1);
\tif (!frame || !base || !hex)
\t\treturn 3;
\tif (hexstr2bin(argv[2], base, len) < 0)
\t\treturn 2;

\tfor (i = 0; i < iterations; i++) {
\t\tsize_t out;

\t\tos_memset(frame, 0, capacity);
\t\tos_memcpy(frame, base, len);
\t\tout = apply_mutation_elements(target, FUZZ_TYPE_IEEE80211_MGMT,
\t\t\t\t\t      frame, len, capacity, chain_off);
\t\twpa_snprintf_hex(hex, 2 * out + 1, frame, out);
\t\tprintf("ret %zu %s\\n", out, hex);
\t}

\treturn 0;
}
"""

# A management frame: 24-byte header, a 6-octet fixed part (as an
# Authentication frame has), then a chain of three elements. Built here rather
# than captured so the checks can state exactly what should happen to it.
HDR = bytes([0xB0]) + bytes(23)
FIXED = bytes(6)
CHAIN = bytes([0, 2, 0x41, 0x41]) + bytes([1, 1, 0x42]) + bytes([3, 0])
FRAME = HDR + FIXED + CHAIN
CHAIN_OFF = len(HDR) + len(FIXED)
NELEM = 3
HEADROOM = 2 + 255
CAPACITY = len(FRAME) + HEADROOM


class Check:
    def __init__(self):
        self.passed = self.failed = 0

    def ok(self, cond, what, detail=""):
        if cond:
            self.passed += 1
            print("  ok    %s" % what)
        else:
            self.failed += 1
            print("  FAIL  %s" % what)
            if detail:
                print("        %s" % detail)


def build(root, workdir):
    objdir = os.path.join(root, "build", "hostapd")
    missing = [o for o in OBJECTS
               if not os.path.exists(os.path.join(objdir, o))]
    if missing:
        print("cannot find %s under %s" % (missing[0], objdir))
        print("Build the checkout with CONFIG_FUZZ=y first:")
        print("    cd hostapd && make")
        return None

    path = os.path.join(workdir, "synth.c")
    binary = os.path.join(workdir, "synth")
    with open(path, "w", encoding="utf-8") as f:
        f.write(HARNESS)

    command = [
        os.environ.get("CC", "cc"), "-o", binary, path,
        "-I%s" % os.path.join(root, "src"),
        "-I%s" % os.path.join(root, "src", "utils"),
        "-DCONFIG_FUZZ",
    ] + [os.path.join(objdir, o) for o in OBJECTS]

    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode != 0:
        print("the harness did not compile:")
        print(result.stderr.strip()[:2000])
        return None
    return binary


def run(binary, target, iterations, frame=FRAME, capacity=CAPACITY,
        chain_off=CHAIN_OFF, env=None):
    e = dict(os.environ)
    for k in list(e):
        if k.startswith("FUZZ_"):
            del e[k]
    e.update(env or {})
    out = subprocess.run(
        [binary, target, frame.hex(), str(capacity), str(chain_off),
         str(iterations + WARMUP)],
        capture_output=True, text=True, env=e).stdout

    frames, messages = [], []
    for line in out.splitlines():
        if line.startswith(PREFIX):
            try:
                messages.append(json.loads(line[len(PREFIX):]))
            except ValueError:
                messages.append({"msg": "unparsable"})
        elif line.startswith("ret "):
            _, n, hexdata = (line.split(" ") + [""])[:3]
            frames.append((int(n), bytes.fromhex(hexdata)))
    return frames[WARMUP:], messages


fuzz_ids = (None, None)


def registries(root):
    sys.path.insert(0, os.path.join(root, "fuzzing", "ledger"))
    import registries as reg
    global fuzz_ids
    data = reg.extract(root)
    fuzz_ids = (sorted(data["element id"]),
                sorted(data["element id extension"]))
    return fuzz_ids


def elems(messages):
    return [m for m in messages
            if m.get("msg") == "fuzz" and m.get("type") == "MUT_ELEM"]


def walk(body):
    """[(id, length, ext_id or None)], or None if it is not a clean chain."""
    out, pos = [], 0
    while pos + 2 <= len(body):
        eid, elen = body[pos], body[pos + 1]
        if pos + 2 + elen > len(body):
            return None
        ext = body[pos + 2] if eid == 255 and elen >= 1 else None
        out.append((eid, elen, ext))
        pos += 2 + elen
    return out if pos == len(body) else None


def check_registry_fresh(root, check):
    print("\nThe tables are the header's")
    rc = subprocess.run(
        [sys.executable, os.path.join(root, "fuzzing", "ledger", "registries.py"),
         root, "--check"], capture_output=True, text=True)
    check.ok(rc.returncode == 0,
             "the generated registry header matches ieee802_11_defs.h",
             rc.stdout.strip()[:300])
    ids, ext = registries(root)
    check.ok(len(ids) == 179 and len(ext) == 62,
             "179 element ids and 62 extension ids (%d, %d)"
             % (len(ids), len(ext)))


def check_every_id(root, check, binary):
    print("\nEvery id is built, and built early")
    ids, ext = registries(root)
    total = len(ids) + len(ext)

    # Identity varies fastest, so one case per id in the element domain is
    # enough -- but the round robin shares the run with the other domains, so
    # the run has to be long enough for the element domain to get that many
    # turns. Five domains, so roughly five times.
    _, msgs = run(binary, "t-ids", total * 6)
    seen_eid = {m["eid"] for m in elems(msgs) if "eid" in m}
    seen_ext = {m["ext_id"] for m in elems(msgs) if "ext_id" in m}

    check.ok(seen_eid == set(ids),
             "every one of the %d element ids is synthesised (%d)"
             % (len(ids), len(seen_eid)),
             "missing: %s" % sorted(set(ids) - seen_eid)[:10])
    check.ok(seen_ext == set(ext),
             "every one of the %d extension ids is synthesised (%d)"
             % (len(ext), len(seen_ext)),
             "missing: %s" % sorted(set(ext) - seen_ext)[:10])
    check.ok(len(elems(msgs)) >= total,
             "within %d cases, which is what a short run gets" % (total * 6))


def check_in_the_frame(check, binary):
    print("\nThe element is in the frame, not just in the log")
    frames, msgs = run(binary, "t-frame", 400)
    bad, checked = [], 0
    for (ret, data), m in pair(frames, msgs):
        if m is None or m.get("type") != "MUT_ELEM":
            continue
        checked += 1
        at, was, now = m["at"], m["was"], m["len"]
        if now == was:
            continue                        # did not fit; reported as such
        inserted = data[at:at + (now - was)]
        want = m.get("eid", 255)
        if not inserted or inserted[0] != want:
            bad.append((m.get("eid"), m.get("ext_id"), inserted[:4].hex()))
    check.ok(checked, "element cases ran (%d)" % checked)
    check.ok(not bad,
             "each one's octets are at the offset the message gives, "
             "beginning with the id it names", str(bad[:4]))


def pair(frames, messages):
    """[((length, frame), fuzz message or None)] for each case after warm-up.

    Every case emits exactly one 'progress' and at most one 'fuzz'; a warm-up
    case emits only the first. Pairing on the progress boundaries, and then
    dropping the warm-up from the message side as run() already dropped it from
    the frame side, is the only way these two line up -- and getting it wrong
    makes correct synthesis look like octets landing at the wrong offset.
    """
    cases, cur, started = [], None, False
    for m in messages:
        if m.get("msg") == "progress":
            if started:
                cases.append(cur)
            cur, started = None, True
        elif m.get("msg") == "fuzz":
            cur = m
    if started:
        cases.append(cur)
    return list(zip(frames, cases[WARMUP:]))


def check_structure(check, binary):
    print("\nWhat was built is a well-formed element")
    _, msgs = run(binary, "t-struct", 600)
    bad = []
    for m in elems(msgs):
        if m["len"] == m["was"]:
            continue
        if "ext_id" in m:
            # id 255, length = body + 1, then the extension id
            want_len = m["body"] + 1
        else:
            want_len = m["body"]
        if want_len > 255:
            bad.append(("length out of range", m.get("body")))
    check.ok(not bad, "no element claims a length a length octet cannot hold",
             str(bad[:4]))

    frames, msgs = run(binary, "t-struct2", 600)
    chains = 0
    broken = []
    for (ret, data), m in pair(frames, msgs):
        if m is None or m.get("type") != "MUT_ELEM" or m["len"] == m["was"]:
            continue
        walked = walk(data[CHAIN_OFF:])
        if walked is None:
            broken.append((m.get("eid"), m.get("ext_id"), m.get("body")))
        else:
            chains += 1
    check.ok(chains, "the frame still walks as a chain afterwards (%d)"
             % chains)
    check.ok(not broken,
             "every synthesised element leaves a chain that walks exactly",
             str(broken[:4]))


def check_position(check, binary):
    print("\nPosition is a domain")
    _, msgs = run(binary, "t-pos", 4000)
    e = elems(msgs)
    positions = {m["pos"] for m in e}
    check.ok(e and e[0]["npos"] == NELEM + 1,
             "a chain of %d elements has %d insertion points (%s)"
             % (NELEM, NELEM + 1, e[0]["npos"] if e else "none"))
    check.ok(positions == set(range(NELEM + 1)),
             "and every one of them is used (%s)" % sorted(positions))

    offsets = {m["pos"]: m["at"] for m in e}
    check.ok(len(set(offsets.values())) == len(offsets),
             "each insertion point is a distinct byte offset (%s)"
             % sorted(offsets.items()))
    check.ok(all(offsets[p] >= CHAIN_OFF for p in offsets),
             "and none of them is inside the fixed part of the frame")


def check_length_and_multiplicity(check, binary):
    print("\nLength and multiplicity are domains")
    # Identity varies fastest, then position, then length -- so a run that is
    # cut short has every id before it has any id twice, which is the ordering
    # the whole domain is built around. The price is that proving the length
    # domain WHOLE needs a run long enough to reach its slowest axis, so it is
    # proved on a frame whose headroom is small enough for that to be quick
    # rather than on one where it would take a quarter of a million cases.
    small = HDR + FIXED + bytes([0xAA, 0xBB, 0xCC])
    room = 10
    ids, ext = len(fuzz_ids[0]), len(fuzz_ids[1])
    want = room - 3 + 1
    _, msgs = run(binary, "t-len", (ids + ext) * want * 6,
                  frame=small, capacity=len(small) + room)
    e = elems(msgs)
    bodies = {m["body"] for m in e if m["copies"] == 1}
    check.ok(bodies == set(range(want)),
             "with %d octets of headroom the body length is swept over its "
             "whole domain, 0..%d (%d distinct)"
             % (room, want - 1, len(bodies)),
             "missing: %s" % sorted(set(range(want)) - bodies)[:8])
    check.ok(0 in bodies, "including an empty body")

    _, msgs = run(binary, "t-len2", 20000)
    e = elems(msgs)
    copies = {m["copies"] for m in e}
    check.ok(copies >= {1, 2, 3, 4, 5},
             "the same element is inserted 1..5 times (%s)" % sorted(copies))

    frames, msgs = run(binary, "t-mult", 20000)
    worst = []
    for (ret, data), m in pair(frames, msgs):
        if m is None or m.get("type") != "MUT_ELEM" or m["copies"] < 2:
            continue
        if m["len"] == m["was"]:
            continue
        span = data[m["at"]:m["at"] + (m["len"] - m["was"])]
        unit = len(span) // m["copies"]
        if any(span[i * unit:(i + 1) * unit] != span[:unit]
               for i in range(m["copies"])):
            worst.append(m["copies"])
    check.ok(not worst,
             "and the copies are identical, so multiplicity is the only "
             "thing that varied", str(worst[:4]))


def check_chain_ops(check, binary):
    print("\nThe chain's shape")
    _, msgs = run(binary, "t-chain", 4000)
    ops = [m for m in msgs
           if m.get("msg") == "fuzz" and m.get("type") == "MUT_CHAIN"]
    kinds = {m["op"] for m in ops}
    check.ok(kinds == {"delete", "duplicate", "swap"},
             "delete, duplicate and swap all run (%s)" % sorted(kinds))

    deleted = {m["i"] for m in ops if m["op"] == "delete"}
    check.ok(deleted == set(range(NELEM)),
             "every element is deleted in turn (%s)" % sorted(deleted))
    duped = {m["i"] for m in ops if m["op"] == "duplicate"}
    check.ok(duped == set(range(NELEM)),
             "every element is duplicated in turn (%s)" % sorted(duped))
    pairs = {(m["i"], m["j"]) for m in ops if m["op"] == "swap"}
    want = {(i, j) for i in range(NELEM) for j in range(i + 1, NELEM)}
    check.ok(pairs == want,
             "every pair is swapped (%s)" % sorted(pairs))

    frames, msgs = run(binary, "t-chain2", 4000)
    broken = []
    for (ret, data), m in pair(frames, msgs):
        if m is None or m.get("type") != "MUT_CHAIN":
            continue
        if walk(data[CHAIN_OFF:]) is None:
            broken.append((m["op"], m["i"], m["j"]))
    check.ok(not broken,
             "and each leaves a chain that still walks exactly",
             str(broken[:4]))


def check_no_chain(check, binary):
    print("\nA region that is not a chain")
    # A fixed part followed by octets that do not walk: the engine must not
    # invent positions in a chain that is not there.
    frame = HDR + FIXED + bytes([0xAA, 0xBB, 0xCC])
    _, msgs = run(binary, "t-nochain", 600, frame=frame,
                  capacity=len(frame) + HEADROOM)
    e = elems(msgs)
    check.ok(e, "elements are still synthesised (%d)" % len(e))
    check.ok(all(m["npos"] == 1 for m in e),
             "but there is exactly one insertion point, not a position "
             "invented by misreading the octets",
             str({m["npos"] for m in e}))
    check.ok(all(m["at"] == m["was"] for m in e),
             "and it is the end of the frame")
    ops = [m for m in msgs
           if m.get("msg") == "fuzz" and m.get("type") == "MUT_CHAIN"]
    check.ok(not ops,
             "no chain operator runs on a chain that does not exist (%d)"
             % len(ops))


def check_bounds(check, binary):
    print("\nThe contract with the caller")
    frames, _ = run(binary, "t-bound", 30000)
    over = [r for r, _ in frames if r > CAPACITY]
    check.ok(not over, "no case returns a length beyond capacity", str(over[:4]))
    check.ok(all(len(f) == r for r, f in frames),
             "the frame emitted is exactly the length returned")


def check_unchanged(check, binary):
    print("\nThe other entry points are unaffected")
    # chain_off past the end means no element domains at all.
    _, msgs = run(binary, "t-off", 300, chain_off=10 ** 6)
    e = elems(msgs)
    ops = [m for m in msgs
           if m.get("msg") == "fuzz" and m.get("type") == "MUT_CHAIN"]
    check.ok(not e and not ops,
             "a caller that does not say where the chain is gets no element "
             "cases (%d, %d)" % (len(e), len(ops)))
    kinds = {m.get("type") for m in msgs if m.get("msg") == "fuzz"}
    # The claim is about the ELEMENT domains, not about how many domains
    # exist: the field domains are keyed off the frame's own layout and are
    # unrelated to where the chain is.
    check.ok(not (kinds & {"MUT_ELEM", "MUT_CHAIN"}),
             "none of the element domains run (%s)" % sorted(kinds))


def check_ledger(root, check, binary):
    print("\nEnd to end: what the ledger makes of it")
    sys.path.insert(0, os.path.join(root, "fuzzing", "ledger"))
    from ledger import Ledger
    ids, ext = registries(root)
    _, msgs = run(binary, "auth-sae", (len(ids) + len(ext)) * 6)
    led = Ledger()
    led.feed({"msg": "inventory", "targets": ["auth-sae"], "stages": []})
    for m in msgs:
        led.feed(m)
    summary = led.summary()
    air = summary["air"]

    # Intersect with the defined members, which is what the acceptance asks
    # for. The raw column is wider than the registry and should be: an octet
    # mutation can set an id to a value no member has, and those are cases
    # worth sending, not members reached.
    seen_ids = set(air.get("element id", [])) & set(ids)
    seen_ext = set(air.get("element id extension", [])) & set(ext)
    check.ok(seen_ids == set(ids),
             "the ledger reports %d of %d defined element ids on the air"
             % (len(seen_ids), len(ids)),
             "missing: %s" % sorted(set(ids) - seen_ids)[:10])
    check.ok(seen_ext == set(ext),
             "and %d of %d extension ids -- the measurement that started this "
             "work was 0 of 62" % (len(seen_ext), len(ext)),
             "missing: %s" % sorted(set(ext) - seen_ext)[:10])
    check.ok(len(air.get("element id", [])) > len(ids),
             "while the raw column stays wider than the registry (%d), which "
             "is the octet sweep reaching ids no member has"
             % len(air.get("element id", [])))
    check.ok(summary["synthesised"] > 0,
             "and counts the synthesis (%d)" % summary["synthesised"])


def main():
    root = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else ".")
    check = Check()
    check_registry_fresh(root, check)
    with tempfile.TemporaryDirectory() as tmp:
        binary = build(root, tmp)
        if not binary:
            return 2
        check_every_id(root, check, binary)
        check_in_the_frame(check, binary)
        check_structure(check, binary)
        check_position(check, binary)
        check_length_and_multiplicity(check, binary)
        check_chain_ops(check, binary)
        check_no_chain(check, binary)
        check_bounds(check, binary)
        check_unchanged(check, binary)
        check_ledger(root, check, binary)
    print("\n%d of %d checks pass" % (check.passed,
                                      check.passed + check.failed))
    return 1 if check.failed else 0


if __name__ == "__main__":
    sys.exit(main())
