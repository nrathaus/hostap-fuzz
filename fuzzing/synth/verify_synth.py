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
import re
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


fuzz_ids = (None, None, None)


def registries(root):
    sys.path.insert(0, os.path.join(root, "fuzzing", "ledger"))
    import registries as reg
    global fuzz_ids
    data = reg.extract(root)
    fuzz_ids = (sorted(data["element id"]),
                sorted(data["element id extension"]),
                sorted(data["extended length element id"]))
    return fuzz_ids


def shapes(root):
    """The element shape table, as the engine gets it: from the tree."""
    sys.path.insert(0, os.path.join(root, "fuzzing", "ledger"))
    import registries as reg
    return reg.shapes(root)


def elems(messages):
    return [m for m in messages
            if m.get("msg") == "fuzz" and m.get("type") == "MUT_ELEM"]


SHAPE_BY_ID = {}
SHAPE_HDRS = []
# The widest header any shape has, which is what the engine calls
# FUZZ_ELEM_OVERHEAD. Taken from the generated table rather than typed, so a
# fourth shape with a wider header moves it here too.
ELEM_OVERHEAD = 0


def walk(body):
    """[(id, declared length, sub id or None)], or None if it is not a clean
    chain.

    Shape-aware, because the tree is: an element's header is two octets for
    most ids, three for the extension id and five -- with a little-endian u16
    length -- for the extended length id. A two-octet walk over a chain
    containing one of the latter reads a length out of octets that are not the
    length field, and then reports a correctly built chain as broken. The
    table comes from the checkout, so this walker cannot drift from the
    engine's.
    """
    out, pos = [], 0
    basic = {"hdr": 2, "len_off": 1, "len_width": 1, "len_le": False,
             "ext_off": 0, "ext_width": 0, "ext_le": False, "covers": False}
    while pos < len(body):
        eid = body[pos]
        sh = SHAPE_BY_ID.get(eid, basic)
        hdr = (sh["len_off"] + sh["len_width"]) if sh["covers"] else sh["hdr"]
        if pos + hdr > len(body):
            return None
        elen = int.from_bytes(
            body[pos + sh["len_off"]:pos + sh["len_off"] + sh["len_width"]],
            "little" if sh["len_le"] else "big")
        if pos + hdr + elen > len(body):
            return None
        sub = None
        if sh["ext_width"]:
            room = elen if sh["covers"] else len(body) - pos - sh["ext_off"]
            if room >= sh["ext_width"]:
                at = pos + sh["ext_off"]
                sub = int.from_bytes(body[at:at + sh["ext_width"]],
                                     "little" if sh["ext_le"] else "big")
        out.append((eid, elen, sub))
        pos += hdr + elen
    return out if pos == len(body) else None


def load_shape_table(root):
    global ELEM_OVERHEAD
    info = shapes(root)
    SHAPE_HDRS[:] = info["shapes"]
    ELEM_OVERHEAD = max(sh["hdr"] for sh in info["shapes"])
    sys.path.insert(0, os.path.join(root, "fuzzing", "ledger"))
    import registries as reg
    defined = reg.extract(root)
    for sh in info["shapes"]:
        if sh["sel"] is None:
            continue
        for members in defined.values():
            for val, names in members.items():
                if sh["sel"] in names:
                    SHAPE_BY_ID[val] = {
                        "hdr": sh["hdr"], "len_off": sh["len_off"],
                        "len_width": sh["len_width"],
                        "len_le": bool(sh["len_le"]),
                        "ext_off": sh["extid_off"],
                        "ext_width": sh["extid_width"],
                        "ext_le": bool(sh["extid_le"]),
                        "covers": bool(sh["covers"]),
                    }


def check_registry_fresh(root, check):
    print("\nThe tables are the header's")
    rc = subprocess.run(
        [sys.executable, os.path.join(root, "fuzzing", "ledger", "registries.py"),
         root, "--check"], capture_output=True, text=True)
    check.ok(rc.returncode == 0,
             "the generated registry header matches ieee802_11_defs.h",
             rc.stdout.strip()[:300])
    ids, ext, extlen = registries(root)
    # Membership is decided by the SECTION of the header a define sits in,
    # not by its name. Four constants named WLAN_EID_EXT_* are element ids
    # and one is a member of a third registry, so a longest-prefix rule gets
    # five of them wrong in both directions at once: it files four element
    # ids as extension ids -- where they are never built as element ids at
    # all -- and emits five numbers as extension ids that the extension
    # registry does not contain.
    check.ok(len(ids) == 183 and len(ext) == 57 and len(extlen) == 1,
             "183 element ids, 57 extension ids and %d extended length id(s) "
             "(%d, %d, %d)" % (len(extlen), len(ids), len(ext), len(extlen)))
    misfiled = {50, 60, 127, 227}
    check.ok(misfiled <= set(ids) and not (misfiled & set(ext)),
             "the element ids whose names carry the extension registry's "
             "prefix are element ids: %s" % sorted(misfiled))

    sh = shapes(root)
    names = [x["name"] for x in sh["shapes"]]
    widths = {x["name"]: x["len_width"] for x in sh["shapes"]}
    check.ok(len(names) == 3 and widths.get("EXTLEN") == 2,
             "three element shapes, one of them with a two-octet length "
             "field (%s)" % ", ".join("%s/%d" % (n, widths[n])
                                      for n in names))


def check_headroom_floor(root, check):
    """The engine's headroom floor is the widest header the table has.

    It is a number in fuzz.c and the table is generated, so the two can part
    company: a fourth shape with a six-octet header would leave the floor at
    five, and the element domains would be sized for a staging buffer that
    cannot hold one header. Checked rather than remembered.
    """
    print("\nThe headroom floor and the table agree")
    src = os.path.join(root, "src", "common", "fuzz.c")
    with open(src, encoding="utf-8") as f:
        text = f.read()
    m = re.search(r"#define\s+FUZZ_ELEM_OVERHEAD\s+(\d+)", text)
    check.ok(m is not None, "fuzz.c states a headroom floor")
    check.ok(m is not None and int(m.group(1)) == ELEM_OVERHEAD,
             "and it is the widest header of any shape (%s against %d)"
             % (m.group(1) if m else "none", ELEM_OVERHEAD))


def check_every_id(root, check, binary):
    print("\nEvery id is built, and built early")
    ids, ext, extlen = registries(root)
    total = len(ids) + len(ext) + len(extlen)

    # Identity varies fastest, so one case per id in the element domain is
    # enough -- but the round robin shares the run with the other domains, so
    # the run has to be long enough for the element domain to get that many
    # turns. Ten domains, so roughly ten times.
    _, msgs = run(binary, "t-ids", total * 12)
    e = elems(msgs)
    seen_eid = {m["eid"] for m in e if "eid" in m}
    # A sub-registry member counts only when the declared length reached far
    # enough to carry it. The length domain contains values that do not, and
    # counting those would report a member the frame did not have.
    seen_ext = {m["ext_id"] for m in e
                if "ext_id" in m and m.get("present") != 0}
    seen_extlen = {m["extlen_id"] for m in e
                   if "extlen_id" in m and m.get("present") != 0}

    check.ok(seen_eid == set(ids),
             "every one of the %d element ids is synthesised (%d)"
             % (len(ids), len(seen_eid)),
             "missing: %s" % sorted(set(ids) - seen_eid)[:10])
    # A subset, not an equality: the element id segment builds id 255 and id
    # 227 under their real shapes without choosing a member of the registry
    # those shapes carry, so a zero goes where the member would be. Zero is a
    # member of one of the two registries and of neither prefix rule, and the
    # case is worth sending either way -- what must not happen is a member
    # going UNSENT.
    check.ok(set(ext) <= seen_ext,
             "every one of the %d extension ids is synthesised (%d sent)"
             % (len(ext), len(seen_ext)),
             "missing: %s" % sorted(set(ext) - seen_ext)[:10])
    check.ok(set(extlen) <= seen_extlen,
             "and every one of the %d extended length ids (%d sent)"
             % (len(extlen), len(seen_extlen)),
             "missing: %s" % sorted(set(extlen) - seen_extlen)[:10])
    check.ok(len(e) >= total,
             "within %d cases, which is what a short run gets" % (total * 12))

    # Shape is not optional. An id built under the wrong shape still goes out,
    # still gets counted, and reports coverage of a length field the parser
    # never read -- so the check is that each of the three is actually built,
    # not merely that the table has three rows.
    built = {m.get("shape") for m in e}
    check.ok(built >= {"BASIC", "EXT", "EXTLEN"},
             "all three shapes are built, not just the two-octet one (%s)"
             % ", ".join(sorted(x for x in built if x)))


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
        # A nested element is not the first thing inserted -- its containers
        # are. The engine reports where the inner one landed, which is the
        # whole reason that key exists.
        if m.get("depth"):
            at = m["nest_at"]
        inserted = data[at:at + (now - was)]
        want = m["eid"]
        if not inserted or inserted[0] != want:
            bad.append((m.get("dom"), m.get("eid"), inserted[:6].hex()))
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
        sh = SHAPE_BY_ID.get(m.get("eid"))
        domain = 1 << (8 * (sh["len_width"] if sh else 1))
        if m.get("declared", 0) >= domain:
            bad.append(("length out of range", m.get("shape"),
                        m.get("declared")))
    check.ok(not bad,
             "no element claims a length its own length field cannot hold "
             "-- which for one shape is 65,535 and not 255",
             str(bad[:4]))

    frames, msgs = run(binary, "t-struct2", 600)
    chains = 0
    broken = []
    lying = 0
    for (ret, data), m in pair(frames, msgs):
        if m is None or m.get("type") != "MUT_ELEM" or m["len"] == m["was"]:
            continue
        if m.get("dom") in ("elen", "frag"):
            # The declared-length domain's whole point is a length that does
            # not describe what follows it, and a fragment run is a parent
            # that declares everything its field can say. Requiring the chain
            # to walk afterwards would be requiring those domains not to
            # work.
            lying += 1
            continue
        walked = walk(data[CHAIN_OFF:])
        if walked is None:
            broken.append((m.get("eid"), m.get("shape"), m.get("declared"),
                           m.get("body")))
        else:
            chains += 1
    check.ok(chains, "the frame still walks as a chain afterwards (%d)"
             % chains)
    check.ok(not broken,
             "every honestly-built element leaves a chain that walks exactly",
             str(broken[:4]))
    check.ok(lying,
             "and the domains whose point is a length that lies are counted "
             "apart rather than called breakage (%d)" % lying)


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
    room = 12
    nids = sum(len(x) for x in fuzz_ids)
    # The headroom bound is the WIDEST header of any shape, not the narrowest,
    # because the domain is one product over all the identities and a bound
    # that moved with the shape would move case_max with it. The declared
    # lengths that bound costs here are not lost: the declared-length domain
    # sweeps the whole field on every shape.
    overhead = max(x["hdr"] for x in SHAPE_HDRS)
    want = room - overhead + 1
    _, msgs = run(binary, "t-len", nids * want * 14,
                  frame=small, capacity=len(small) + room)
    e = [m for m in elems(msgs) if m.get("dom") == "elem"]
    declared = {m["declared"] for m in e if m["copies"] == 1}
    check.ok(declared == set(range(want)),
             "with %d octets of headroom the declared length is swept over "
             "its whole domain, 0..%d (%d distinct)"
             % (room, want - 1, len(declared)),
             "missing: %s" % sorted(set(range(want)) - declared)[:8])
    check.ok(0 in declared, "including an empty body")

    # The declared-length domain reaches past what the headroom holds, which
    # is the point of it: what an element says about itself and what follows
    # it are two different things, and for a two-octet length field the gap
    # is up to 65,535 octets.
    wide = [m for m in elems(msgs) if m.get("dom") == "elen"]
    check.ok(any(m["declared"] > room for m in wide),
             "and the declared length alone reaches past the headroom (max "
             "%d with %d octets of room)"
             % (max([m["declared"] for m in wide] or [0]), room))

    _, msgs = run(binary, "t-len2", 30000)
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


# ---------------------------------------------------------------------------
# Shape, fragmentation and nesting.
#
# 5b built every id as "u8 id, u8 len, body", inserted into a flat chain.
# Three things about the element layer in this tree make that one case out of
# several rather than the general one, and all three land on domains 5b
# already sweeps -- which is why none of them showed up as a failure. The
# frame went out, the ledger counted the id, and the length domain the run
# believed it swept was not the field the parser read.
# ---------------------------------------------------------------------------

# A chain containing all three shapes and a fragment group, so the walk has
# something to be wrong about. Built from the shape table rather than typed,
# for the same reason the engine's tables are generated: a hand-written chain
# here would keep passing after the tree changed underneath it.
def mixed_chain(root):
    info = shapes(root)
    byname = {x["name"]: x for x in info["shapes"]}
    sel = {}
    sys.path.insert(0, os.path.join(root, "fuzzing", "ledger"))
    import registries as reg
    defined = reg.extract(root)
    for sh in info["shapes"]:
        if sh["sel"] is None:
            continue
        for members in defined.values():
            for val, names in members.items():
                if sh["sel"] in names:
                    sel[sh["name"]] = val
    frag_id = None
    for members in defined.values():
        for val, names in members.items():
            if info["frag_id"] in names:
                frag_id = val

    out = bytearray()
    # basic
    out += bytes([0, 2, 0x41, 0x41])
    # extended length: id, le16 ext id, le16 datalen, body
    x = byname["EXTLEN"]
    e = bytearray(x["hdr"])
    e[0] = sel["EXTLEN"]
    e[x["extid_off"]:x["extid_off"] + x["extid_width"]] = \
        (0).to_bytes(x["extid_width"], "little")
    e[x["len_off"]:x["len_off"] + x["len_width"]] = \
        (4).to_bytes(x["len_width"], "little")
    out += bytes(e) + bytes(4)
    # extension: id, len (covering the ext id), ext id, body
    out += bytes([sel["EXT"], 3, 1]) + bytes(2)
    # a fragmentable element and its continuation: the parent declares
    # everything its length field can say, which is what makes the tree look
    # for one.
    out += bytes([1, info["frag_parent_len"]]) + bytes(info["frag_parent_len"])
    out += bytes([frag_id, 4]) + bytes(4)
    # and a trailing element, so "after the group" is a real position
    out += bytes([3, 0])
    # groups: basic, extlen, ext, (parent+fragment), trailing
    return bytes(out), 5, frag_id


def check_shapes(root, check, binary):
    print("\nThree shapes, and the chain walk that knows them")
    chain, ngroup, frag_id = mixed_chain(root)
    frame = HDR + FIXED + chain
    off = len(HDR) + len(FIXED)
    cap = len(frame) + 2 + 255

    # A flat two-octet walk over this chain is not merely less informative --
    # it reads a length out of octets that are not the length field, so every
    # offset after that point is arithmetic on unrelated bytes.
    flat, pos = [], 0
    while pos + 2 <= len(chain):
        flat.append((chain[pos], chain[pos + 1]))
        pos += 2 + chain[pos + 1]
    shaped = walk(chain)
    check.ok(shaped is not None,
             "the shape-aware walk consumes a chain with all three shapes "
             "exactly (%s)" % ("yes" if shaped else "no"))
    check.ok(pos != len(chain) or len(flat) != len(shaped or []),
             "and a two-octet walk of the same chain does not agree with it "
             "(%d elements against %d)" % (len(flat), len(shaped or [])))

    _, msgs = run(binary, "t-shape", 6000, frame=frame, capacity=cap,
                  chain_off=off)
    e = elems(msgs)
    check.ok(e and all(m["npos"] == ngroup + 1 for m in e),
             "a chain of %d groups has %d insertion points, not one per "
             "element (%s)"
             % (ngroup, ngroup + 1, e[0]["npos"] if e else "none"))

    # The insertion points are between groups. Landing between a fragmentable
    # element and its continuation terminates defragmentation and hands the
    # consumer a truncated buffer -- and the chain still walks afterwards, so
    # nothing would report it.
    parent = off + chain.index(bytes([1, 255]))
    inside = parent + 2 + 255
    hit = sorted({m["at"] for m in e if m["at"] == inside})
    check.ok(not hit,
             "and none of them is inside a fragment group, where inserting "
             "removes octets from an element without breaking the walk (%s)"
             % hit)

    # The declared length follows the shape. For the two-octet one that is a
    # 65,536-value domain, which is why an element header needs the tiers.
    byshape = {}
    for m in e:
        byshape.setdefault(m.get("shape"), set()).add(m.get("declared", 0))
    check.ok(max(byshape.get("EXTLEN", {0})) > 255,
             "an extended length element declares past 255 (%d), which a "
             "one-octet length field cannot say"
             % max(byshape.get("EXTLEN", {0})))
    check.ok(all(v <= 255 for v in byshape.get("BASIC", {0})),
             "and a basic element never does")
    tiers = {m.get("tier") for m in e if m.get("dom") == "elen"}
    check.ok("STRIDE" in tiers or "FULL" in tiers,
             "the declared-length domain names its tier, as every domain "
             "over 256 values in this engine does (%s)"
             % ", ".join(sorted(x for x in tiers if x)))

    # The window the extension shape has and the others do not: its declared
    # length covers the extension id, so the bottom of the length domain is a
    # frame carrying the shape without the id the identity domain selected.
    window = [m for m in e
              if m.get("shape") == "EXT" and m.get("present") == 0]
    check.ok(window,
             "a declared length below the extension id's width leaves it out "
             "of the frame, and is reported as not sent (%d case(s))"
             % len(window))
    check.ok(all(m["declared"] < 1 for m in window),
             "and that happens only below the minimum, not above it")


def check_fragments_and_nesting(root, check, binary):
    print("\nPast one element: fragments and nesting")
    big = len(FRAME) + 4000
    _, msgs = run(binary, "t-frag", 9000, capacity=big)
    e = elems(msgs)

    frag = [m for m in e if m.get("dom") == "frag"]
    check.ok(frag, "fragment runs are built (%d)" % len(frag))
    counts = sorted({m["nfrag"] for m in frag})
    check.ok(len(counts) > 1,
             "with the fragment count as the swept axis (%s)" % counts)
    longest = max([m.get("deflen", 0) for m in frag] or [0])
    check.ok(longest > 255,
             "and the defragmented length passes what a one-octet length "
             "field can say (%d octets), which is the only route there"
             % longest)
    check.ok(any(m.get("deflen", 0) < 255 * m["nfrag"] for m in frag),
             "including the run that ends at a fragment declaring nothing, "
             "which is where the walk stops")

    nest = [m for m in e if m.get("dom") == "nest"]
    check.ok(nest, "nested elements are built (%d)" % len(nest))
    depths = sorted({m["depth"] for m in nest})
    check.ok(depths == [1, 2],
             "at both depths the domain has, and early rather than at the "
             "end of a sweep no run finishes (%s)" % depths)
    check.ok(all(m["nest_at"] > m["at"] for m in nest),
             "and the inner element is inside its container, not beside it")


def check_one_hostile_field(check, binary):
    """W10. A case is a valid message with one hostile region, and the rest of
    the message is still READ.

    A walker that stops has not tested what was behind it. So an element whose
    declared length does not match its body may only go last -- anywhere else
    the overrun is absorbed by the element that follows, the walker's bound is
    never reached, and every element behind it is skipped while the ledger
    counts them as sent.

    Nothing here trusts the engine's own account of which domain lies. Every
    assertion is made against the octets that came out, re-walked here with
    the shape table taken from the checkout.
    """
    print("\nOne hostile field, and the rest of the message still readable")
    frames, msgs = run(binary, "t-w10", 6000)
    cases = [(f, m) for f, m in pair(frames, msgs)
             if m is not None and m.get("type") == "MUT_ELEM"]

    missing = [m for _, m in cases
               if m.get("walks") is None or m.get("tail") is None or
               m.get("pre") is None or m.get("post") is None]
    check.ok(cases and not missing,
             "every element case reports whether it walks, whether it went "
             "last, and how far a walker got before and after (%d case(s))"
             % len(cases),
             str(missing[:2]))

    # The flag is read off the octets, not off the domain that built them.
    # Cut the inserted region back out of the frame -- the engine says where
    # it went and how long it is -- and walk one copy with this file's own
    # walker. A flag that disagreed here would be a flag asserted rather than
    # measured, which is the failure this item is about.
    disagree, checked = [], 0
    for (ret, data), m in cases:
        grown, copies = m["len"] - m["was"], m.get("copies", 1)
        if grown <= 0 or copies <= 0 or grown % copies:
            continue
        one = data[m["at"]:m["at"] + grown // copies]
        mine = walk(one) is not None and len(one) > 0
        checked += 1
        if mine != bool(m["walks"]):
            disagree.append((m.get("dom"), m.get("eid"), m.get("declared"),
                             m["walks"], mine))
    check.ok(checked and not disagree,
             "and the flag agrees with an independent walk of the octets it "
             "emitted, case by case (%d)" % checked,
             str(disagree[:4]))

    walking = {bool(m["walks"]) for _, m in cases}
    check.ok(walking == {True, False},
             "both answers occur, so neither is a constant (%s)"
             % sorted(walking))

    # The invariant itself.
    absorbed = [(m.get("dom"), m.get("eid"), m.get("declared"), m["pos"],
                 m["npos"]) for _, m in cases if not m["walks"] and
                not m["tail"]]
    check.ok(not absorbed,
             "no case that stops the walk sits anywhere but last, where the "
             "overrun leaves the buffer instead of being absorbed",
             str(absorbed[:4]))

    want_pre = len(walk(FRAME[CHAIN_OFF:]) or [])
    wrong_pre = [m.get("pre") for _, m in cases if m["pre"] != want_pre]
    check.ok(want_pre == NELEM and not wrong_pre,
             "the chain this frame started with is %d elements deep, and "
             "every case says so" % want_pre,
             str(sorted(set(wrong_pre))[:4]))

    lost = [(m.get("dom"), m.get("eid"), m["pre"], m["post"])
            for _, m in cases if m["post"] < m["pre"]]
    check.ok(not lost,
             "and no case leaves a walker able to read fewer elements than "
             "the frame had before it -- which is what an item that lies in "
             "the middle of a chain costs",
             str(lost[:4]))

    # The honest domains keep their position axis; that is the other half of
    # the rule and the half a blunt "put everything last" would destroy.
    honest_pos = {m["pos"] for _, m in cases if m["walks"]}
    check.ok(honest_pos == set(range(NELEM + 1)),
             "every insertion point is still used by the cases that do walk "
             "(%s)" % sorted(honest_pos))

    first = [(m, m["post"] - m["pre"]) for _, m in cases
             if m["walks"] and m["pos"] == 0 and m.get("dom") == "elem"]
    check.ok(first and all(d == m.get("copies", 1) for m, d in first),
             "an honest element at index 0 of the chain really has tested "
             "%d elements and %s more, not one (%d case(s))"
             % (NELEM, "one", len(first)),
             str([(m.get("eid"), d) for m, d in first[:4]]))

    liars = [m for _, m in cases if not m["walks"]]
    check.ok(liars and all(m["at"] == m["was"] for m in liars),
             "and every item that lies went in at the end of the frame, not "
             "merely at the last insertion point of a chain (%d)"
             % len(liars),
             str([(m.get("dom"), m["at"], m["was"]) for m in liars[:4]]))


def check_copies_fit(check, binary):
    """A case the sizing admitted that the headroom will not hold.

    The multiplicity domain is 2..5 copies whatever the room, and the insert
    refuses rather than clipping -- so on a frame with little headroom the
    frame went out unmutated while the ledger still counted the id as sent at
    multiplicity 5. Same family as the rest of W10: the run reports a case it
    did not send.
    """
    print("\nMultiplicity against the headroom it actually has")
    # The least headroom the element domains will run in at all, so the
    # clamp is reached inside a run rather than at a copy count no sweep
    # gets to. Picked from the engine's own floor rather than guessed:
    # anything smaller and there are no element cases to check.
    narrow = len(FRAME) + ELEM_OVERHEAD
    frames, msgs = run(binary, "t-w10-fit", 6000, capacity=narrow)
    mult = [(f, m) for f, m in pair(frames, msgs)
            if m is not None and m.get("type") == "MUT_ELEM" and
            m.get("dom") == "mult"]
    check.ok(mult, "multiplicity cases ran against %d octets of headroom (%d)"
             % (narrow - len(FRAME), len(mult)))

    idle = [(m.get("eid"), m.get("shape"), m.get("copies"))
            for _, m in mult if m["len"] == m["was"]]
    check.ok(not idle,
             "none of them left the frame as built while reporting copies it "
             "never inserted",
             str(idle[:4]))

    clamped = [m for _, m in mult if m.get("copies_req") is not None]
    check.ok(clamped,
             "the ones the headroom could not hold are clamped and say so "
             "(%d of %d)" % (len(clamped), len(mult)))
    check.ok(all(m["copies"] < m["copies_req"] for m in clamped),
             "a clamped case reports fewer copies than it asked for",
             str([(m.get("shape"), m["copies"], m["copies_req"])
                  for m in clamped[:4]]))
    bad = [(m.get("shape"), m["copies"], m["len"] - m["was"])
           for _, m in mult
           if (m["len"] - m["was"]) % m["copies"] or
           m["len"] - m["was"] > narrow - m["was"]]
    check.ok(not bad,
             "and the octets that went in really are that many whole copies, "
             "inside the headroom",
             str(bad[:4]))

    room = {m.get("shape") for _, m in mult if m.get("copies_req") is None}
    check.ok(room,
             "while a shape small enough to hold the copies it asked for is "
             "not clamped (%s)" % sorted(x for x in room if x))


MINIMA = []


def load_minima(root):
    """The generated minima table, as the engine gets it: from the tree."""
    sys.path.insert(0, os.path.join(root, "fuzzing", "ledger"))
    import minima
    MINIMA[:] = minima.extract(root)
    return minima


def check_minima_fresh(root, check):
    """W11. The minimums are generated, and the build fails when one moves."""
    print("\nThe parser's own minimums, generated")
    rc = subprocess.run([sys.executable,
                         os.path.join(root, "fuzzing", "ledger", "minima.py"),
                         root, "--check"], capture_output=True, text=True)
    check.ok(rc.returncode == 0,
             "minima.py --check agrees with the tree",
             (rc.stdout + rc.stderr).strip()[:400])

    minima = load_minima(root)
    check.ok(MINIMA, "the parser states %d length guard(s)" % len(MINIMA))

    # Every number came out of the compiler, against the tree's own headers.
    # A row whose expression is not a plain integer is the interesting case:
    # it is the one a re-implementation here would get wrong.
    derived = [r for r in MINIMA if not r[4].strip().isdigit()]
    check.ok(len(derived) >= 10,
             "%d of them are sizeof() or a named constant rather than a "
             "literal, so the value cannot be read off the source text"
             % len(derived))
    check.ok(all(r[5] > 0 for r in derived),
             "and every one of those evaluated to a real length",
             str([(r[4], r[5]) for r in derived if r[5] <= 0][:4]))

    nptr, nlen, npair = minima.pairs(root)
    check.ok((nptr, nlen) == (92, 78),
             "struct ieee802_11_elems holds %d pointers and %d lengths, "
             "which is the denominator this item is against" % (nptr, nlen))

    # The extension parser's guard is against a length that has already lost
    # the extension id. Getting that wrong aims the whole extension registry
    # one octet low, and every window would miss by one in the same
    # direction -- which is the shape of mistake a sweep never reports.
    ext = [r for r in MINIMA if r[0] == "element id extension"]
    check.ok(ext and all(r[6] == 1 for r in ext),
             "every extension guard is one octet past the declared length, "
             "read from the parser's own decrement (%d row(s))" % len(ext))
    basic = [r for r in MINIMA if r[0] == "element id"]
    check.ok(basic and all(r[6] == 0 for r in basic),
             "and no basic element's is (%d row(s))" % len(basic))


# The window's offsets, in the order the engine takes them. The membership
# is the plan's; the order is a design choice, and it is the order that
# decides what a short run reaches -- so it is checked as well as used.
MIN_LADDER = [0, 1, 2, 3, 4, -1, -2, 7, 8, 0]
EDGE_LADDER = [0, 1, 2, -1, 0, 1, -2, -1]


def window_first(minimum, top, k):
    """A permutation of 0..top that starts at the window around 'minimum'."""
    window = []
    for off in MIN_LADDER:
        v = minimum + off
        if 0 <= v <= top and v not in window:
            window.append(v)
    rest = [v for v in range(top + 1) if v not in window]
    seq = window + rest
    return seq[k] if k < len(seq) else None


def ladder_value(domain, built, minimum, n, full):
    """This file's own reading of the engine's ordering.

    Written from the plan rather than from fuzz.c, because a check that
    called the engine's arithmetic would agree with it however wrong both
    were. A domain small enough to enumerate is permuted to start at the
    window; a domain that is sampled gets ten ladder entries aimed at the
    parser's minimum, then the eight that sit at the edges of the domain and
    of where the frame already was.
    """
    mask = domain - 1
    if full:
        return window_first(minimum, mask, n)
    if n < len(MIN_LADDER):
        return (minimum + MIN_LADDER[n]) & mask
    n -= len(MIN_LADDER)
    if n < len(EDGE_LADDER):
        d = EDGE_LADDER[n]
        if n < 3:
            return d & mask
        if n < 6:
            return (built + d) & mask
        return (domain + d) & mask
    return None                                # the stride, not the ladder


def ident(m):
    """(registry, member) for an element case."""
    if m.get("reg") == "element id":
        return ("element id", m.get("eid"))
    return (m.get("reg"), m.get("ext_id", m.get("extlen_id")))


def check_aims_at_the_minimum(check, binary):
    """W11. The window above each enforced minimum is reached in run 1."""
    print("\nEvery sampled length domain aims at the minimum")
    want = {}
    for registry, value, label, rel, expr, n, past in MINIMA:
        want[(registry, value)] = (n + past, rel, expr)

    _, msgs = run(binary, "t-w11", 9000)
    e = [m for m in elems(msgs) if m.get("dom") in ("elem", "elen")]
    check.ok(e, "element length cases ran (%d)" % len(e))

    missing = [m for m in e if m.get("min") is None or
               m.get("min_known") is None]
    check.ok(not missing,
             "every one of them reports the minimum it was aimed at",
             str(missing[:2]))

    known = {bool(m["min_known"]) for m in e}
    check.ok(known == {True, False},
             "both a known minimum and none occur, so the flag is not a "
             "constant (%s)" % sorted(known))

    # The engine's number against the generator's, row by row. A lookup that
    # returned a constant, or that read the wrong registry, passes every
    # other check in this file.
    wrong = []
    for m in e:
        key = ident(m)
        row = want.get(key)
        if row is None:
            if m["min_known"]:
                wrong.append(("claimed a minimum", key, m.get("min")))
        elif not m["min_known"] or m["min"] != row[0] or \
                m.get("min_rel") != row[1] or m.get("min_expr") != row[2]:
            wrong.append((key, m.get("min"), m.get("min_expr"), row))
    check.ok(not wrong,
             "and it is the generator's number and the guard's own words, "
             "id by id (%d case(s) cross-checked)" % len(e),
             str(wrong[:4]))

    # The window itself, in the domain that samples: the k'th case an id
    # gets must be the k'th entry of the ladder this file computes for it.
    # Checking the k'th rather than the set is what makes a short run
    # enough -- and a run is always short.
    elen = [m for m in e if m["dom"] == "elen"]
    by_id, out_of_order = {}, []
    for m in elen:
        seq = by_id.setdefault(ident(m), [])
        sh = SHAPE_BY_ID.get(m["eid"], {"len_width": 1, "covers": False,
                                        "ext_width": 0})
        domain = 1 << (8 * sh["len_width"])
        built = sh["ext_width"] if sh["covers"] else 0
        want_v = ladder_value(domain, built, m["min"], len(seq),
                              m.get("tier") == "FULL")
        if want_v is not None and m["declared"] != want_v:
            out_of_order.append((ident(m), len(seq), m["declared"], want_v))
        seq.append(m["declared"])
    check.ok(by_id and not out_of_order,
             "the declared-length domain's k'th case for an id is the k'th "
             "entry of the ladder, aimed at that id's own minimum "
             "(%d id(s))" % len(by_id),
             str(out_of_order[:4]))

    check.ok(MIN_LADDER[0] == 0 and sorted(MIN_LADDER) ==
             [-2, -1, 0, 0, 1, 2, 3, 4, 7, 8],
             "the window's first entry is the minimum ITSELF, not the "
             "bottom of the window: identity varies fastest, so an id a "
             "short run touches once is built at that entry and no other")

    # The figure this item exists to move: ids built at or above the length
    # their own parser insists on. Below it the handler never runs, so the
    # case is a registry member sent and a parser not reached.
    at_or_above = {ident(m) for m in e
                   if m["min_known"] and m["declared"] >= m["min"]}
    aimed_ids = {ident(m) for m in e if m["min_known"]}
    check.ok(aimed_ids and at_or_above == aimed_ids,
             "every id with a guard was built AT or above it in this run "
             "(%d of %d)" % (len(at_or_above), len(aimed_ids)),
             str(sorted(aimed_ids - at_or_above)[:6]))

    aimed = [m for m in elen if m["min_known"]]
    below = sum(1 for m in aimed if m["declared"] < m["min"])
    check.ok(below,
             "the guard is tested from below as well as above (%d case(s))"
             % below)

    # The element domain enumerates rather than samples, so the window is a
    # reordering there. Its first case for an id must be in the window.
    first = {}
    for m in e:
        if m["dom"] != "elem" or not m["min_known"]:
            continue
        first.setdefault(ident(m), m)
    off = [(k, m["declared"], m["min"]) for k, m in first.items()
           if abs(m["declared"] - m["min"]) > 2]
    check.ok(first and not off,
             "the element domain's FIRST case for an id with a minimum is "
             "within two octets of it, not at zero (%d id(s))" % len(first),
             str(off[:4]))


def check_fixed_ladder(check, binary):
    """W11. A fixed count even when entries coincide."""
    print("\nThe ladder is the same size whether or not there is a minimum")
    _, msgs = run(binary, "t-w11-ladder", 9000,
                  env={"FUZZ_TIER": "LADDER"})
    elen = [m for m in elems(msgs) if m.get("dom") == "elen"]
    check.ok(elen, "declared-length cases ran at LADDER (%d)" % len(elen))
    check.ok(all(m.get("tier") == "LADDER" for m in elen),
             "and say so")

    seen = {}
    for m in elen:
        seen.setdefault(ident(m), []).append(m)
    done = {k: v for k, v in seen.items() if len(v) >= 18}
    check.ok(done,
             "at least one id was taken through a whole ladder (%d of %d)"
             % (len(done), len(seen)))
    sizes = {len(v) for v in seen.values() if len(v) < 18}
    check.ok(all(len(v) == 18 for v in done.values()),
             "and a whole ladder is 18 cases: %d edges plus %d aimed at the "
             "minimum" % (8, 10),
             str(sorted({len(v) for v in done.values()})))

    # The count does not move with whether a minimum is known -- which is the
    # property that lets the generated table gain a row without shifting
    # every case_id after it.
    withmin = [k for k, v in done.items() if v[0]["min_known"]]
    without = [k for k, v in done.items() if not v[0]["min_known"]]
    check.ok(withmin and without,
             "ids of both kinds completed one (%d with a minimum, %d "
             "without)" % (len(withmin), len(without)))
    check.ok(len({len(done[k]) for k in withmin + without}) == 1,
             "and both kinds cost exactly the same number of cases",
             str({k: len(done[k]) for k in (withmin[:2] + without[:2])}))

    # Coinciding entries stay entries. An id whose minimum is 1 has a window
    # that runs off the bottom of the domain and folds onto its edges; the
    # case count must not notice.
    dupes = [k for k, v in done.items()
             if len({m["declared"] for m in v}) < len(v)]
    check.ok(dupes,
             "some ladders have entries that coincide, and are still 18 "
             "cases (%d id(s))" % len(dupes))


def check_ledger(root, check, binary):
    print("\nEnd to end: what the ledger makes of it")
    sys.path.insert(0, os.path.join(root, "fuzzing", "ledger"))
    from ledger import Ledger
    ids, ext, extlen = registries(root)
    nids = len(ids) + len(ext) + len(extlen)
    _, msgs = run(binary, "auth-sae", nids * 12)
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
    seen_xl = set(air.get("extended length element id", [])) & set(extlen)
    check.ok(seen_ids == set(ids),
             "the ledger reports %d of %d defined element ids on the air"
             % (len(seen_ids), len(ids)),
             "missing: %s" % sorted(set(ids) - seen_ids)[:10])
    check.ok(seen_ext == set(ext),
             "and %d of %d extension ids -- the measurement that started this "
             "work was 0 of 62" % (len(seen_ext), len(ext)),
             "missing: %s" % sorted(set(ext) - seen_ext)[:10])
    check.ok(seen_xl == set(extlen),
             "and %d of %d extended length ids, a registry that had no "
             "denominator before there was a shape table"
             % (len(seen_xl), len(extlen)),
             "missing: %s" % sorted(set(extlen) - seen_xl)[:10])
    check.ok(len(air.get("element id", [])) > len(ids),
             "while the raw column stays wider than the registry (%d), which "
             "is the octet sweep reaching ids no member has"
             % len(air.get("element id", [])))
    check.ok(summary["synthesised"] > 0,
             "and counts the synthesis (%d)" % summary["synthesised"])


def main():
    root = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else ".")
    check = Check()
    load_shape_table(root)
    check_registry_fresh(root, check)
    check_headroom_floor(root, check)
    check_minima_fresh(root, check)
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
        check_shapes(root, check, binary)
        check_fragments_and_nesting(root, check, binary)
        check_one_hostile_field(check, binary)
        check_aims_at_the_minimum(check, binary)
        check_fixed_ladder(check, binary)
        check_copies_fit(check, binary)
        check_ledger(root, check, binary)
    print("\n%d of %d checks pass" % (check.passed,
                                      check.passed + check.failed))
    return 1 if check.failed else 0


if __name__ == "__main__":
    sys.exit(main())
