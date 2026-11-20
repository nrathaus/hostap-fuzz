#!/usr/bin/env python3
"""Behavioural checks for the field model.

    python3 verify_fields.py /path/to/checkout

Needs no radio, no interface and no root: it compiles a harness against the
checkout's own fuzz.o and drives the hook directly. Build with CONFIG_FUZZ=y
first.

The claim the whole thing turns on is small and testable. A byte-offset sweep
puts all 255 other values through the low octet of a two-octet field and all
255 through the high one, and never once sends the pair that makes the field
300. 65,536 values; 511 reached. So what is checked here is that each named
field really is driven across its own domain as a unit, that the table those
fields come from is the tree's and not someone's memory of it, and that the
reduction applied to the domains too wide to finish is deferral rather than
sampling -- the union over runs has to be the whole domain, or 'STRIDE' is
just a nicer word for giving up.
"""

import json
import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
PREFIX = "[fuzz] "
WARMUP = 9

OBJECTS = [
    "src/common/fuzz.o",
    "src/utils/json.o",
    "src/utils/wpabuf.o",
    "src/utils/common.o",
    "src/utils/os_unix.o",
    "src/utils/base64.o",
    "src/utils/wpa_debug.o",
]

HARNESS = """
#include "utils/includes.h"
#include "utils/common.h"
#include "common/fuzz.h"

int main(int argc, char *argv[])
{
\tconst char *target = argv[1];
\tsize_t len, capacity;
\tint iterations, i, type;
\tu8 *frame, *base;
\tchar *hex;

\tif (argc < 6)
\t\treturn 2;

\tlen = os_strlen(argv[2]) / 2;
\tcapacity = (size_t) atoi(argv[3]);
\ttype = atoi(argv[4]);
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
\t\tout = apply_mutation_resize(target,
\t\t\t\t\t    (enum fuzz_frame_type) type,
\t\t\t\t\t    frame, len, capacity);
\t\twpa_snprintf_hex(hex, 2 * out + 1, frame, out);
\t\tprintf("ret %zu %s\\n", out, hex);
\t}

\treturn 0;
}
"""

# An Authentication frame: subtype 11 in the frame control field, then the
# three two-octet fields struct ieee80211_mgmt declares for it, then a short
# element chain. The built values are deliberately not zero, so the ladder's
# "n-1, n, n+1" entries are distinguishable from its "0, 1, 2" ones.
AUTH_ALG, AUTH_TRANS, AUTH_STATUS = 0x1234, 0x0002, 0x4321


def auth_frame():
    hdr = bytearray(24)
    hdr[0] = (11 << 4)                      # type management, subtype auth
    body = bytearray()
    for v in (AUTH_ALG, AUTH_TRANS, AUTH_STATUS):
        body += bytes([v & 0xff, v >> 8])   # le16
    body += bytes([0, 2, 0x41, 0x41])
    return bytes(hdr + body)


FRAME = auth_frame()
CAP = len(FRAME) + 2 + 255
MGMT, EAPOL = 1, 2


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


def build_harness(root, workdir):
    objdir = os.path.join(root, "build", "hostapd")
    missing = [o for o in OBJECTS
               if not os.path.exists(os.path.join(objdir, o))]
    if missing:
        print("cannot find %s under %s" % (missing[0], objdir))
        print("Build the checkout with CONFIG_FUZZ=y first:")
        print("    cd hostapd && cp defconfig-fuzz .config && make")
        return None
    path = os.path.join(workdir, "f.c")
    binary = os.path.join(workdir, "f")
    with open(path, "w", encoding="utf-8") as f:
        f.write(HARNESS)
    r = subprocess.run(
        [os.environ.get("CC", "cc"), "-o", binary, path,
         "-I%s" % os.path.join(root, "src"),
         "-I%s" % os.path.join(root, "src", "utils"),
         "-DCONFIG_FUZZ"] +
        [os.path.join(objdir, o) for o in OBJECTS],
        capture_output=True, text=True)
    if r.returncode != 0:
        print("the harness did not compile:")
        print(r.stderr.strip()[:2000])
        return None
    return binary


def run(binary, target, iterations, frame=FRAME, capacity=CAP, ftype=MGMT,
        env=None):
    e = {k: v for k, v in os.environ.items() if not k.startswith("FUZZ_")}
    e.update(env or {})
    out = subprocess.run(
        [binary, target, frame.hex(), str(capacity), str(ftype),
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


def muts(messages, kind=None):
    out = [m for m in messages if m.get("msg") == "fuzz"]
    return [m for m in out if kind is None or m.get("type") == kind]


def table(root):
    sys.path.insert(0, os.path.join(root, "fuzzing", "ledger"))
    import fields as fields_mod
    return fields_mod


# --------------------------------------------------------------------------

def check_table_is_derived(root, check):
    """The offsets and widths are the tree's, not a transcription of it."""
    print("\nThe field table comes from the tree")
    mod = table(root)
    rows = mod.build(root)
    check.ok(rows, "the structs parse (%d fields)" % len(rows or []))

    r = subprocess.run([sys.executable,
                        os.path.join(root, "fuzzing", "ledger", "fields.py"),
                        root, "--check"], capture_output=True, text=True)
    check.ok(r.returncode == 0,
             "src/common/fuzz_fields.h matches the tree",
             r.stdout.strip())

    # Every type width the generator assumes, checked against the tree's own
    # typedefs. These are not cosmetic: a width that is wrong by one shifts
    # every offset after it, and the sweep would then be driving the field
    # next to the one whose name it reports -- with nothing failing.
    src = open(os.path.join(root, "src", "utils", "common.h"),
               encoding="utf-8").read()
    chain = {}
    for m in re.finditer(r"(?m)^typedef\s+(.+?)\s+(?:__bitwise\s+)?(\w+)\s*;",
                         src):
        chain.setdefault(m.group(2), m.group(1).replace("__bitwise", "")
                         .strip())

    def width_of(name, depth=0):
        """Follow the typedefs down to something whose width is in its name."""
        if depth > 8:
            return None
        m = re.search(r"(?:u|s|U|S)?INT(\d+)|(?:u|)int(\d+)_t", name)
        if m:
            return int(m.group(1) or m.group(2)) // 8
        nxt = chain.get(name)
        return width_of(nxt, depth + 1) if nxt else None

    used = sorted({t for t in mod.SCALARS})
    bad = []
    for name in used:
        got = width_of(name)
        if got is not None and got != mod.SCALARS[name]:
            bad.append((name, got, mod.SCALARS[name]))
    resolved = [n for n in used if width_of(n) is not None]
    check.ok(not bad,
             "every type width the generator assumes matches the tree's "
             "typedef (%d of %d resolved)" % (len(resolved), len(used)),
             "; ".join("%s is %d, assumed %d" % b for b in bad))
    check.ok(width_of("le16") == 2 and width_of("be16") == 2,
             "including le16 and be16, which carry the frame's two-octet "
             "fields")

    # Offsets must agree with the C the compiler sees, which is the real
    # authority. Checked by arithmetic the compiler would do: every
    # management field starts at or after the 24-octet header, and the
    # fields of one subtype are contiguous from there.
    byst = {}
    for frame, stype, name, off, width, kind, _ in rows:
        if frame != "mgmt":
            continue
        byst.setdefault(stype, []).append((off, width, name))
    gaps = []
    for stype, fs in byst.items():
        fs.sort()
        pos = 24
        for off, width, name in fs:
            if off != pos:
                gaps.append((name, off, pos))
            pos = off + width
    check.ok(not gaps,
             "every management subtype's fields are packed from octet 24 "
             "with no gaps (%d subtypes)" % len(byst),
             "; ".join("%s at %d, expected %d" % g for g in gaps[:3]))


def check_field_domain(root, binary, check):
    """A two-octet field is driven across 0..65535, not across its octets."""
    print("\nA field is swept as a field")
    # FULL on everything, so the claim is about the domain and not the tier.
    _, msgs = run(binary, "t-full", 200000, env={"FUZZ_TIER": "FULL"})
    fm = muts(msgs, "MUT_FIELD")
    check.ok(fm, "the field domain runs (%d cases)" % len(fm))

    names = {m.get("field") for m in fm}
    check.ok(names == {"auth.auth_alg", "auth.auth_transaction",
                       "auth.status_code"},
             "and only the fields this subtype declares: %s" % sorted(names))

    for name in sorted(names):
        vals = {m.get("after") for m in fm if m.get("field") == name}
        check.ok(vals == set(range(0, 65536)),
                 "%s takes every one of its 65536 values" % name,
                 "got %d distinct" % len(vals))

    # The point of the exercise, stated as the comparison it came from.
    byte = muts(msgs, "MUT_BYTE_XOR")
    reach = set()
    for m in byte:
        pos = m.get("hdr", 0) + m.get("idx", 0)
        if 24 <= pos < 30:
            reach.add(pos)
    check.ok(len(reach) == 6,
             "the octet domain does reach all six of those octets (%d)"
             % len(reach))
    check.ok(len(vals) > 511,
             "but octet-wise reaches 511 of a two-octet field's values and "
             "the field domain reaches %d" % len(vals))


def check_before_is_the_built_value(root, binary, check):
    """'before' is what the frame was built with, which is the only record
    of what the running configuration emits."""
    print("\nThe message says what was there")
    _, msgs = run(binary, "t-before", 4000, env={"FUZZ_TIER": "FULL"})
    want = {"auth.auth_alg": AUTH_ALG,
            "auth.auth_transaction": AUTH_TRANS,
            "auth.status_code": AUTH_STATUS}
    bad = [m for m in muts(msgs, "MUT_FIELD")
           if m.get("before") != want.get(m.get("field"))]
    check.ok(not bad,
             "every field case reports the value the frame was built with",
             str(bad[:1]))

    # And the frame on the wire really carries 'after' at 'at'.
    frames, msgs2 = run(binary, "t-wire", 2000, env={"FUZZ_TIER": "FULL"})
    pairs = list(zip(frames, muts(msgs2)))
    wrong = []
    for (_, data), m in pairs:
        if m.get("type") != "MUT_FIELD":
            continue
        at, w = m["at"], m["width"]
        got = int.from_bytes(data[at:at + w], "little")
        if got != m["after"]:
            wrong.append((m["field"], got, m["after"]))
    check.ok(not wrong,
             "and the octets at that offset really hold it (%d checked)"
             % len([1 for _, m in pairs if m.get("type") == "MUT_FIELD"]),
             str(wrong[:3]))


def check_tiers(root, binary, check):
    """FULL, LADDER and STRIDE are declared, and STRIDE is not sampling."""
    print("\nThe reduction is declared, and it is deferral")
    _, full = run(binary, "t-t-full", 300, env={"FUZZ_TIER": "FULL"})
    _, lad = run(binary, "t-t-lad", 300, env={"FUZZ_TIER": "LADDER"})
    _, strd = run(binary, "t-t-str", 300, env={"FUZZ_TIER": "STRIDE"})

    for name, msgs in (("FULL", full), ("LADDER", lad), ("STRIDE", strd)):
        tiers = {m.get("tier") for m in muts(msgs, "MUT_FIELD")}
        check.ok(tiers == {name},
                 "FUZZ_TIER=%s is reported on every field case" % name,
                 str(sorted(tiers)))

    def case_max(msgs):
        return max(m.get("case_max", 0) for m in msgs
                   if m.get("msg") == "progress")

    check.ok(case_max(lad) < case_max(strd) < case_max(full),
             "and each tier is a smaller case space than the next "
             "(%d < %d < %d)" % (case_max(lad), case_max(strd),
                                 case_max(full)))

    # The ladder is the edges, whatever the width -- eight entries, including
    # where the frame already is.
    vals = {m["after"] for m in muts(lad, "MUT_FIELD")
            if m.get("field") == "auth.status_code"}
    check.ok({0, 1, 2, 65534, 65535} <= vals,
             "the ladder carries both ends of the domain",
             str(sorted(vals)))
    check.ok({AUTH_STATUS - 1, AUTH_STATUS, AUTH_STATUS + 1} <= vals,
             "and the values either side of the one the frame was built with",
             str(sorted(vals)))

    # STRIDE is the claim that nothing is skipped, only deferred -- so the
    # union over the whole set of runs has to be the whole domain, or
    # "deferred" is a nicer word for giving up. Run every offset to the end
    # of its case space and take the union. No capacity beyond the frame, so
    # the length and element domains are empty and the run is short.
    seen, per_run, spaces = set(), [], set()
    offsets = 251
    for off in range(offsets):
        _, m = run(binary, "t-str%d" % off, 3500, capacity=len(FRAME),
                   env={"FUZZ_TIER": "STRIDE",
                        "FUZZ_STRIDE_OFFSET": str(off)})
        got = {x["after"] for x in muts(m, "MUT_FIELD")
               if x.get("field") == "auth.status_code"}
        per_run.append(len(got))
        spaces.add(case_max(m))
        seen |= got
    missing = sorted(set(range(65536)) - seen)
    check.ok(not missing,
             "the union of all %d stride offsets is the whole 65536-value "
             "domain, so nothing is skipped -- only deferred (%d seen)"
             % (offsets, len(seen)),
             "missing %d, first few: %s" % (len(missing), missing[:5]))
    check.ok(max(per_run) < 300,
             "while any single run of it is at most %d cases, not 65536"
             % max(per_run))
    # Cases, not distinct values: a ladder entry can coincide with a stride
    # value, so how many DISTINCT values a run lands on varies by one. What
    # must not vary is the size of the case space, because a case_id is an
    # index into it and a case space that moved with the stride offset would
    # renumber every case in the set.
    check.ok(len(spaces) == 1,
             "and every offset is the same size of case space, so a case_id "
             "means the same thing across the set (%s)" % sorted(spaces),
             "distinct values per run: %s" % sorted(set(per_run)))


def check_identity_varies_fastest(root, binary, check):
    """A run cut short has touched every field, not finished one."""
    print("\nIdentity varies fastest")
    _, msgs = run(binary, "t-fast", 400, env={"FUZZ_TIER": "FULL"})
    fm = muts(msgs, "MUT_FIELD")
    check.ok(fm, "there are field cases to look at (%d)" % len(fm))
    first = {}
    for i, m in enumerate(fm):
        first.setdefault(m["field"], i)
    check.ok(len(first) == 3 and max(first.values()) < 10,
             "all three fields appear within the first ten field cases %s"
             % sorted(first.items()),
             str(first))
    # Against a real peer every run is cut short, so a domain that is
    # complete but unreachable is the same as one that is missing.
    check.ok(len({m["field"] for m in fm[:6]}) == 3,
             "and the first six alternate between them rather than "
             "finishing one")


def check_patterns(root, binary, check):
    """An opaque field is filled, not counted."""
    print("\nAn opaque field gets shapes, not values")
    # EAPOL-Key: the nonce, the replay counter, the IV are all opaque.
    frame = bytes([2, 3, 0, 95, 2]) + bytes([0x55]) * 90
    _, msgs = run(binary, "t-pat", 3000, frame=frame,
                  capacity=len(frame) + 257, ftype=EAPOL)
    pm = muts(msgs, "MUT_PATTERN")
    check.ok(pm, "the pattern domain runs (%d cases)" % len(pm))
    names = {m.get("field") for m in pm}
    check.ok("key_nonce" in names and "replay_counter" in names,
             "on the fields that are too wide to enumerate: %s"
             % sorted(names))
    pats = {m.get("pattern") for m in pm}
    check.ok(pats == set(range(6)),
             "every pattern is used (%s)" % sorted(pats))

    frames, msgs2 = run(binary, "t-pat2", 3000, frame=frame,
                        capacity=len(frame) + 257, ftype=EAPOL)
    bad = []
    for (_, data), m in zip(frames, muts(msgs2)):
        if m.get("type") != "MUT_PATTERN":
            continue
        region = data[m["at"]:m["at"] + m["width"]]
        if m["pattern"] < 5:
            fill = [0x00, 0x01, 0x7f, 0x80, 0xff][m["pattern"]]
            if any(b != fill for b in region):
                bad.append((m["field"], m["pattern"], region[:4].hex()))
        elif list(region) != list(range(len(region))):
            bad.append((m["field"], m["pattern"], region[:4].hex()))
    check.ok(not bad,
             "and the frame really carries it (%d checked)"
             % len([1 for m in muts(msgs2) if m.get("type") == "MUT_PATTERN"]),
             str(bad[:3]))

    # A two-octet field is counted, not filled: its whole content space is
    # 65536 values and that is a domain you can finish.
    fm = muts(msgs2, "MUT_FIELD")
    check.ok({"key_info", "key_length", "length"} <= {m["field"]
                                                      for m in fm},
             "while a two-octet field is counted instead: %s"
             % sorted({m["field"] for m in fm}))


def check_subtype_selects(root, binary, check):
    """The layout comes from the frame, not from the call site."""
    print("\nThe subtype is read from the frame")
    deauth = bytearray(FRAME)
    deauth[0] = (12 << 4)                   # WLAN_FC_STYPE_DEAUTH
    _, msgs = run(binary, "t-deauth", 3000, frame=bytes(deauth))
    names = {m.get("field") for m in muts(msgs, "MUT_FIELD")}
    check.ok(names == {"deauth.reason_code"},
             "the same octets read as a Deauthentication frame give its "
             "field, not the Authentication frame's: %s" % sorted(names))

    probe = bytearray(FRAME)
    probe[0] = (4 << 4)                     # WLAN_FC_STYPE_PROBE_REQ
    _, msgs = run(binary, "t-probe", 500, frame=bytes(probe))
    check.ok(not muts(msgs, "MUT_FIELD"),
             "and a subtype with no fixed fields gets no field cases, "
             "rather than another subtype's")
    check.ok(muts(msgs, "MUT_BYTE_XOR"),
             "while the octet domain still runs there, so coverage never "
             "regresses where the model says nothing")

    # A frame too short for a field does not get that field, rather than a
    # clamped version of it written over whatever is there.
    short = bytes(FRAME[:26])
    _, msgs = run(binary, "t-short", 2000, frame=short,
                  capacity=len(short))
    names = {m.get("field") for m in muts(msgs, "MUT_FIELD")}
    check.ok(names == {"auth.auth_alg"},
             "a frame that ends mid-field gets only the fields that fit: %s"
             % sorted(names))


def check_opset(root, binary, check):
    """The case space says which case space it is."""
    print("\nThe case space names itself")
    _, a = run(binary, "t-op-a", 50, env={"FUZZ_TIER": "FULL"})
    _, b = run(binary, "t-op-b", 50, env={"FUZZ_TIER": "STRIDE",
                                          "FUZZ_STRIDE_OFFSET": "7"})
    opa = {m.get("opset") for m in a if m.get("msg") in ("fuzz", "progress")}
    opb = {m.get("opset") for m in b if m.get("msg") in ("fuzz", "progress")}
    check.ok(len(opa) == 1 and None not in opa,
             "every progress and fuzz message carries one opset (%s)"
             % sorted(opa))
    check.ok(opa != opb,
             "and it differs when the tier or the stride offset does "
             "(%s vs %s)" % (sorted(opa), sorted(opb)))
    check.ok("@7" in list(opb)[0],
             "the stride offset is in it, so a deferred case says which run "
             "of the set it came from (%s)" % list(opb)[0])

    # The hazard this exists for: the same case_id under two case spaces is
    # two different frames.
    fa, _ = run(binary, "t-same", 40, env={"FUZZ_TIER": "FULL"})
    fb, _ = run(binary, "t-same", 40, env={"FUZZ_TIER": "LADDER"})
    check.ok(fa != fb,
             "and the same case_id under two of them really is two "
             "different frames")


def check_registries(root, binary, check):
    """The three registries the element work could not reach.

    status code, authentication algorithm and reason code are not element
    ids: they are fields, and until there was a field model the ledger
    measured 1, 1 and 0 of them. They are the measurement this part of the
    work exists to move.
    """
    print("\nThe registries that needed a field, not an element")
    sys.path.insert(0, os.path.join(root, "fuzzing", "ledger"))
    from ledger import Ledger
    import registries as reg

    defined = reg.extract(root)

    def tally(frame, iterations):
        _, msgs = run(binary, "t-reg", iterations, frame=frame,
                      capacity=len(frame), env={"FUZZ_TIER": "FULL"})
        led = Ledger()
        for m in msgs:
            led.feed(m)
        return led

    led = tally(FRAME, 220000)
    for name, key in (("status code", "status code"),
                      ("authentication algorithm",
                       "authentication algorithm")):
        want = set(defined[key]) if key in defined else set()
        got = set(led.air[name].values) & want if name in led.air else set()
        check.ok(want and got == want,
                 "%s: %d of %d defined members on the air"
                 % (name, len(got), len(want)),
                 "missing %d" % len(want - got))

    deauth = bytearray(FRAME)
    deauth[0] = (12 << 4)
    led = tally(bytes(deauth), 80000)
    want = set(defined["reason code"])
    got = set(led.air["reason code"].values) & want \
        if "reason code" in led.air else set()
    check.ok(got == want,
             "reason code: %d of %d defined members on the air"
             % (len(got), len(want)),
             "missing %d" % len(want - got))

    # The point of the tier, stated as the number it is there to bound.
    check.ok(all(t == "FULL" for t in led.tiers),
             "all of that under FULL, which for a two-octet field is 65536 "
             "cases per field and is why the default is not FULL over the "
             "air (%s)" % sorted(led.tiers))


def check_u8_is_full(root, binary, check):
    """The acceptance: FULL on every u8 domain, no tier needed."""
    print("\nA one-octet field needs no reduction")
    frame = bytes([2, 3, 0, 95, 2]) + bytes([0x55]) * 90
    _, msgs = run(binary, "t-u8", 4000, frame=frame,
                  capacity=len(frame), ftype=EAPOL)
    fm = muts(msgs, "MUT_FIELD")
    u8 = {m["field"] for m in fm if m["width"] == 1}
    check.ok(u8, "the frame has one-octet fields (%s)" % sorted(u8))
    tiers = {m["tier"] for m in fm if m["width"] == 1}
    check.ok(tiers == {"FULL"},
             "every one of them is swept FULL by default, because 256 is a "
             "domain you can finish (%s)" % sorted(tiers))
    for name in sorted(u8):
        vals = {m["after"] for m in fm if m["field"] == name}
        check.ok(vals == set(range(256)),
                 "%s takes all 256 of its values" % name,
                 "got %d" % len(vals))
    wide = {m["tier"] for m in fm if m["width"] == 2}
    check.ok(wide == {"STRIDE"},
             "while a two-octet field defaults to a named reduction instead "
             "(%s)" % sorted(wide))


def check_replay_guard(root, check):
    """A case recorded under one case space must not replay under another."""
    print("\nA recorded case says which case space it came from")
    with tempfile.TemporaryDirectory() as tmp:
        # A binary that announces a case space the record was not written
        # under. The monitor has to stop rather than run it: the same case_id
        # indexes a different frame under each, so it would reproduce
        # something else and read as a flaky crash.
        fake = os.path.join(tmp, "fake")
        with open(fake, "w") as f:
            f.write('#!/bin/sh\n'
                    'echo \'[fuzz] {"msg":"progress","case_id":1,'
                    '"case_max":9,"target":"t","state":"mutating",'
                    '"opset":"v2/7d/FULL/251@0"}\'\n'
                    'sleep 1\n')
        os.chmod(fake, 0o755)
        conf = os.path.join(tmp, "c")
        open(conf, "w").close()

        def attempt(opset):
            rec = os.path.join(tmp, "rec.json")
            with open(rec, "w") as f:
                json.dump({"opset": opset, "replay_env": {"FUZZ_START_T": 1},
                           "case": {}}, f)
            return subprocess.run(
                [sys.executable, os.path.join(root, "monitor_fuzzing.py"),
                 "--hostapd", fake, "--config", conf, "--replay", rec,
                 "--no-ledger", "--quiet"],
                capture_output=True, text=True, cwd=root, timeout=60)

        r = attempt("v2/7d/STRIDE/251@3")
        check.ok(r.returncode == 2 and "case space" in r.stderr,
                 "a record from another case space is refused, not replayed",
                 (r.stderr or r.stdout).strip()[:200])
        r = attempt("v2/7d/FULL/251@0")
        check.ok(r.returncode != 2 or "case space" not in r.stderr,
                 "and a record from this one is not")
        check.ok("FUZZ_START_T=1" in r.stdout,
                 "the replay environment from the record is applied",
                 r.stdout.strip()[:200])


def main():
    root = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else ".")
    check = Check()
    check_table_is_derived(root, check)
    with tempfile.TemporaryDirectory() as tmp:
        binary = build_harness(root, tmp)
        if binary is None:
            return 2
        check_field_domain(root, binary, check)
        check_before_is_the_built_value(root, binary, check)
        check_tiers(root, binary, check)
        check_identity_varies_fastest(root, binary, check)
        check_patterns(root, binary, check)
        check_subtype_selects(root, binary, check)
        check_opset(root, binary, check)
        check_u8_is_full(root, binary, check)
        check_registries(root, binary, check)
    check_replay_guard(root, check)
    print("\n%d of %d checks pass" % (check.passed,
                                      check.passed + check.failed))
    return 1 if check.failed else 0


if __name__ == "__main__":
    sys.exit(main())
