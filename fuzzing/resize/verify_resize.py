#!/usr/bin/env python3
"""Behavioural checks for the resize contract.

    python3 verify_resize.py /path/to/checkout

Needs no radio, no interface and no root: it compiles a small harness against
the checkout's own fuzz.o and drives the hook directly. Build the checkout with
CONFIG_FUZZ=y first.

Two things are being established here and they pull in opposite directions.

The first is that the frame's length is now a domain -- that a sweep walks
every length in 0..capacity, that it reaches them early rather than after the
octet domain is exhausted, and that it never returns a length the caller cannot
hold. A hook that could return more than capacity would overrun a buffer inside
hostapd, which is a crash this harness would have caused and then reported as a
finding.

The second is that NOTHING ELSE MOVED. apply_mutation() is the same function it
was: same case_max, same frame for the same case. Every call site in the tree
uses it, so a change there would silently renumber a case space that live runs
and recorded crashes are indexed against. That is checked by running both entry
points over the same case space and comparing them case for case.
"""

import json
import os
import subprocess
import sys
import tempfile

PREFIX = "[fuzz] "
FILL = 0x41

# A target's first FUZZ_FIRST_CASE_ID frames go out unmutated, so an iteration
# of the harness is not a case until the warm-up is over. Every count below is
# a count of CASES, so the driver runs the warm-up and drops it; getting this
# wrong makes a correct sweep look as though it is missing its last few cases.
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
\tint iterations, i, use_resize;
\tenum fuzz_frame_type type;
\tu8 *frame;
\tchar *hex;

\tif (argc < 7)
\t\treturn 2;

\tlen = (size_t) atoi(argv[2]);
\tcapacity = (size_t) atoi(argv[3]);
\titerations = atoi(argv[4]);
\ttype = os_strcmp(argv[5], "eapol") == 0 ? FUZZ_TYPE_IEEE802_1X_HDR :
\t\tFUZZ_TYPE_IEEE80211_MGMT;
\tuse_resize = os_strcmp(argv[6], "resize") == 0;

\tframe = os_malloc(capacity > len ? capacity : (len ? len : 1));
\thex = os_malloc(2 * (capacity > len ? capacity : len) + 1);
\tif (!frame || !hex)
\t\treturn 3;

\tfor (i = 0; i < iterations; i++) {
\t\tsize_t out;

\t\tos_memset(frame, 0x41, capacity > len ? capacity : len);
\t\tif (use_resize)
\t\t\tout = apply_mutation_resize(target, type, frame, len,
\t\t\t\t\t\t    capacity);
\t\telse {
\t\t\tapply_mutation(target, type, frame, len);
\t\t\tout = len;
\t\t}
\t\twpa_snprintf_hex(hex, 2 * out + 1, frame, out);
\t\tprintf("ret %zu %s\\n", out, hex);
\t}

\tos_free(frame);
\tos_free(hex);

\treturn 0;
}
"""


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

    path = os.path.join(workdir, "resize.c")
    binary = os.path.join(workdir, "resize")
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


def run(binary, target, length, capacity, iterations, resize=True,
        ftype="mgmt", env=None):
    """([(returned length, frame bytes)], [messages])"""
    e = dict(os.environ)
    for k in list(e):
        if k.startswith("FUZZ_"):
            del e[k]
    e["FUZZ_START_CASE"] = e.get("FUZZ_START_CASE", "0")
    e.update(env or {})
    out = subprocess.run(
        [binary, target, str(length), str(capacity),
         str(iterations + WARMUP), ftype, "resize" if resize else "plain"],
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


HDR = 24           # the 802.11 header the hook keeps out of the sweep
LEN = 40
CAP = 60


def case_max(messages):
    for m in messages:
        if m.get("msg") == "progress":
            return m.get("case_max")
    return None


def check_identical(binary, check):
    """apply_mutation() has not moved."""
    print("\nNothing else moved")
    n = 400
    plain, pmsgs = run(binary, "t-plain", LEN, LEN, n, resize=False)
    same, smsgs = run(binary, "t-same", LEN, LEN, n, resize=True)

    check.ok(plain and plain == same,
             "apply_mutation() and apply_mutation_resize() with capacity == "
             "len produce the identical frame for every one of %d cases" % n,
             "first difference at case %s" % next(
                 (i for i, (a, b) in enumerate(zip(plain, same)) if a != b),
                 "none"))
    check.ok(case_max(pmsgs) == case_max(smsgs) ==
             (LEN - HDR) * 255,
             "and the identical case space (%s vs %s, expected %d)"
             % (case_max(pmsgs), case_max(smsgs), (LEN - HDR) * 255))
    check.ok(all(r == LEN for r, _ in same),
             "capacity == len means the length never moves")


def check_case_space(binary, check):
    """The length domain is a domain: whole, and counted once."""
    print("\nThe length domain")
    _, msgs = run(binary, "t-space", LEN, CAP, 1, resize=True)
    byte_max = (LEN - HDR) * 255
    check.ok(case_max(msgs) == byte_max + CAP,
             "case_max is the octet domain plus the length domain "
             "(%s, expected %d + %d)" % (case_max(msgs), byte_max, CAP))

    total = byte_max + CAP
    frames, _ = run(binary, "t-walk", LEN, CAP, total, resize=True)
    check.ok(len(frames) == total, "the whole space runs (%d)" % len(frames))

    lengths = [r for r, _ in frames if r != LEN]
    check.ok(sorted(lengths) == sorted(set(lengths)),
             "no length is swept twice (%d cases, %d distinct)"
             % (len(lengths), len(set(lengths))))
    expected = set(range(0, CAP + 1)) - {LEN}
    check.ok(set(lengths) == expected,
             "every length in 0..%d except the frame's own is swept (%d of "
             "%d)" % (CAP, len(set(lengths)), len(expected)),
             "missing=%s extra=%s" % (sorted(expected - set(lengths))[:6],
                                      sorted(set(lengths) - expected)[:6]))

    byte_cases = [f for r, f in frames if r == LEN]
    check.ok(len(byte_cases) == byte_max,
             "and the octet domain still has all its cases (%d of %d)"
             % (len(byte_cases), byte_max))


def check_interleave(binary, check):
    """The length cases are reached by a run that does not finish."""
    print("\nReached, not merely present")
    early = 60
    frames, _ = run(binary, "t-early", LEN, CAP, early, resize=True)
    moved = [r for r, _ in frames if r != LEN]
    check.ok(moved,
             "a run of %d cases -- far short of the %d the octet domain alone "
             "needs -- still moves the length %d times"
             % (early, (LEN - HDR) * 255, len(moved)))
    check.ok(len(moved) >= early // 2 - 1,
             "half the early cases are length cases, so neither domain waits "
             "for the other (%d of %d)" % (len(moved), early))


def check_bounds(binary, check):
    """Nothing is returned that the caller cannot hold."""
    print("\nThe contract with the caller")
    total = (LEN - HDR) * 255 + CAP
    frames, _ = run(binary, "t-bound", LEN, CAP, total, resize=True)
    over = [r for r, _ in frames if r > CAP]
    check.ok(not over,
             "no case returns a length beyond capacity (%d checked)"
             % len(frames), str(over[:5]))
    check.ok(all(len(f) == r for r, f in frames),
             "the frame emitted is exactly the length returned")

    frames, _ = run(binary, "t-under", LEN, LEN - 10, 50, resize=True)
    check.ok(all(r == LEN for r, _ in frames),
             "a capacity below the frame's own length is treated as no "
             "headroom rather than as a licence to truncate",
             str(sorted({r for r, _ in frames})))


def check_fill(binary, check):
    """What the new octets say is not this domain's business."""
    print("\nGrowth is filled with a constant")
    total = (LEN - HDR) * 255 + CAP
    frames, _ = run(binary, "t-fill", LEN, CAP, total, resize=True)
    grown = [(r, f) for r, f in frames if r > LEN]
    check.ok(grown, "some cases grow the frame (%d)" % len(grown))
    bad = [r for r, f in grown if any(b != 0 for b in f[LEN:])]
    check.ok(not bad,
             "and the octets past the original length are a constant, so the "
             "length is swept independently of what they say", str(bad[:5]))
    unchanged = [r for r, f in grown if f[:LEN] != bytes([FILL]) * LEN]
    check.ok(not unchanged,
             "a length case changes only the length, never a byte of the "
             "frame as built", str(unchanged[:5]))

    short = [(r, f) for r, f in frames if r < LEN]
    check.ok(short, "some cases truncate the frame (%d)" % len(short))
    check.ok(all(f == bytes([FILL]) * r for r, f in short),
             "and a truncated frame is a prefix of the one built")


def check_message(binary, check):
    """A consumer can tell a length case from an octet case."""
    print("\nThe message")
    total = (LEN - HDR) * 255 + CAP
    _, msgs = run(binary, "t-msg", LEN, CAP, total, resize=True)
    fuzz = [m for m in msgs if m.get("msg") == "fuzz"]
    lenmsgs = [m for m in fuzz if m.get("type") == "MUT_LEN"]
    bytemsgs = [m for m in fuzz if m.get("type") == "MUT_BYTE_XOR"]
    check.ok(len(lenmsgs) == CAP,
             "one MUT_LEN message per length case (%d of %d)"
             % (len(lenmsgs), CAP))
    check.ok(len(bytemsgs) == (LEN - HDR) * 255,
             "and the octet cases still report MUT_BYTE_XOR (%d)"
             % len(bytemsgs))
    check.ok(all(m.get("was") == LEN for m in lenmsgs),
             "each names the length the frame was built at")
    check.ok({m.get("len") for m in lenmsgs} ==
             set(range(0, CAP + 1)) - {LEN},
             "and the length it was sent at, covering the domain")
    check.ok(all("hdr" in m and "target" in m and "order" in m
                 for m in lenmsgs),
             "and carries hdr, target and order like every other case")
    check.ok(all(len(bytes.fromhex(m.get("data", ""))) == m.get("len")
                 for m in lenmsgs if "data" in m),
             "the hexdump is the frame as sent, at the new length")


def check_disabled(binary, check):
    print("\nFUZZ_DISABLE still means disabled")
    frames, msgs = run(binary, "t-off", LEN, CAP, 20, resize=True,
                       env={"FUZZ_DISABLE": "1"})
    check.ok(all(r == LEN for r, _ in frames),
             "the length never moves under FUZZ_DISABLE=1",
             str(sorted({r for r, _ in frames})))
    check.ok(all(f == bytes([FILL]) * LEN for _, f in frames),
             "and no octet moves either")
    check.ok(not msgs, "and nothing is emitted")


def field_cases(root, frame, length):
    """What the field domains contribute to a frame of this kind and length.

    Read out of the generated table rather than written down, so this does not
    have to be edited every time upstream moves a field -- which is the same
    reason the table is generated in the first place.
    """
    sys.path.insert(0, os.path.join(root, "fuzzing", "ledger"))
    import fields as fields_mod

    total = 0
    for f_frame, _, _, off, width, kind, _ in fields_mod.build(root):
        if f_frame != frame or off + width > length:
            continue
        if kind == "opaque":
            total += 6                      # FUZZ_PATTERN_COUNT
            continue
        domain = 1 << (8 * width)
        total += domain if domain <= 256 else 8 + -(-domain // 251)
    return total


def check_eapol(root, binary, check):
    """A frame type with no skipped header still works."""
    print("\nA frame with no header to skip")
    byte_max = LEN * 255
    fields = field_cases(root, "eapol", LEN)
    want = byte_max + CAP + fields
    _, msgs = run(binary, "t-eapol", LEN, CAP, 1, resize=True, ftype="eapol")
    check.ok(case_max(msgs) == want,
             "an EAPOL frame's case space is the whole frame, the length "
             "domain and its named fields (%s, expected %d = %d + %d + %d)"
             % (case_max(msgs), want, byte_max, CAP, fields))
    check.ok(fields > 0,
             "and the field domains are not empty for it (%d cases)" % fields)


def main():
    root = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else ".")
    check = Check()
    with tempfile.TemporaryDirectory() as tmp:
        binary = build(root, tmp)
        if not binary:
            return 2
        for fn in (check_identical, check_case_space, check_interleave,
                   check_bounds, check_fill, check_message, check_disabled):
            fn(binary, check)
        check_eapol(root, binary, check)
    print("\n%d of %d checks pass" % (check.passed,
                                      check.passed + check.failed))
    return 1 if check.failed else 0


if __name__ == "__main__":
    sys.exit(main())
