#!/usr/bin/env python3
"""Behavioural checks for the Action-frame hooks (W9).

    python3 verify_action.py /path/to/checkout

Needs no radio, no interface and no root: it compiles a small harness against
the checkout's own fuzz.o and drives fuzz_action_mutate() directly. Build the
checkout with CONFIG_FUZZ=y first.

The claim being established is that ONE hook on each side reaches eight
protocols, and that each of them arrives under its own name.

Two functions -- offchannel_send_action() on the station side and
hapd_drv_send_action() on the AP side -- are the convergence point for over a
hundred call sites. Naming the sites would be a hundred hooks to carry across
every rebase, and would file each case under whichever caller happened to
reach the convergence point rather than under the protocol that parses it. So
the label is read out of the frame: the Action category, the code after it for
the two categories that have a code registry, and the vendor type after that
for the code that says a vendor follows. Which is how the receiver decides
what it is holding.

What is checked here is that the reading is right, that it is the TREE's
reading and not a second copy of it, and that nothing is quietly filed under a
neighbour's name -- which is the failure mode worth worrying about, because a
label that is merely wrong still produces frames, still produces a ledger
column, and says the wrong protocol was reached.
"""

import json
import os
import subprocess
import sys
import tempfile

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
\tsize_t len, base_len;
\tint iterations, i;
\tu8 *base;
\tchar *hex;

\tif (argc < 3)
\t\treturn 2;

\tbase_len = os_strlen(argv[1]) / 2;
\titerations = atoi(argv[2]);

\tbase = os_malloc(base_len ? base_len : 1);
\thex = os_malloc(2 * (base_len + 65536) + 1);
\tif (!base || !hex)
\t\treturn 3;
\tif (hexstr2bin(argv[1], base, base_len) < 0)
\t\treturn 2;

\tfor (i = 0; i < iterations; i++) {
\t\tu8 *out;

\t\tlen = base_len;
\t\tout = fuzz_action_mutate(base, &len);
\t\tif (!out) {
\t\t\tprintf("ret 0 -\\n");
\t\t\tcontinue;
\t\t}
\t\twpa_snprintf_hex(hex, 2 * len + 1, out, len);
\t\tprintf("ret %zu %s\\n", len, hex);
\t\tos_free(out);
\t}

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

    path = os.path.join(workdir, "act.c")
    binary = os.path.join(workdir, "act")
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


def run(binary, body, iterations, env=None):
    e = dict(os.environ)
    for k in list(e):
        if k.startswith("FUZZ_"):
            del e[k]
    e.update(env or {})
    out = subprocess.run([binary, body.hex(), str(iterations + WARMUP)],
                         capture_output=True, text=True, env=e).stdout
    messages, frames = [], []
    for line in out.splitlines():
        if line.startswith(PREFIX):
            try:
                messages.append(json.loads(line[len(PREFIX):]))
            except ValueError:
                messages.append({"msg": "unparsable"})
        elif line.startswith("ret "):
            _, n, hexdata = (line.split(" ") + [""])[:3]
            frames.append((int(n), b"" if hexdata == "-"
                           else bytes.fromhex(hexdata)))
    return frames[WARMUP:], messages


# ---------------------------------------------------------------------------
# Frames are BUILT FROM THE GENERATED TABLE, never typed.
#
# A hand-written "04 09 50 6f 9a 1a" here would be a second copy of the thing
# under test: it would keep passing after the tree renumbered a category, and
# it would pass just as well against a lookup that returned a constant.
# ---------------------------------------------------------------------------

def reg(root):
    sys.path.insert(0, os.path.join(root, "fuzzing", "ledger"))
    import registries as registries_mod
    return registries_mod


def value_of(data, const):
    for members in data.values():
        for val, names in members.items():
            if const in names:
                return val
    return None


def action_frame(root, const, code_const=None, oui_type_const=None,
                 tail=b""):
    """An Action body as the tree would build one, from the tree's constants."""
    m = reg(root)
    data = m.extract(root)
    cat = value_of(data, const)
    assert cat is not None, const
    out = bytes([cat])
    if code_const:
        code = value_of(data, code_const)
        assert code is not None, code_const
        out += bytes([code])
    if oui_type_const:
        oui = None
        vend = m.vendor_types(root)
        for val, names in vend.items():
            if oui_type_const in names:
                oui = val
        assert oui is not None, oui_type_const
        # The OUI itself comes from the same header, as a big-endian 24-bit
        # value, exactly as dpp_alloc_msg() writes it.
        wfa = None
        with open(os.path.join(root, "src", "common",
                               "ieee802_11_defs.h"),
                  encoding="utf-8", errors="replace") as f:
            for line in f:
                mm = m.DEFINE_RE.match(line.rstrip())
                if mm and mm.group(1) == m.VENDOR_OUI:
                    wfa = m._value(mm.group(2))
        assert wfa is not None
        out += bytes([(wfa >> 16) & 0xff, (wfa >> 8) & 0xff, wfa & 0xff,
                      oui])
    return out + tail


def labels(messages):
    return {m.get("target") for m in messages if m.get("msg") == "progress"}


def check_table_is_derived(root, check):
    print("\nThe table is the tree's")
    rc = subprocess.run(
        [sys.executable, os.path.join(root, "fuzzing", "ledger",
                                      "registries.py"), root, "--check"],
        capture_output=True, text=True)
    check.ok(rc.returncode == 0,
             "the generated label table matches the sources",
             rc.stdout.strip()[:300])

    m = reg(root)
    rows = m.action_labels(root)
    names = [r[3] for r in rows]
    check.ok(len(names) == len(set(names)),
             "every label is distinct (%d), so no two protocols share a "
             "ledger column" % len(names),
             str([n for n in names if names.count(n) > 1][:5]))

    # Precedence is the order of the table, so a less specific row must never
    # come before a more specific one for the same category.
    bad = []
    for i, (cat, code, oui, _) in enumerate(rows):
        for cat2, code2, oui2, lab2 in rows[i + 1:]:
            if cat2 != cat:
                continue
            spec = (code is not None) + (oui is not None)
            spec2 = (code2 is not None) + (oui2 is not None)
            if spec2 > spec:
                bad.append(lab2)
    check.ok(not bad,
             "and the table is ordered most specific first, so the lookup's "
             "first match is its best one", str(bad[:4]))


def check_labels_come_from_the_frame(root, check, binary):
    print("\nThe label is read out of the frame, not taken from the site")
    cases = [
        # (what it is, category, code, vendor type, the label it must get)
        ("DPP", "WLAN_ACTION_PUBLIC", "WLAN_PA_VENDOR_SPECIFIC",
         "DPP_OUI_TYPE", "act-public-vendor-dpp"),
        ("P2P", "WLAN_ACTION_PUBLIC", "WLAN_PA_VENDOR_SPECIFIC",
         "P2P_OUI_TYPE", "act-public-vendor-p2p"),
        ("NAN", "WLAN_ACTION_PUBLIC", "WLAN_PA_VENDOR_SPECIFIC",
         "NAN_SDF_OUI_TYPE", "act-public-vendor-nan"),
        ("GAS", "WLAN_ACTION_PUBLIC", "WLAN_PA_GAS_INITIAL_REQ", None,
         "act-public-gas-initial-req"),
        ("RRM", "WLAN_ACTION_RADIO_MEASUREMENT", None, None,
         "act-radio-measurement"),
        ("robust AV", "WLAN_ACTION_ROBUST_AV_STREAMING", None, None,
         "act-robust-av-streaming"),
        ("WNM", "WLAN_ACTION_WNM", None, None, "act-wnm"),
        ("TDLS", "WLAN_ACTION_TDLS", None, None, "act-tdls"),
    ]
    seen = {}
    for what, cat, code, oui, want in cases:
        body = action_frame(root, cat, code, oui, tail=bytes(16))
        _, msgs = run(binary, body, 2)
        got = labels(msgs)
        check.ok(got == {want},
                 "%-10s -> %s" % (what, want), "got %s" % sorted(got))
        seen[what] = sorted(got)[0] if got else None

    check.ok(len(set(seen.values())) == len(seen),
             "eight protocols, eight labels, one hook (%d distinct)"
             % len(set(seen.values())),
             str(seen))


def check_unknown_is_its_own_label(root, check, binary):
    print("\nA category this engine cannot name is not filed under one it can")
    m = reg(root)
    data = m.extract(root)
    defined = set(data["action category"])
    spare = next(v for v in range(256) if v not in defined)
    _, msgs = run(binary, bytes([spare]) + bytes(8), 2)
    got = labels(msgs)
    check.ok(got == {"act-other"},
             "an undefined category %d gets its own label (%s)"
             % (spare, sorted(got)))

    # And a defined category whose code registry has no row for this code
    # falls back to the CATEGORY, not to another category's code.
    pub = value_of(data, "WLAN_ACTION_PUBLIC")
    codes = set(data["public action"])
    spare_code = next(v for v in range(256) if v not in codes)
    _, msgs = run(binary, bytes([pub, spare_code]) + bytes(8), 2)
    got = labels(msgs)
    check.ok(got == {"act-public"},
             "and an unknown code falls back to its category (%s)"
             % sorted(got))


def check_prefix_is_the_chain_offset(root, check, binary):
    print("\nThe offset the label consumed is the only one it claims")
    # A vendor-specific public action frame has a six-octet prefix before
    # anything protocol-specific. Nothing in this engine knows what follows a
    # category -- the tree keys that through a union that says nothing about
    # which member applies -- so the chain walk gets the prefix the LABEL read
    # and refuses whatever it cannot consume exactly from there.
    body = action_frame(root, "WLAN_ACTION_PUBLIC", "WLAN_PA_VENDOR_SPECIFIC",
                        "DPP_OUI_TYPE", tail=bytes([0, 2, 0x41, 0x41]))
    frames, msgs = run(binary, body, 3000)
    elems = [m for m in msgs if m.get("type") == "MUT_ELEM"]
    check.ok(elems, "element cases run on an Action body (%d)" % len(elems))
    check.ok(all(m["at"] >= 6 for m in elems),
             "and none of them lands inside the prefix the label read",
             str(sorted({m["at"] for m in elems})[:6]))

    # A frame whose prefix is followed by something that is NOT a chain gets
    # one insertion point, not a position invented by misreading octets.
    body = action_frame(root, "WLAN_ACTION_PUBLIC", "WLAN_PA_VENDOR_SPECIFIC",
                        "DPP_OUI_TYPE", tail=bytes([0xff, 0xff, 0xff]))
    _, msgs = run(binary, body, 2000)
    elems = [m for m in msgs if m.get("type") == "MUT_ELEM"]
    check.ok(elems and all(m["npos"] == 1 for m in elems),
             "a body that is not a chain gets exactly one insertion point",
             str(sorted({m["npos"] for m in elems})))

    byte = [m for m in msgs if m.get("type") == "MUT_BYTE_XOR"]
    check.ok(byte and all(m.get("hdr") == 0 for m in byte),
             "and no octet is held back: an Action body's first octet is "
             "already one the peer parses",
             str(sorted({m.get("hdr") for m in byte})))
    check.ok(any(m["idx"] == 0 for m in byte),
             "including the category itself, which selects the parser")


def check_frame_kind(check, binary, root):
    print("\nThe messages say what kind of thing was mutated")
    body = action_frame(root, "WLAN_ACTION_RADIO_MEASUREMENT",
                        tail=bytes(12))
    _, msgs = run(binary, body, 300)
    muts = [m for m in msgs if m.get("msg") == "fuzz"]
    check.ok(muts, "mutations are produced (%d)" % len(muts))
    kinds = {m.get("frame") for m in muts}
    check.ok(kinds == {"action"},
             "every one of them says 'action', so a consumer need not infer "
             "the layout from the target's name (%s)" % sorted(kinds))
    types = {m.get("type") for m in muts}
    check.ok(len(types) > 1,
             "across more than one mutation kind (%s)" % sorted(types))


CLAIM_HARNESS = """
#include "utils/includes.h"
#include "utils/common.h"
#include "common/fuzz.h"

/*
 * A frame built, mutated under its own label, then handed to the convergence
 * point below it. That is exactly the shape of the WNM transmit paths, which
 * all call hostapd_drv_send_action() after mutating.
 */
int main(int argc, char *argv[])
{
	u8 buf[64];
	size_t len, n;
	u8 *out;
	int i, claimed = 0, mutated = 0, unclaimed = 0, empty = 0;

	(void) argc;
	(void) argv;

	for (i = 0; i < 40; i++) {
		os_memset(buf, 0, sizeof(buf));
		buf[0] = (u8) atoi(argv[1]);
		len = 32;
		n = apply_mutation_elements("named-hook", FUZZ_TYPE_FRAME_BODY,
					    buf, len, sizeof(buf), len);
		len = n;
		if (!len) {
			empty++;
			continue;
		}
		out = fuzz_action_mutate(buf, &len);
		if (out)
			mutated++;
		else
			claimed++;
		os_free(out);
	}

	for (i = 0; i < 10; i++) {
		os_memset(buf, 0, sizeof(buf));
		/* A different category, so the claimed label is ONLY ever
		 * claimed and the ledger has something to be wrong about. */
		buf[0] = (u8) atoi(argv[2]);
		len = 32;
		out = fuzz_action_mutate(buf, &len);
		if (out)
			unclaimed++;
		os_free(out);
	}

\tprintf("claimed %d mutated %d unclaimed %d empty %d\\n",
	       claimed, mutated, unclaimed, empty);
	return 0;
}
"""


def check_one_frame_one_case(root, check, workdir):
    print("\nOne transmitted frame, one case")
    objdir = os.path.join(root, "build", "hostapd")
    path = os.path.join(workdir, "claim.c")
    binary = os.path.join(workdir, "claim")
    with open(path, "w", encoding="utf-8") as f:
        f.write(CLAIM_HARNESS)
    rc = subprocess.run(
        [os.environ.get("CC", "cc"), "-o", binary, path,
         "-I%s" % os.path.join(root, "src"),
         "-I%s" % os.path.join(root, "src", "utils"), "-DCONFIG_FUZZ"] +
        [os.path.join(objdir, o) for o in OBJECTS],
        capture_output=True, text=True)
    if rc.returncode != 0:
        check.ok(False, "the claim harness compiles",
                 rc.stderr.strip()[:400])
        return

    m = reg(root)
    data = m.extract(root)
    cat = value_of(data, "WLAN_ACTION_WNM")
    other = value_of(data, "WLAN_ACTION_RADIO_MEASUREMENT")
    e = {k: v for k, v in os.environ.items() if not k.startswith("FUZZ_")}
    out = subprocess.run([binary, str(cat), str(other)],
                         capture_output=True, text=True, env=e)
    nums = dict(zip(out.stdout.split()[0::2], out.stdout.split()[1::2]))
    msgs = [json.loads(l[len(PREFIX):]) for l in out.stdout.splitlines()
            if l.startswith(PREFIX)]

    # The convergence point sits BELOW six hooks that already name their
    # frames. Mutating there as well is not a second case: it is one
    # transmitted frame with two cases charged against it, two counters
    # moved, an as-built column that undoes one of two mutations and calls
    # the result what the configuration built, and a repro record that
    # replays something that was never sent.
    check.ok(nums.get("mutated") == "0",
             "a frame a named hook already took is not mutated again at the "
             "convergence point (%s of 40 were)" % nums.get("mutated"),
             out.stdout.strip()[:200])
    passes = 40 - int(nums.get("empty", 0))
    check.ok(nums.get("claimed") == str(passes),
             "all %d of them yield to the label that knew more (%s)"
             % (passes, nums.get("claimed")))
    check.ok(nums.get("unclaimed") == "10",
             "while an Action frame nothing above claimed is still mutated "
             "(%s of 10)" % nums.get("unclaimed"))

    claims = [x for x in msgs if x.get("msg") == "claimed"]
    check.ok(len(claims) == passes,
             "and every yield is reported, so a label that never fires "
             "because something above it always does is not read as a "
             "parser nothing is aimed at (%d of %d)"
             % (len(claims), passes))
    check.ok(claims and all(c.get("by") == "named-hook" for c in claims),
             "naming which hook took it",
             str({c.get("by") for c in claims}))

    # And the ledger says so in words, in the place the confusion would be.
    sys.path.insert(0, os.path.join(root, "fuzzing", "ledger"))
    from ledger import Ledger
    led = Ledger()
    led.feed({"msg": "inventory", "daemon": "hostapd",
              "targets": ["act-wnm"], "stages": [],
              "roster": [{"name": "act-wnm", "guard": None}]})
    for x in msgs:
        led.feed(x)
    lines = []

    def say(*a):
        lines.append(" ".join(str(x) for x in a))

    led._report_targets(say)
    text = "\n".join(lines)
    row = [l for l in lines if l.strip().startswith("act-wnm")]
    check.ok(row and "claimed upstream" in row[0],
             "the ledger reports it as claimed upstream, not as never "
             "reached", str(row[:1]))
    check.ok(any("claimed upstream" in l and "reached" in l for l in lines),
             "and counts it apart in the totals",
             str([l for l in lines if "never reached" in l][:1]))


def check_disabled(check, binary, root):
    print("\nA disabled run changes nothing")
    body = action_frame(root, "WLAN_ACTION_PUBLIC", "WLAN_PA_GAS_INITIAL_REQ",
                        tail=bytes(12))
    frames, msgs = run(binary, body, 20, env={"FUZZ_DISABLE": "1"})
    check.ok(all(n == 0 for n, _ in frames),
             "fuzz_action_mutate() returns NULL, so the caller sends what it "
             "built", str(frames[:3]))
    check.ok(not [m for m in msgs if m.get("msg") == "fuzz"],
             "and nothing is reported")


def check_roster(root, check):
    print("\nEvery label the hook can produce is in the roster")
    sys.path.insert(0, os.path.join(root, "fuzzing", "ledger"))
    import targets as targets_mod
    import registries as registries_mod

    found = targets_mod.extract(root, with_guards=True)
    want = {r[3] for r in registries_mod.action_labels(root)} | {"act-other"}
    missing = sorted(want - set(found))
    check.ok(not missing,
             "the roster names all %d of them, so a run reports them as "
             "absent rather than not at all" % len(want),
             "missing: %s" % missing[:6])

    # Derived labels carry a guard like any other, and it has to be the guard
    # of the SITE: these have no string in the binary to find them by, so a
    # missing guard would make them indistinguishable from never-reached.
    nog = sorted(n for n in want if not found.get(n, {}).get("guard"))
    check.ok(not nog, "each with the build guard of its call site",
             str(nog[:6]))
    derived = sorted(n for n in want if not found.get(n, {}).get("derived"))
    check.ok(not derived,
             "and each marked as read-from-the-frame, so a consumer checking "
             "the table against the binaries looks for the object and not "
             "for a string that is not there", str(derived[:6]))

    # The single-site hooks of W9, which do have a literal.
    for name, where in (("wps-msg", "src/wps/wps.c"),
                        ("sta-tdls", "src/rsn_supp/tdls.c"),
                        ("dpp-tcp", "src/common/dpp_tcp.c")):
        check.ok(name in found and where in found[name]["files"],
                 "%s is hooked, at %s" % (name, where),
                 str(found.get(name)))


def check_overlap_is_known(root, check):
    print("\nWhich hooks sit above the convergence points")
    # The overlap is not hypothetical and it is not static knowledge: it is
    # whichever functions in the tree today both mutate under their own label
    # and then call one of the two convergence points. Finding them here
    # rather than listing them means a seventh WNM frame, or a new hook
    # anywhere above either function, is covered the day it lands.
    import re as _re

    sends = ("hostapd_drv_send_action", "hostapd_drv_send_action_addr3_ap",
             "hostapd_drv_send_action_forced_addr3",
             "offchannel_send_action")
    overlap = []
    for sub in ("src", "wpa_supplicant", "hostapd"):
        for dirpath, _, names in os.walk(os.path.join(root, sub)):
            for n in names:
                if not n.endswith(".c"):
                    continue
                path = os.path.join(dirpath, n)
                with open(path, encoding="utf-8", errors="replace") as f:
                    src = f.read()
                if "apply_mutation" not in src:
                    continue
                for fn in _re.finditer(r"\n(\w[^\n]*\([^;]*?\)\s*\n\{)", src):
                    start = fn.start()
                    end = src.find("\n}", start)
                    body = src[start:end if end > 0 else len(src)]
                    if "apply_mutation" in body and \
                            any(sd in body for sd in sends):
                        overlap.append(
                            os.path.relpath(path, root).replace(os.sep, "/"))
    overlap = sorted(set(overlap))

    check.ok(overlap,
             "there are call sites that mutate and then transmit through a "
             "convergence point (%s)" % ", ".join(overlap),
             "none found: either the hooks moved or this scan did")

    # Those are exactly the frames that would be mutated twice -- two
    # counters moved for one transmitted frame, an as-built column that
    # undoes one of two mutations, and a repro record that replays something
    # that was never sent. The claim is what stops it, and the check that it
    # does is the offline one above; this one is that the overlap exists at
    # all, so that check is testing something real.
    sys.path.insert(0, os.path.join(root, "fuzzing", "ledger"))
    import targets as targets_mod
    found = targets_mod.extract(root)
    above = sorted(n for n, files in found.items()
                   if any(f in overlap for f in files)
                   and not n.startswith("act-"))
    check.ok(above,
             "and %d label(s) sit above them: %s"
             % (len(above), ", ".join(above[:8])),
             str(above))


def main():
    root = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else ".")
    check = Check()
    check_table_is_derived(root, check)
    with tempfile.TemporaryDirectory() as tmp:
        binary = build(root, tmp)
        if not binary:
            return 2
        check_labels_come_from_the_frame(root, check, binary)
        check_unknown_is_its_own_label(root, check, binary)
        check_prefix_is_the_chain_offset(root, check, binary)
        check_frame_kind(check, binary, root)
        check_disabled(check, binary, root)
        check_one_frame_one_case(root, check, tmp)
    check_roster(root, check)
    check_overlap_is_known(root, check)
    print("\n%d of %d checks pass" % (check.passed,
                                      check.passed + check.failed))
    return 1 if check.failed else 0


if __name__ == "__main__":
    sys.exit(main())
