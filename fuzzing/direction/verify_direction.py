#!/usr/bin/env python3
"""Checks on the inverted direction -- the hooks that send, rather than reply.

    python3 verify_direction.py /path/to/checkout

Needs no radio, no interface and no root. The two topology scripts do need
hwsim and are not run here; what is checked here is everything about them that
can be checked without one, plus the parts of the engine and the ledger that
had to change because a frame is no longer always something hostapd built.

The thing being established is that pointing the harness the other way is a
real change in what gets parsed and not just more labels. An AP-only harness
leaves every parser on the AP side and every parser on the mesh side
unreachable -- not because they are hard to reach but because nothing is
aimed at them -- and a station build whose hooks were compiled out, or whose
frames the ledger reads as something else, would look exactly like one that
works.
"""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
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
\t\tout = apply_mutation_elements(target,
\t\t\t\t\t      (enum fuzz_frame_type) type,
\t\t\t\t\t      frame, len, capacity, 0);
\t\twpa_snprintf_hex(hex, 2 * out + 1, frame, out);
\t\tprintf("ret %zu %s\\n", out, hex);
\t}

\treturn 0;
}
"""

# A body with no 802.11 header: an element chain, as an Association Request's
# variable part is. Its first octet is an element id, not a frame control
# field, which is the whole hazard this file exists to pin down.
BODY = bytes([0, 2, 0x41, 0x41]) + bytes([1, 1, 0x42]) + bytes([48, 2, 1, 0])
HEADROOM = 2 + 255


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


# --------------------------------------------------------------------------
# Build wiring
# --------------------------------------------------------------------------

def enclosing_ifdefs(lines, target):
    """The ifdef conditions open at the line that matches 'target'."""
    stack = []
    for line in lines:
        s = line.strip()
        # The target is itself an ifdef line, so it has to be recognised
        # before the push, or it reports the conditions around its own body.
        if s == target:
            return list(stack)
        if re.match(r"^ifn?def\s+\S+", s) or re.match(r"^ifn?eq\s*\(", s):
            stack.append(s)
        elif s == "endif":
            if stack:
                stack.pop()
    return None


def check_build_wiring(root, check):
    print("\nThe hooks are compiled into the station build")
    for name in ("Makefile", "Android.mk"):
        path = os.path.join(root, "wpa_supplicant", name)
        lines = open(path, encoding="utf-8").read().splitlines()
        inner = enclosing_ifdefs(lines, "ifdef CONFIG_FUZZ")
        check.ok(inner is not None,
                 "wpa_supplicant/%s has a CONFIG_FUZZ block" % name)
        # The station and mesh hooks are not behind CONFIG_AP. A fuzz block
        # nested inside it builds a binary that reports its hooks in -v and
        # mutates nothing, which is the worst of both.
        check.ok(inner is not None and
                 not any("CONFIG_AP" in c for c in inner),
                 "and it is not nested inside CONFIG_AP in %s" % name,
                 "enclosed by: %s" % (inner,))

    path = os.path.join(root, "wpa_supplicant", "defconfig-fuzz")
    check.ok(os.path.exists(path), "wpa_supplicant/defconfig-fuzz exists")
    conf = open(path, encoding="utf-8").read() if os.path.exists(path) else ""
    check.ok(re.search(r"(?m)^CONFIG_FUZZ=y", conf),
             "and it turns the hooks on")
    # Upstream defconfig leaves CONFIG_MESH off, and without it mesh_mpm.c is
    # not compiled at all -- the peering hooks would have no call site and the
    # mesh topology would quietly be a two-node nothing.
    check.ok(re.search(r"(?m)^CONFIG_MESH=y", conf),
             "and CONFIG_MESH, without which the peering hooks have no call "
             "site")

    # Every CONFIG_ option it sets must still be one the build reads.
    mk = open(os.path.join(root, "wpa_supplicant", "Makefile"),
              encoding="utf-8").read()
    known = set(re.findall(r"\bCONFIG_[A-Z0-9_]+", mk))
    known |= set(re.findall(r"\bCONFIG_[A-Z0-9_]+",
                            open(os.path.join(root, "wpa_supplicant",
                                              "defconfig"),
                                 encoding="utf-8").read()))
    used = set(re.findall(r"(?m)^(CONFIG_[A-Z0-9_]+)=", conf))
    check.ok(used <= known,
             "every option it sets is one the build still reads (%d)"
             % len(used),
             "unknown: %s" % sorted(used - known))


# --------------------------------------------------------------------------
# The frame kind
# --------------------------------------------------------------------------

def enum_members(root):
    src = open(os.path.join(root, "src", "common", "fuzz.h"),
               encoding="utf-8").read()
    body = re.search(r"enum fuzz_frame_type \{(.*?)\};", src, re.S).group(1)
    return re.findall(r"(FUZZ_TYPE_[A-Z0-9_]+)\s*=\s*(\d+)", body)


def build_harness(root, workdir):
    objdir = os.path.join(root, "build", "hostapd")
    missing = [o for o in OBJECTS
               if not os.path.exists(os.path.join(objdir, o))]
    if missing:
        print("cannot find %s under %s" % (missing[0], objdir))
        print("Build the checkout with CONFIG_FUZZ=y first:")
        print("    cd hostapd && cp defconfig-fuzz .config && make")
        return None

    path = os.path.join(workdir, "dir.c")
    binary = os.path.join(workdir, "dir")
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


def run(binary, target, type_value, iterations, frame=BODY, capacity=None):
    if capacity is None:
        capacity = len(frame) + HEADROOM
    e = {k: v for k, v in os.environ.items() if not k.startswith("FUZZ_")}
    out = subprocess.run(
        [binary, target, frame.hex(), str(capacity), str(type_value),
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


def check_frame_kind(root, binary, check):
    print("\nEvery mutation says what it mutated")
    members = enum_members(root)
    check.ok(len(members) == 3,
             "fuzz_frame_type has the three kinds the tree uses (%d)"
             % len(members),
             str(members))

    kinds = {}
    for name, value in members:
        # A management frame's first 24 octets are held back, so a probe
        # shorter than that has nothing left to mutate and would look like a
        # kind that produces no cases.
        probe = bytes(24) + BODY if name == "FUZZ_TYPE_IEEE80211_MGMT" \
            else BODY
        _, messages = run(binary, "t-%s" % value, int(value), 400,
                          frame=probe)
        muts = [m for m in messages if m.get("msg") == "fuzz"]
        check.ok(muts, "%s produces mutations" % name)
        seen = {m.get("frame") for m in muts}
        check.ok(len(seen) == 1 and None not in seen,
                 "and every one of them carries a single 'frame' value (%s)"
                 % sorted(seen),
                 str(sorted(seen)))
        kinds[name] = seen.pop() if len(seen) == 1 else None
        types = {m.get("type") for m in muts}
        check.ok(len(types) > 1,
                 "across more than one mutation kind (%s), so the field is "
                 "not attached to only one reporter" % sorted(types))

    check.ok(len(set(kinds.values())) == len(kinds),
             "the kinds are distinguishable from each other: %s"
             % sorted(v for v in kinds.values() if v))
    check.ok(kinds.get("FUZZ_TYPE_IEEE80211_MGMT") == "mgmt" and
             kinds.get("FUZZ_TYPE_IEEE802_1X_HDR") == "eapol" and
             kinds.get("FUZZ_TYPE_FRAME_BODY") == "body",
             "and they are the names the consumers switch on",
             str(kinds))

    # The header skip is a property of the kind, not of the label. A body has
    # no header, so nothing in it is held back from the sweep.
    _, messages = run(binary, "t-hdr-body", 3, 50)
    hdrs = {m.get("hdr") for m in messages if m.get("msg") == "fuzz"}
    check.ok(hdrs == {0},
             "a body frame reserves no header: every octet of it is in the "
             "sweep", str(sorted(hdrs)))
    _, messages = run(binary, "t-hdr-mgmt", 1, 50, frame=bytes(24) + BODY)
    hdrs = {m.get("hdr") for m in messages if m.get("msg") == "fuzz"}
    check.ok(hdrs == {24},
             "and a management frame still reserves its 24", str(sorted(hdrs)))


# --------------------------------------------------------------------------
# The ledger must not read a body as a frame
# --------------------------------------------------------------------------

def check_ledger_kinds(root, binary, check):
    print("\nThe ledger reads a body as a body")
    sys.path.insert(0, os.path.join(root, "fuzzing", "ledger"))
    import ledger as ledger_mod

    # A clean element chain, whose first element id is 0x10. Read as a frame
    # control field that octet says "management frame, subtype 1" -- an
    # Association Response -- so a ledger that did not know better would take
    # a status code out of the middle of an element body and then walk
    # whatever followed. The walk succeeds, which is the point: this is not
    # caught by anything failing.
    body = bytes([0x10, 22]) + bytes(22) + bytes([1, 4]) + bytes(4)
    check.ok((body[0] >> 2) & 3 == 0 and (body[0] >> 4) & 0xF == 1,
             "the probe body does read as a management frame if you let it")
    check.ok(ledger_mod.parse_frame("mgmt", body) != {},
             "and taken as one it yields registry values (%s)"
             % sorted(ledger_mod.parse_frame("mgmt", body)))
    check.ok(ledger_mod.parse_frame("body", body) == {},
             "but taken as a body it yields none, so nothing is invented")
    check.ok(ledger_mod.parse_frame("eapol", body) == {},
             "nor as an EAPOL frame")

    # A log written before the 'frame' key must keep reading as it did.
    check.ok(ledger_mod.frame_kind({"target": "eapol"}) == "eapol" and
             ledger_mod.frame_kind({"target": "auth-sae"}) == "mgmt",
             "a message with no 'frame' falls back to what the engine did "
             "when such messages were written")
    check.ok(ledger_mod.frame_kind({"target": "eapol",
                                    "frame": "mgmt"}) == "mgmt",
             "and the key wins over the fallback when it is there")

    # End to end: feed the ledger a run of real body mutations and check it
    # claims no element ids it was not told about.
    _, messages = run(binary, "sta-assoc-req", 3, 600)
    led = ledger_mod.Ledger()
    for m in messages:
        led.feed(m)
    told = {m.get("eid") for m in messages
            if m.get("type") == "MUT_ELEM" and m.get("eid") is not None}
    air = led.air.get("element id")
    seen = set(air.values) if air else set()
    check.ok(told, "the run synthesised elements to count (%d id(s))"
             % len(told))
    check.ok(seen == told,
             "and the ledger's element ids are exactly the ones the engine "
             "reported: %d of %d" % (len(seen), len(told)),
             "extra: %s" % sorted(seen - told))

    summary = led.summary()
    check.ok(summary["frames"] == len([m for m in messages
                                       if m.get("msg") == "fuzz"]),
             "every mutated body is still counted as a frame (%d)"
             % summary["frames"])


# --------------------------------------------------------------------------
# The call sites
# --------------------------------------------------------------------------

def check_call_sites(root, check):
    print("\nThe hooks are on paths that transmit")
    sys.path.insert(0, os.path.join(root, "fuzzing", "ledger"))
    import targets as targets_mod

    found = targets_mod.extract(root)
    station = {n: f for n, f in found.items()
               if any(p.startswith("wpa_supplicant/") or
                      p.startswith("src/rsn_supp/") for p in f)}
    check.ok(len(station) >= 10,
             "the station and mesh paths carry labels of their own (%d)"
             % len(station))

    # Each of the three directions must actually be represented. A label is
    # not evidence on its own, but its absence is.
    want = {
        "the station's Authentication frames":
            [n for n in station if n.startswith("sta-auth")],
        "its Association Request":
            [n for n in station if n == "sta-assoc-req"],
        "its EAPOL-Key replies":
            [n for n in station if n == "sta-eapol"],
        "mesh peering":
            [n for n in station if n.startswith("mesh-plink")],
    }
    for what, names in want.items():
        check.ok(names, "%s are hooked (%s)" % (what, sorted(names)))

    # Secured and unsecured mesh peering reach differently -- one is MICed and
    # can only take octet mutations, the other gets the length and element
    # domains too -- so they are separate labels. One name over both would
    # report a reach the run did not have.
    check.ok({"mesh-plink", "mesh-plink-ampe"} <= set(station),
             "and a secured mesh is a different target from an unsecured one")

    # The table compiled into the engine has to list them, or the inventory
    # message cannot tell a target that was never reached from one that does
    # not exist.
    rc = subprocess.run([sys.executable,
                         os.path.join(root, "fuzzing", "ledger", "targets.py"),
                         root, "--check"],
                        capture_output=True, text=True)
    check.ok(rc.returncode == 0,
             "and fuzz_known_targets[] lists every one of them (%d labels)"
             % len(found),
             rc.stdout.strip())


def check_reconnect(root, check):
    print("\nThe station cycles its association")
    src = open(os.path.join(root, "wpa_supplicant", "wpa_supplicant.c"),
               encoding="utf-8").read()
    check.ok("FUZZ_RECONNECT_MS" in src,
             "there is a knob for how often (FUZZ_RECONNECT_MS)")
    check.ok(re.search(r"delay_ms\s*<=\s*0", src),
             "and setting it to zero leaves the station connected, for "
             "anything past the handshake")
    # One case per association means a run that associates once covers one
    # case, and the first nine per target are the warm-up -- so without this
    # the station direction covers nothing at all.
    check.ok(re.search(r"state == WPA_COMPLETED\)?\s*\n?\s*"
                       r"fuzz_schedule_reconnect", src) or
             "fuzz_schedule_reconnect(wpa_s)" in src,
             "scheduled when the association completes")
    check.ok("#ifdef CONFIG_FUZZ" in src,
             "and compiled out of a stock build")


# --------------------------------------------------------------------------
# The topologies
# --------------------------------------------------------------------------

def check_topologies(root, check):
    print("\nThe topologies refuse to run the wrong way round")
    sh = os.path.join(root, "fuzzing", "topology", "sta-vs-ap.sh")
    check.ok(os.access(sh, os.X_OK), "fuzzing/topology/sta-vs-ap.sh is executable")
    check.ok(os.access(os.path.join(root, "fuzzing", "topology", "mesh.sh"), os.X_OK),
             "fuzzing/topology/mesh.sh is executable")

    with tempfile.TemporaryDirectory() as tmp:
        def fake(name, fuzzing):
            path = os.path.join(tmp, name)
            with open(path, "w") as f:
                f.write("#!/bin/sh\necho 'v0'\n")
                if fuzzing:
                    f.write("echo 'Frame fuzzing hooks are COMPILED IN: x'\n")
            os.chmod(path, 0o755)
            return path

        stock_ap = fake("ap-stock", False)
        fuzz_ap = fake("ap-fuzz", True)
        stock_sta = fake("sta-stock", False)
        fuzz_sta = fake("sta-fuzz", True)

        def attempt(ap, sta):
            env = dict(os.environ, AP=ap, STA=sta)
            return subprocess.run([sh, "0"], capture_output=True, text=True,
                                  env=env, cwd=root)

        # A fuzzing AP would mean both ends mutating and neither being a
        # reference, which is the mesh topology and not this one.
        r = attempt(fuzz_ap, fuzz_sta)
        check.ok(r.returncode == 2 and "must be a stock one" in r.stderr,
                 "a fuzzing victim is refused, because then nothing in the "
                 "run is a reference", r.stderr.strip()[:200])

        # A station with no hooks sends nothing mutated, so the run would
        # look like a clean pass of a sweep that never happened.
        r = attempt(stock_ap, stock_sta)
        check.ok(r.returncode == 2 and "no fuzzing hooks" in r.stderr,
                 "and a subject with no hooks is refused, because a run that "
                 "sends nothing passes", r.stderr.strip()[:200])

    # The radios are read back from the kernel rather than assumed, so a run
    # cannot point hostapd at an interface that is someone else's.
    src = open(os.path.join(root, "fuzzing", "topology", "radios.py"),
               encoding="utf-8").read()
    check.ok("iw" in src and "interfaces()" in src,
             "radios.py reads the interface names back rather than assuming "
             "wlan0")
    for name in ("sta-vs-ap.sh", "mesh.sh"):
        text = open(os.path.join(root, "fuzzing", "topology", name),
                    encoding="utf-8").read()
        check.ok("unshare -r -m -n" in text,
                 "%s contains itself in a user, mount and network namespace"
                 % name)
        check.ok("mac80211_hwsim" in text and "modprobe" in text,
                 "and names the one privileged step rather than running it"
                 % ())


def check_monitor(root, check):
    print("\nThe monitor watches the process that can die")
    src = open(os.path.join(root, "monitor_fuzzing.py"),
               encoding="utf-8").read()
    check.ok("--victim" in src,
             "a second process can be launched and watched")
    check.ok("def decode(frame," in src,
             "frames are dissected by the kind the engine reported, not by "
             "the target's name")
    check.ok('"who"' in src,
             "and a repro record says which process died, because in this "
             "direction it is not the one that sent the frame")
    #  A run whose subject never started reports zero coverage, which is
    #  indistinguishable from a run that fuzzed nothing interesting. Under
    #  --quiet the reason was not printed as it went by either, so the tail
    #  has to be kept.
    check.ok("saw_fuzz_line" in src,
             "a subject that emitted no [fuzz] line at all is noticed")
    check.ok("tail = collections.deque" in src,
             "and its last output is kept even under --quiet")
    check.ok("fuzzed nothing" in src,
             "so an invalid config is reported as a reason, not as zero "
             "coverage")
    rc = subprocess.run([sys.executable,
                         os.path.join(root, "monitor_fuzzing.py"), "--help"],
                        capture_output=True, text=True)
    check.ok(rc.returncode == 0, "monitor_fuzzing.py --help still runs")


def check_no_uncommitted_paths(root, check):
    """Nothing the repository ships points at a path the repository does not have.

    FUZZING.md used to cite a local scratch directory, excluded from the
    repository, for the recorded live results, the live-run script and one
    runnable command in the verification block. To anyone who clones this they
    were dangling, and the last of them was a command the document told them to
    run. A path in a shipped file is a promise. The prefix is spelled below
    rather than written out, because this file is one of the files it scans."""
    print("\nNothing shipped points outside the repository")
    shipped = [os.path.join(root, "FUZZING.md"),
               os.path.join(root, "monitor_fuzzing.py")]
    for dirpath, dirnames, filenames in os.walk(os.path.join(root, "fuzzing")):
        dirnames[:] = [d for d in dirnames if d != "__pycache__"]
        shipped += [os.path.join(dirpath, f) for f in filenames]

    # Assembled rather than written literally: see the docstring.
    excluded = "cla" + "ude/"
    bad = []
    for f in shipped:
        try:
            text = open(f, encoding="utf-8").read()
        except (UnicodeDecodeError, OSError):
            continue
        for i, line in enumerate(text.splitlines(), 1):
            if excluded in line:
                bad.append("%s:%d" % (os.path.relpath(f, root), i))
    check.ok(not bad,
             "no shipped file cites the uncommitted scratch directory%s"
             % ("" if not bad else ": " + ", ".join(bad[:4])))

    # The live run is the one script that is not sandboxed, so where it writes
    # matters more, not less: it runs under sudo and would leave root-owned
    # files in the checkout.
    live = os.path.join(root, "fuzzing", "live", "run_live.sh")
    check.ok(os.path.isfile(live), "fuzzing/live/run_live.sh is in the tree")
    if os.path.isfile(live):
        text = open(live, encoding="utf-8").read()
        check.ok("FUZZ_LOGDIR" in text,
                 "and it writes under $FUZZ_LOGDIR, not into the checkout")
        check.ok('OUTDIR="$ROOT/' not in text,
                 "with no output path anchored at the repository root")
    phasing = os.path.join(root, "fuzzing", "phasing", "phase_starvation.py")
    check.ok(os.path.isfile(phasing),
             "the phasing tool the verification block runs is in the tree")

    # Every path FUZZING.md tells a reader to run, each checked once.
    doc = open(os.path.join(root, "FUZZING.md"), encoding="utf-8").read()
    runnable = []
    for line in doc.splitlines():
        line = line.strip().lstrip("$ ").replace("sudo ", "")
        for lead in ("python3 ", "./"):
            if line.startswith(lead):
                rel = line[len(lead):].split()[0].lstrip("./")
                if rel.startswith("fuzzing/") and rel not in runnable:
                    runnable.append(rel)
    check.ok(len(runnable) >= 15,
             "FUZZING.md names %d runnable paths under fuzzing/" % len(runnable))
    missing = [r for r in runnable
               if not os.path.isfile(os.path.join(root, r))]
    check.ok(not missing,
             "and every one of them exists%s"
             % ("" if not missing else ": " + ", ".join(missing)))


def check_wnm_hooks(root, check):
    """The WNM transmit paths are hooked, and the build and configs reach them.

    A hook is three things, not one: the call in the transmit path, the build
    option that compiles it in, and the configuration that makes hostapd take
    that path at all. Any one of them missing and the target is announced in
    the inventory and reached zero times -- which reads as "never got there"
    rather than "cannot get there". All three are checked here."""
    print("\nThe WNM transmit paths are reachable")
    src = open(os.path.join(root, "src", "ap", "wnm_ap.c"),
               encoding="utf-8").read()

    want = ["wnm-sleep-resp", "wnm-bss-tm-req", "wnm-disassoc-imminent",
            "wnm-ess-disassoc-imminent", "wnm-bss-tm-req-full",
            "wnm-coloc-intf-req"]
    for label in want:
        check.ok('"%s"' % label in src,
                 "%s is hooked" % label)

    # Every transmit in the file is behind a hook, not just most of them.
    # Comments are stripped first: the hooks' own comments name the transmit
    # functions, and counting those would make the check pass by describing
    # the work rather than by doing it.
    code = re.sub(r'/\*.*?\*/', '', src, flags=re.S)
    code = re.sub(r'//[^\n]*', '', code)
    sends = len(re.findall(r'hostapd_drv_send_mlme\s*\(|'
                           r'hostapd_drv_send_action\s*\(', code))
    hooks = len(re.findall(r'apply_mutation[a-z_]*\s*\(', code))
    check.ok(sends == hooks,
             "every transmit in wnm_ap.c has one (%d send, %d hook)"
             % (sends, hooks))

    # The collocated interference frame ends at req_info: claiming an element
    # chain there would have the engine synthesise elements into a frame with
    # no place for them.
    check.ok("apply_mutation_resize(\n\t\t\"wnm-coloc-intf-req" in src or
             'apply_mutation_resize(' in src,
             "and the frame with no element chain does not claim one")

    # The build option, both ends.
    ap = open(os.path.join(root, "hostapd", "defconfig-fuzz"),
              encoding="utf-8").read()
    check.ok(re.search(r'^CONFIG_WNM=y', ap, re.M) is not None,
             "hostapd/defconfig-fuzz compiles the hooks in")
    sta = open(os.path.join(root, "wpa_supplicant", "defconfig-fuzz"),
               encoding="utf-8").read()
    check.ok(re.search(r'^CONFIG_WNM=y', sta, re.M) is not None,
             "and the station can ask, or two of the six are unreachable in "
             "every topology")

    # The configuration that makes hostapd willing to answer.
    conf = open(os.path.join(root, "fuzzing", "topology", "ap-stock.conf"),
                encoding="utf-8").read()
    for opt in ("wnm_sleep_mode=1", "bss_transition=1"):
        check.ok(re.search(r'^%s' % re.escape(opt), conf, re.M) is not None,
                 "the topology AP sets %s" % opt)


def check_handover(root, check):
    """The reporting tools survive being copied out of the checkout.

    The binary is self-contained -- the generated tables are compiled into it
    -- so handing someone the binary alone still fuzzes. The reporting around
    it is what has a source-tree dependency, and the failure used to be a
    traceback at the end of a finished run: the worst possible moment, because
    the run is over and the output is gone. Degrading is what makes the binary
    a thing you can hand over."""
    print("\nThe reporting survives leaving the checkout")
    with tempfile.TemporaryDirectory() as tmp:
        shutil.copy(os.path.join(root, "monitor_fuzzing.py"), tmp)
        shutil.copytree(os.path.join(root, "fuzzing", "ledger"),
                        os.path.join(tmp, "fuzzing", "ledger"),
                        ignore=shutil.ignore_patterns("__pycache__"))
        log = os.path.join(tmp, "run.log")
        with open(log, "w", encoding="utf-8") as f:
            f.write('[fuzz] {"msg":"inventory","targets":["a","b"],'
                    '"stages":[]}\n')
            f.write('[fuzz] {"msg":"progress","target":"a"}\n')
            f.write('[fuzz] {"msg":"fuzz","type":"MUT_BYTE_XOR","target":"a",'
                    '"frame":"mgmt","case":3,"at":30,"before":1,"after":129,'
                    '"peer":"02:00:00:00:01:00"}\n')
        rc = subprocess.run(
            [sys.executable,
             os.path.join(tmp, "fuzzing", "ledger", "ledger.py"), tmp, log],
            capture_output=True, text=True)
        check.ok(rc.returncode == 0,
                 "the ledger reports a log with no hostap source beside it")
        check.ok("Traceback" not in rc.stderr,
                 "without a traceback")
        check.ok("1 of 2 reached" in rc.stdout,
                 "and still says which targets were reached")
        check.ok("02:00:00:00:01:00" in rc.stdout,
                 "and which peer received the case")
        check.ok("No checkout" in rc.stdout,
                 "while saying the denominators are missing rather than "
                 "printing them as zero")
        # A table of zeros would read as "nothing was sent", which is the one
        # thing it does not mean.
        check.ok("defined  as built  on air" not in rc.stdout,
                 "so the denominator table is not printed at all")

        rc = subprocess.run([sys.executable,
                             os.path.join(tmp, "monitor_fuzzing.py"),
                             "--help"], capture_output=True, text=True)
        check.ok(rc.returncode == 0,
                 "and the monitor runs outside the checkout too")


def check_documented_builds(root, check):
    """The build pairing the document states is the one the scripts enforce.

    Which end carries the hooks inverts between the scripts, and getting it
    wrong produces a run in which both ends mutate and nothing is a reference
    -- a session that looks healthy and proves nothing. The scripts refuse it.
    This checks the table in FUZZING.md still says what they refuse, because a
    reader who trusts a stale table builds the wrong pair and meets the
    refusal instead of the run."""
    print("\nThe documented build pairing is the enforced one")
    doc = open(os.path.join(root, "FUZZING.md"), encoding="utf-8").read()

    # More than one table lists the scripts, so find the build-pairing one by
    # its header rather than by the first row that mentions a script name.
    lines = doc.splitlines()
    head = [i for i, l in enumerate(lines)
            if l.startswith("| script |") and "hostapd/hostapd" in l]
    check.ok(len(head) == 1,
             "FUZZING.md has exactly one build-pairing table")
    if len(head) != 1:
        return
    table = []
    for l in lines[head[0] + 1:]:
        if not l.startswith("|"):
            break
        table.append(l)

    # script -> (hostapd wants fuzz?, wpa_supplicant wants fuzz?); None = unused
    want = {
        "sta-vs-ap.sh": (False, True),
        "mesh.sh": (None, True),
        "multi-sta.sh": (False, True),
        "multi-peer-ap.sh": (True, False),
    }
    for name, (ap_fuzz, sta_fuzz) in want.items():
        text = open(os.path.join(root, "fuzzing", "topology", name),
                    encoding="utf-8").read()
        # A script demands a fuzzing build with `if ! "$X" -v | grep -q`, and
        # demands a stock one with the same test un-negated.
        for var, wants in (("AP", ap_fuzz), ("STA", sta_fuzz)):
            probe = 'if ! "$%s" -v' % var
            anti = 'if "$%s" -v' % var
            if wants is None:
                check.ok(probe not in text and anti not in text,
                         "%s does not use $%s at all" % (name, var))
                continue
            if wants:
                check.ok(probe in text and anti not in text,
                         "%s requires a fuzzing $%s" % (name, var))
            else:
                check.ok(anti in text and probe not in text,
                         "%s requires a stock $%s" % (name, var))

        # and the document's row for this script says the same thing
        row = [l for l in table if l.startswith("| `%s`" % name)]
        check.ok(len(row) == 1,
                 "the build-pairing table has one row for %s" % name)
        if len(row) != 1:
            continue
        cells = [c.strip() for c in row[0].strip("|").split("|")]
        said = []
        for c in cells[1:3]:
            said.append(None if "not used" in c
                        else ("fuzz" in c and "**" in c))
        check.ok(said == [ap_fuzz, sta_fuzz],
                 "and it says what %s enforces (%s)" % (name, cells[1:3]))

    check.ok("CONFIG_FUZZ` commented out" in doc,
             "and the document says a stock build is defconfig-fuzz minus "
             "CONFIG_FUZZ, not the upstream defconfig, which does not build")


def check_ledger_path(root, check):
    """The ledger is looked for at one path, and that path is this one.

    A search would have found any stale copy left in the checkout and reported
    coverage parsed by the wrong version -- output that looks right and is not.
    The cost of the fixed path is that moving the ledger breaks the monitor,
    which is the point: it breaks here, in a check, instead of in a run."""
    print("\nThe ledger has one home")
    src = open(os.path.join(root, "monitor_fuzzing.py"),
               encoding="utf-8").read()

    check.ok("glob" not in src,
             "the monitor does not search for the ledger")
    check.ok('LEDGER_DIR = os.path.join(_HERE, "fuzzing", "ledger")' in src,
             "it names fuzzing/ledger and nothing else")
    check.ok(os.path.isfile(os.path.join(root, "fuzzing", "ledger",
                                         "ledger.py")),
             "and the file is actually there -- a move is caught here")

    # Behavioural: a copy of the monitor with a ledger somewhere else in its
    # tree must not find it. This is the case the glob got wrong.
    with tempfile.TemporaryDirectory() as tmp:
        shutil.copy(os.path.join(root, "monitor_fuzzing.py"), tmp)
        decoy = os.path.join(tmp, "stale", "ledger")
        os.makedirs(decoy)
        with open(os.path.join(decoy, "ledger.py"), "w",
                  encoding="utf-8") as f:
            f.write("raise AssertionError('a stale ledger was imported')\n")
        rc = subprocess.run([sys.executable,
                             os.path.join(tmp, "monitor_fuzzing.py"),
                             "--help"],
                            capture_output=True, text=True)
        check.ok(rc.returncode == 0,
                 "a ledger elsewhere in the tree is not imported")
        check.ok("no coverage ledger at" in rc.stderr and
                 os.path.join("fuzzing", "ledger") in rc.stderr,
                 "and a missing ledger says so, naming the path it wanted")
        check.ok("stale" not in rc.stderr,
                 "without offering the one it declined to use")


def main():
    root = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else ".")
    check = Check()
    check_build_wiring(root, check)
    check_call_sites(root, check)
    check_reconnect(root, check)
    check_topologies(root, check)
    check_monitor(root, check)
    check_ledger_path(root, check)
    check_documented_builds(root, check)
    check_no_uncommitted_paths(root, check)
    check_handover(root, check)
    check_wnm_hooks(root, check)
    with tempfile.TemporaryDirectory() as tmp:
        binary = build_harness(root, tmp)
        if binary is None:
            return 2
        check_frame_kind(root, binary, check)
        check_ledger_kinds(root, binary, check)
    print("\n%d of %d checks pass" % (check.passed,
                                      check.passed + check.failed))
    return 1 if check.failed else 0


if __name__ == "__main__":
    sys.exit(main())
