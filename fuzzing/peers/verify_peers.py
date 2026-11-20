#!/usr/bin/env python3
"""Behavioural checks for multi-peer runs.

    python3 verify_peers.py /path/to/checkout

Needs no radio, no interface and no root: it compiles a harness against the
checkout's own fuzz.o and drives the hook directly. Build with CONFIG_FUZZ=y
first.

A one-peer run cannot produce concurrent-session stimulus at all -- whatever
the single peer negotiated is the only thing live, and every path that needs
two overlapping sessions is unreachable because there is only ever one. What
is checked here is that N peers is N times the stimulus rather than N copies
of it (they share a target's case counter, so each gets a different case),
and that the record says which peer received which case. Which peer, not
whether it minded: this is still a record and not a verdict.
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

# argv: target frame capacity type iterations npeers hint
#
# 'npeers' rewrites the destination address of each iteration's frame, which
# is what several stations in flight actually looks like. 'hint' sets the
# one-shot peer hint before each mutation, for the frames that carry no
# address of their own.
HARNESS = """
#include "utils/includes.h"
#include "utils/common.h"
#include "common/fuzz.h"

int main(int argc, char *argv[])
{
\tconst char *target = argv[1];
\tsize_t len, capacity;
\tint iterations, i, type, npeers, hint, skip;
\tu8 *frame, *base, hintaddr[ETH_ALEN];
\tchar *hex;

\tif (argc < 9)
\t\treturn 2;

\tlen = os_strlen(argv[2]) / 2;
\tcapacity = (size_t) atoi(argv[3]);
\ttype = atoi(argv[4]);
\titerations = atoi(argv[5]);
\tnpeers = atoi(argv[6]);
\thint = atoi(argv[7]);
\tskip = atoi(argv[8]);

\tif (capacity < len)
\t\tcapacity = len;

\tframe = os_malloc(capacity ? capacity : 1);
\tbase = os_malloc(len ? len : 1);
\thex = os_malloc(2 * capacity + 1);
\tif (!frame || !base || !hex)
\t\treturn 3;
\tif (hexstr2bin(argv[2], base, len) < 0)
\t\treturn 2;

\tos_memset(hintaddr, 0, sizeof(hintaddr));
\thintaddr[0] = 0x0a;

\tfor (i = 0; i < iterations; i++) {
\t\tsize_t out;

\t\tos_memset(frame, 0, capacity);
\t\tos_memcpy(frame, base, len);
\t\tif (npeers > 0 && len >= 10)
\t\t\tframe[8] = (u8) (i % npeers);

\t\tif (hint) {
\t\t\thintaddr[5] = (u8) (i % (npeers > 0 ? npeers : 1));
\t\t\tfuzz_peer_hint(hintaddr);
\t\t}

\t\t/* A call site that sets a hint and then takes an error path:
\t\t * the mutation is skipped entirely, and the hint must not be
\t\t * waiting for the next frame. */
\t\tif (skip && (i % 2) == 0) {
\t\t\tprintf("ret skipped\\n");
\t\t\tcontinue;
\t\t}

\t\tout = apply_mutation_resize(target,
\t\t\t\t\t    (enum fuzz_frame_type) type,
\t\t\t\t\t    frame, len, capacity);
\t\twpa_snprintf_hex(hex, 2 * out + 1, frame, out);
\t\tprintf("ret %zu %s\\n", out, hex);
\t}

\treturn 0;
}
"""


def auth_frame():
    hdr = bytearray(24)
    hdr[0] = (11 << 4)
    hdr[4:10] = bytes([0x02, 0, 0, 0, 0, 0])      # DA
    body = bytes([0x34, 0x12, 0x02, 0x00, 0x21, 0x43]) + bytes([0, 2, 65, 65])
    return bytes(hdr) + body


FRAME = auth_frame()
CAP = len(FRAME)
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
    path = os.path.join(workdir, "p.c")
    binary = os.path.join(workdir, "p")
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


def run(binary, target, iterations, frame=FRAME, capacity=None, ftype=MGMT,
        npeers=0, hint=0, skip=0, env=None):
    if capacity is None:
        capacity = len(frame)
    e = {k: v for k, v in os.environ.items() if not k.startswith("FUZZ_")}
    e.update(env or {})
    out = subprocess.run(
        [binary, target, frame.hex(), str(capacity), str(ftype),
         str(iterations + WARMUP), str(npeers), str(hint), str(skip)],
        capture_output=True, text=True, env=e).stdout
    messages = []
    for line in out.splitlines():
        if line.startswith(PREFIX):
            try:
                messages.append(json.loads(line[len(PREFIX):]))
            except ValueError:
                messages.append({"msg": "unparsable"})
    return messages


def muts(messages):
    return [m for m in messages if m.get("msg") == "fuzz"]


# --------------------------------------------------------------------------

def check_peer_from_frame(binary, check):
    """A management frame says who it is for, so nothing has to be told."""
    print("\nA management frame carries its own peer")
    msgs = run(binary, "t-da", 60, npeers=3)
    seen = {m.get("peer") for m in muts(msgs)}
    check.ok(seen == {"02:00:00:00:00:00", "02:00:00:00:01:00",
                      "02:00:00:00:02:00"},
             "each frame reports the destination address it was built with: "
             "%s" % sorted(x for x in seen if x))
    check.ok(all(m.get("peer") for m in muts(msgs)),
             "and every mutation message carries one, with no call site "
             "having said anything")

    prog = [m for m in msgs if m.get("msg") == "progress"]
    check.ok(all(m.get("peer") for m in prog[WARMUP:]),
             "the progress message carries it too, so a case that announced "
             "and was never sent is still attributed")

    # It is the DA, which is what went on the air -- not a hint that could be
    # stale, and not the source address.
    bad = []
    for m in muts(msgs):
        data = bytes.fromhex(m.get("data", ""))
        da = ":".join("%02x" % b for b in data[4:10])
        if da != m.get("peer"):
            bad.append((da, m.get("peer")))
    check.ok(not bad,
             "and it is read out of the frame's own header, so it cannot "
             "disagree with what was sent (%d checked)" % len(muts(msgs)),
             str(bad[:3]))


def check_hint(binary, check):
    """A frame with no address in it gets one from the call site."""
    print("\nA frame with no address gets a hint")
    eapol = bytes([2, 3, 0, 40]) + bytes([2]) + bytes([0x55]) * 40
    msgs = run(binary, "t-hint", 40, frame=eapol, ftype=EAPOL, npeers=2,
               hint=1)
    seen = {m.get("peer") for m in muts(msgs)}
    check.ok(seen == {"0a:00:00:00:00:00", "0a:00:00:00:00:01"},
             "the hint is what gets reported: %s"
             % sorted(x for x in seen if x))

    # Without a hint there is no peer, and no guess either.
    msgs = run(binary, "t-nohint", 40, frame=eapol, ftype=EAPOL, hint=0)
    check.ok(all("peer" not in m for m in muts(msgs)),
             "and with no hint the message simply has no peer, rather than "
             "a value someone inferred")


def check_hint_is_one_shot(binary, check):
    """A hint set on a frame that was never sent must not follow the next."""
    print("\nA hint cannot go stale")
    eapol = bytes([2, 3, 0, 40]) + bytes([2]) + bytes([0x55]) * 40
    # Every even iteration sets a hint and then returns without mutating.
    # If the hint survived, the odd iterations would report the even one's
    # peer, which is a case attributed to a peer that never received it.
    msgs = run(binary, "t-skip", 40, frame=eapol, ftype=EAPOL, npeers=2,
               hint=1, skip=1)
    seen = {m.get("peer") for m in muts(msgs)}
    check.ok(seen == {"0a:00:00:00:00:01"},
             "only the peers that were actually mutated for appear: %s"
             % sorted(x for x in seen if x),
             "a stale hint would also show 0a:00:00:00:00:00")

    # A management frame ignores a hint entirely: its own header is better
    # evidence than anything the call site remembers.
    msgs = run(binary, "t-both", 20, npeers=2, hint=1)
    seen = {m.get("peer") for m in muts(msgs)}
    check.ok(all(p.startswith("02:") for p in seen if p),
             "and a frame that carries an address uses it in preference to "
             "any hint: %s" % sorted(x for x in seen if x))


def check_peers_share_the_sweep(binary, check):
    """N peers is N times the stimulus, not N copies of it."""
    print("\nPeers share a target's case counter")
    one = run(binary, "t-share1", 90, npeers=1)
    three = run(binary, "t-share3", 90, npeers=3)

    def cases(msgs):
        return [m["case_id"] for m in msgs
                if m.get("msg") == "progress" and m.get("case_id", -1) >= 0]

    check.ok(cases(one) == cases(three),
             "the case sequence does not change with the number of peers "
             "(%d cases either way)" % len(cases(one)))

    bypeer = {}
    for m in muts(three):
        bypeer.setdefault(m.get("peer"), []).append(m.get("idx"))
    check.ok(len(bypeer) == 3,
             "three peers received cases (%d)" % len(bypeer))

    sizes = sorted(len(v) for v in bypeer.values())
    check.ok(max(sizes) - min(sizes) <= 1,
             "and the cases are spread across them rather than piled on one "
             "(%s)" % sizes)

    # The claim, stated as the thing that would be false if each peer got
    # its own counter: no two peers received the same case.
    #
    # The case is the case_id, not the mutation's own fields -- a field case
    # carries no idx or mask, so comparing those would make every field case
    # look identical to every other and the check would fail on its own
    # blindness rather than on anything the engine did. The case_id comes
    # from the progress message immediately before each mutation, which is
    # the order the engine emits them in.
    perpeer, case_id = {}, None
    for m in three:
        if m.get("msg") == "progress":
            case_id = m.get("case_id")
        elif m.get("msg") == "fuzz" and case_id is not None:
            perpeer.setdefault(m.get("peer"), set()).add(case_id)
    overlap = set()
    seen = set()
    for cases in perpeer.values():
        overlap |= seen & cases
        seen |= cases
    check.ok(len(perpeer) == 3 and not overlap,
             "no two peers received the same case, so three peers is three "
             "times the stimulus rather than three copies of it (%d cases "
             "across %d peers)" % (len(seen), len(perpeer)),
             "%d shared" % len(overlap))


def check_ledger(root, binary, check):
    """The record says which peer received which case."""
    print("\nThe ledger splits the run by peer")
    sys.path.insert(0, os.path.join(root, "fuzzing", "ledger"))
    from ledger import Ledger

    msgs = run(binary, "t-led", 120, npeers=4)
    led = Ledger()
    for m in msgs:
        led.feed(m)
    summary = led.summary()
    check.ok(len(led.peers) == 4,
             "four peers are tallied (%d)" % len(led.peers))
    check.ok(sum(led.peers.values()) == len(muts(msgs)),
             "and every mutated frame is attributed to exactly one of them "
             "(%d of %d)" % (sum(led.peers.values()), len(muts(msgs))))
    check.ok(all(" " in k for k in summary["peers"]),
             "the summary keys it by peer and target, because a peer's "
             "coverage of one target says nothing about another")

    # A single-peer run must still read correctly -- this is additive.
    led = Ledger()
    for m in run(binary, "t-led1", 40, npeers=1):
        led.feed(m)
    check.ok(len(led.peers) == 1,
             "a one-peer run reports one peer, not none")


def check_generator(root, check):
    """The settings the peers differ in come from the tree."""
    print("\nThe peers differ in a setting the tree derives")
    sys.path.insert(0, os.path.join(root, "fuzzing", "topology"))
    sys.path.insert(0, os.path.join(root, "fuzzing", "axes"))
    import peers as peers_mod
    import families

    reg = families.group_registry(root)
    known = {v for tier in ("ffc", "ecc") for v, _ in reg[tier]}
    g = peers_mod.groups(root)
    check.ok(set(g) == known,
             "every group the tree can instantiate is available to a peer "
             "(%d)" % len(g))
    check.ok(len(g) > len(reg["production"]),
             "including the ones the production filter rejects (%d of %d), "
             "which is the point of sweeping it" % (len(g),
                                                    len(reg["production"])))

    # A group the build cannot instantiate gives a station that never
    # associates: a peer contributing nothing rather than a refusal. So the
    # ones that work come first.
    ungated = {v for tier in ("ffc", "ecc") for v, gate in reg[tier]
               if not gate}
    usable = ungated & set(reg["production"])
    check.ok(set(g[:len(usable)]) == usable,
             "the groups a stock build can actually complete come first "
             "(%s)" % sorted(usable))

    assigned = peers_mod.assign(root, 3)
    check.ok(len(set(assigned)) == 3,
             "three peers get three different groups (%s)" % assigned)
    check.ok(len(set(peers_mod.assign(root, len(g) + 2))) == len(g),
             "and asking for more peers than there are groups reuses them "
             "rather than inventing one")

    with tempfile.TemporaryDirectory() as tmp:
        made = peers_mod.generate(root, 3, tmp, "ssid", "pw", tmp)
        texts = [open(p, encoding="utf-8").read().splitlines() for p, _ in made]
        diffs = set()
        for a in texts:
            for b in texts:
                if a is b:
                    continue
                diffs |= {l for l in a if l not in b}
        settings = {d for d in diffs
                    if d.strip() and not d.strip().startswith("#")}
        # ctrl_interface is per-process bookkeeping: two stations cannot
        # share a control socket, so it has to differ and it is not a
        # negotiated property. Everything else that differs is.
        plumbing = {d for d in settings if d.startswith("ctrl_interface=")}
        check.ok(len(plumbing) == len(made),
                 "each station gets its own control socket, which is "
                 "plumbing and not a negotiated setting (%d)" % len(plumbing))
        negotiated = settings - plumbing
        check.ok(negotiated and
                 all(d.startswith("sae_groups=") for d in negotiated),
                 "and they differ in exactly one negotiated setting, so "
                 "whatever a run finds attributes to it: %s"
                 % sorted(negotiated))
        for path, _ in made:
            d = os.path.join(tmp, os.path.basename(path).replace(".conf", ""))
            check.ok(os.path.isdir(d),
                     "the control directory %s exists, which wpa_supplicant "
                     "will not create for itself"
                     % os.path.basename(d))
            break


def check_script(root, check):
    """The run script, and the one mistake it already made."""
    print("\nThe multi-peer run script")
    sh = os.path.join(root, "fuzzing", "topology", "multi-sta.sh")
    check.ok(os.access(sh, os.X_OK), "multi-sta.sh is executable")
    text = open(sh, encoding="utf-8").read()

    ap_sub = os.path.join(root, "fuzzing", "topology", "multi-peer-ap.sh")
    check.ok(os.access(ap_sub, os.X_OK), "multi-peer-ap.sh is executable")

    # Shell-owned names. GROUPS is a read-only array in bash holding the
    # caller's group ids: assigning to it is silently discarded and the
    # expansion gives a group id instead. That is exactly what happened here
    # -- the AP got sae_groups=0, accepted nothing, every station failed to
    # associate, and no part of the run reported an error. One check is
    # cheaper than finding it again.
    OWNED = {"GROUPS", "UID", "EUID", "PPID", "PWD", "IFS", "SECONDS",
             "RANDOM", "LINENO", "HOSTNAME", "OPTARG", "OPTIND", "SHLVL",
             "BASH_ARGV", "FUNCNAME"}
    for path in (sh, ap_sub):
        body = open(path, encoding="utf-8").read()
        assigned = set(re.findall(r"(?m)^\s*([A-Za-z_][A-Za-z0-9_]*)=",
                                  body))
        clash = sorted(assigned & OWNED)
        check.ok(not clash,
                 "%s assigns to no name the shell owns"
                 % os.path.basename(path),
                 "the assignment is discarded and the expansion is the "
                 "shell's value: %s" % clash)

    for path in (sh, ap_sub):
        body = open(path, encoding="utf-8").read()
        name = os.path.basename(path)
        check.ok("unshare -r -m -n" in body,
                 "%s contains itself in a user, mount and network namespace"
                 % name)
        check.ok("mac80211_hwsim" in body and "modprobe" in body,
                 "and names the one privileged step rather than running it")
        # A log written next to the source is one `git add -A` from being
        # committed. Everything a run produces goes outside the checkout.
        check.ok("LOGDIR=" in body and "$ROOT/fuzz-" not in body,
                 "and writes its logs outside the checkout")

    with tempfile.TemporaryDirectory() as tmp:
        def fake(name, fuzzing):
            path = os.path.join(tmp, name)
            with open(path, "w") as f:
                f.write("#!/bin/sh\necho 'v0'\n")
                if fuzzing:
                    f.write("echo 'Frame fuzzing hooks are COMPILED IN: x'\n")
            os.chmod(path, 0o755)
            return path

        fuzz_ap, stock_ap = fake("ap-fuzz", True), fake("ap-stock", False)
        fuzz_sta, stock_sta = fake("sta-fuzz", True), fake("sta-stock", False)

        def attempt(script, ap, sta):
            return subprocess.run([script, "0", "2"], capture_output=True,
                                  text=True, cwd=root,
                                  env=dict(os.environ, AP=ap, STA=sta,
                                           FUZZ_LOGDIR=tmp))

        # Both ends mutating means nothing in the run is a reference, and the
        # two scripts disagree about WHICH end should be the fuzzing one --
        # so each has to refuse the other's arrangement, not just its own.
        r = attempt(sh, fuzz_ap, fuzz_sta)
        check.ok(r.returncode == 2 and "must be a stock one" in r.stderr,
                 "multi-sta.sh refuses a fuzzing victim", r.stderr[:160])
        r = attempt(sh, stock_ap, stock_sta)
        check.ok(r.returncode == 2 and "no fuzzing hooks" in r.stderr,
                 "and a subject with no hooks", r.stderr[:160])

        r = attempt(ap_sub, fuzz_ap, fuzz_sta)
        check.ok(r.returncode == 2 and "must be stock" in r.stderr,
                 "multi-peer-ap.sh refuses fuzzing peers", r.stderr[:160])
        r = attempt(ap_sub, stock_ap, stock_sta)
        check.ok(r.returncode == 2 and "no fuzzing hooks" in r.stderr,
                 "and an AP with no hooks, which is the opposite arrangement "
                 "from the other script's", r.stderr[:160])


def main():
    root = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else ".")
    check = Check()
    check_generator(root, check)
    check_script(root, check)
    with tempfile.TemporaryDirectory() as tmp:
        binary = build_harness(root, tmp)
        if binary is None:
            return 2
        check_peer_from_frame(binary, check)
        check_hint(binary, check)
        check_hint_is_one_shot(binary, check)
        check_peers_share_the_sweep(binary, check)
        check_ledger(root, binary, check)
    print("\n%d of %d checks pass" % (check.passed,
                                      check.passed + check.failed))
    return 1 if check.failed else 0


if __name__ == "__main__":
    sys.exit(main())
