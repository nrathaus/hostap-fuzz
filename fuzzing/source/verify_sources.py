#!/usr/bin/env python3
"""W14 -- distinct source identities.

W8 swept concurrent peers with N real peers. Underneath it is a cheaper and
larger domain: the number of DISTINCT SOURCE ADDRESSES one peer presents. The
state that gates a second attempt on this product is keyed by address, not by
radio -- a WPS registrar's device list, a P2P peer table with its own
eviction, SAE's comeback slots, a DPP Controller's connection list, and
nan_ndp_attr_handle_req(), which refuses a second request from a peer already
in progress. **One fixed address gets exactly one request through per run**,
and everything behind the second is unreachable however many cases run.

The item's own first box was a decision, and this suite checks the decision as
much as the code:

  N vifs      is N stations, which is W8 again at N times the cost.
  injection   cannot be done from a hooked daemon: an injected frame whose
              addr2 matches no local interface is dropped by mac80211 before
              it leaves the radio, silently.

So neither. The address a daemon presents is something this product already
changes on purpose, and this turns that choice into a domain. What has to be
true for that to mean anything is checked below: that EVERY picker in the tree
is hooked (the failure mode is a new call site, not a broken hook), that the
addresses cannot collide with a radio in the rig, and that a run which asks
for the domain and gets nothing says so.

    python3 fuzzing/source/verify_sources.py [checkout]

Offline. Needs the checkout built with CONFIG_FUZZ=y, for the objects.
"""

import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))

HARNESS = """
#include "utils/includes.h"
#include "utils/common.h"
#include "common/fuzz.h"

int main(int argc, char *argv[])
{
\tint iterations, i, n;
\tu8 addr[ETH_ALEN];
\tu8 seed;

\tif (argc < 3)
\t\treturn 2;
\titerations = atoi(argv[1]);
\tseed = (u8) atoi(argv[2]);

\tfor (i = 0; i < iterations; i++) {
\t\tos_memset(addr, seed, ETH_ALEN);
\t\tn = fuzz_source_addr("t-w14", addr);
\t\tprintf("ret %d " MACSTR "\\n", n, MAC2STR(addr));
\t}

\treturn 0;
}
"""


class Check:
    def __init__(self):
        self.passed = self.failed = self.skipped = 0

    def ok(self, cond, what, detail=""):
        if cond:
            self.passed += 1
            print("  ok    %s" % what)
        else:
            self.failed += 1
            print("  FAIL  %s" % what)
            if detail:
                print("        %s" % detail)

    def skip(self, what, why):
        self.skipped += 1
        print("  skip  %s" % what)
        print("        %s" % why)


def load_synth(root):
    sys.path.insert(0, os.path.join(root, "fuzzing", "synth"))
    import verify_synth as vs
    return vs


def build(root, vs, workdir):
    objdir = os.path.join(root, "build", "hostapd")
    missing = [o for o in vs.OBJECTS
               if not os.path.exists(os.path.join(objdir, o))]
    if missing:
        print("cannot find %s under %s" % (missing[0], objdir))
        print("Build the checkout with CONFIG_FUZZ=y first:")
        print("    cd hostapd && make")
        return None
    path = os.path.join(workdir, "src.c")
    binary = os.path.join(workdir, "src")
    with open(path, "w", encoding="utf-8") as f:
        f.write(HARNESS)
    command = [
        os.environ.get("CC", "cc"), "-o", binary, path,
        "-I%s" % os.path.join(root, "src"),
        "-I%s" % os.path.join(root, "src", "utils"),
        "-DCONFIG_FUZZ",
    ] + [os.path.join(objdir, o) for o in vs.OBJECTS]
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode != 0:
        print("the harness did not compile:")
        print(result.stderr.strip()[:2000])
        return None
    return binary


def run(binary, iterations, env=None, seed=0xAA):
    e = dict(os.environ)
    for k in list(e):
        if k.startswith("FUZZ_"):
            del e[k]
    e.update(env or {})
    out = subprocess.run([binary, str(iterations), str(seed)],
                         capture_output=True, text=True, env=e).stdout
    rets, messages = [], []
    for line in out.splitlines():
        if line.startswith("[fuzz] "):
            try:
                messages.append(json.loads(line[len("[fuzz] "):]))
            except ValueError:
                messages.append({"msg": "unparsable"})
        elif line.startswith("ret "):
            _, n, addr = line.split(" ")
            rets.append((int(n), addr))
    return rets, messages


# --------------------------------------------------------------------------
# A. the generator
# --------------------------------------------------------------------------

def check_generator(root, check, src):
    print("\nThe roster comes out of the tree")
    found, structure, problems = src.scan(root)
    check.ok(not problems, "the tree has no unhooked pickers",
             "; ".join(problems[:3]))
    check.ok(len(found) >= 4, "identities instrumented: %d" % len(found),
             str(sorted(found)))
    check.ok(all(src.LABEL_RE.match(n) for n in found),
             "every label is in [A-Za-z0-9_-]")
    check.ok(all(n.startswith(src.LABEL_PREFIX) for n in found),
             "and every label begins with %r, which is not cosmetic: the "
             "ground truth below is the label's STRING surviving into an "
             "object, and the compiler merges a short string that is a "
             "suffix of a longer one -- a label of \"sta\" is invisible in "
             "any object that also holds \"...sta\"" % src.LABEL_PREFIX,
             str(sorted(n for n in found
                        if not n.startswith(src.LABEL_PREFIX))))
    header = os.path.join(root, src.HEADER)
    have = open(header, encoding="utf-8").read() \
        if os.path.exists(header) else ""
    check.ok(have == src.emit_c(root),
             "%s matches the tree byte for byte" % src.HEADER)

    print("\nThe guards say which binary carries which identity")
    for label, macro in (("own-p2p-dev", "CONFIG_P2P"),
                         ("own-p2p-iface", "CONFIG_P2P"),
                         ("own-ap-mld", "CONFIG_IEEE80211BE")):
        if label not in found:
            check.skip("%s names %s" % (label, macro), "not in this tree")
            continue
        check.ok(macro in (found[label]["guard"] or ""),
                 "%s is guarded by %s, so a build without it announces the "
                 "identity as ABSENT rather than reporting it never varied"
                 % (label, macro), found[label]["guard"])
    if "own-sta" in found:
        g = found["own-sta"]["guard"] or ""
        check.ok("!defined(HOSTAPD)" in g,
                 "the station's own address is a station-side identity, and "
                 "the guard says so: hostapd announces it as absent instead "
                 "of reporting it never varied", g)

    print("\nThe tree picks an address in exactly the places it is hooked at")
    check.ok(len(structure) == 2,
             "two pickers, both in %s: %s" % (src.STRUCTURE_IN,
                                              ", ".join(fn for _, fn
                                                        in structure)),
             str(structure))
    check.ok(all(rel == src.STRUCTURE_IN and fn in src.PICKERS
                 for rel, fn in structure),
             "and nothing else in the tree builds a locally administered "
             "address -- which is what makes \"every picker is hooked\" a "
             "statement about the tree rather than about a list someone "
             "wrote down")


def check_completeness_rule(root, check, src):
    print("\nA picker with no hook fails the generator")

    def tree(body):
        tmp = tempfile.mkdtemp()
        for d in ("src/common", "hostapd", "wpa_supplicant"):
            os.makedirs(os.path.join(tmp, d), exist_ok=True)
        for mk in ("hostapd/Makefile", "wpa_supplicant/Makefile"):
            open(os.path.join(tmp, mk), "w").write(
                "OBJS += ../src/common/p.o\n")
        open(os.path.join(tmp, "src/common/p.c"), "w").write(body)
        return tmp

    good = '''int pick(struct x *s)
{
\tu8 addr[6];

\tif (random_mac_addr(addr) < 0)
\t\treturn -1;
\tfuzz_source_addr("own-p", addr);
\treturn 0;
}
'''
    bad = good.replace('\tfuzz_source_addr("own-p", addr);\n', "")
    two = good.replace('''\tif (random_mac_addr(addr) < 0)
\t\treturn -1;
\tfuzz_source_addr("own-p", addr);''',
                       '''\tif (random_mac_addr(addr) < 0)
\t\treturn -1;
\tfuzz_source_addr("own-p", addr);
\tif (random_mac_addr_keep_oui(addr) < 0)
\t\treturn -1;''')
    stray = '''int pick(struct x *s)
{
\tu8 addr[6];

\tos_get_random(addr, 6);
\taddr[0] &= 0xfe;
\taddr[0] |= 0x02;
\treturn 0;
}
'''

    for body, want, what in (
            (good, False,
             "a picker whose call is hooked passes"),
            (bad, True,
             "an UNHOOKED picker is rejected -- the failure mode here is "
             "not a broken hook, it is a new call site nobody hooked, and "
             "that is an identity that stays fixed all run while the report "
             "says the domain is on"),
            (two, True,
             "and so is a second picker in a function that already has one "
             "hook: the count has to match, or half the identities a "
             "function produces are outside the domain"),
            (stray, True,
             "a function that open-codes the address structure is rejected "
             "too: it is a third picker, and the roster would not know"),
    ):
        t = tree(body)
        try:
            _, _, problems = src.scan(t, with_guards=False)
            check.ok(bool(problems) == want, what, str(problems))
        finally:
            shutil.rmtree(t, ignore_errors=True)


def check_guards_against_binaries(root, check, src):
    """The guards are DERIVED, so they are not trusted.

    Hand each one to the C preprocessor under the flags the real build uses,
    and compare the answer against whether the label's string survived into
    the object its call site compiles to, in an object that daemon links.
    Both directions fail differently: an identity claimed but absent is
    announced and then reported NEVER VARIED forever, and one present but
    unclaimed silently stops being counted.

    The ground truth is the OBJECT, not the binary, and that was learned the
    hard way: gas_query_set_sa() is static and the compiler inlines it away,
    so a symbol lookup in the linked binary reported a call site that is
    plainly compiled in as absent. The string at the call site survives
    whether or not the function does, and looking for it in that file's own
    object keeps a stray "sta" elsewhere in the daemon from answering for
    this one.
    """
    print("\nThe guards are checked against the objects, not believed")
    sys.path.insert(0, os.path.join(root, "fuzzing", "ledger"))
    try:
        import verify_ledger as vl
    except ImportError as exc:
        check.skip("each guard matches the build it describes", str(exc))
        return

    found, _, _ = src.scan(root)
    guards = [(n, found[n]["guard"]) for n in sorted(found)]
    files = {n: sorted({s.split(":")[0] for s in found[n]["sites"]})
             for n in found}

    for daemon in ("hostapd", "wpa_supplicant"):
        # Reused rather than copied: it is the same ground truth, and two
        # copies of it would drift -- the first thing to go being exactly
        # the stale-object correction that made it right.
        objs = vl.linked_objects(root, daemon)
        if not objs:
            check.skip("%s: each guard matches the build" % daemon,
                       "could not read %s's link line" % daemon)
            continue
        flags = vl.daemon_cflags(root, daemon)
        live = vl.preprocessor_says(guards, flags) if flags else None
        if live is None:
            check.skip("%s: each guard matches the build" % daemon,
                       "could not read the build's flags")
            continue
        linked = set(objs)
        wrong = []
        for i, (name, _) in enumerate(guards):
            claimed = i in live
            present = False
            for rel in files[name]:
                obj = vl.object_for(root, daemon, rel)
                if obj in linked and \
                        vl.labels_in_objects([obj], [name]):
                    present = True
                    break
            if claimed != present:
                wrong.append("%s: guard says %s, objects say %s"
                             % (name, claimed, present))
        check.ok(not wrong,
                 "%s: every guard agrees with whether its call site is in "
                 "the build (%d identit%s)"
                 % (daemon, len(guards), "y" if len(guards) == 1 else "ies"),
                 "; ".join(wrong))


# --------------------------------------------------------------------------
# B. the domain, run for real
# --------------------------------------------------------------------------

def check_domain(root, check, binary):
    print("\nOff by default, so a build behaves as it did")
    rets, msgs = run(binary, 5)
    check.ok(all(n == 0 for n, _ in rets),
             "with FUZZ_ADDRS unset the hook declines and the caller keeps "
             "the address its own picker produced", str(rets[:2]))
    check.ok(all(a == "aa:aa:aa:aa:aa:aa" for _, a in rets),
             "and the address is untouched", str(rets[:2]))
    check.ok(not [m for m in msgs if m.get("msg") == "source"],
             "and nothing is reported, so a run that did not ask makes no "
             "claim")

    print("\nN distinct identities, then it cycles")
    rets, msgs = run(binary, 10, env={"FUZZ_ADDRS": "4"})
    addrs = [a for _, a in rets]
    check.ok(all(n == 1 for n, _ in rets), "the hook takes every call")
    check.ok(len(set(addrs)) == 4,
             "a domain of 4 presents 4 distinct addresses in 10 calls (%d)"
             % len(set(addrs)), str(addrs[:6]))
    check.ok(addrs[:4] == addrs[4:8],
             "and then cycles, rather than drifting: the ask is how many "
             "identities, not how many changes", str(addrs[:8]))

    print("\nThe rules that keep the rig from looking like a case")
    rets, _ = run(binary, 600, env={"FUZZ_ADDRS": "600"})
    addrs = [a for _, a in rets]
    check.ok(len(set(addrs)) == 600,
             "600 asked for, 600 distinct (%d)" % len(set(addrs)))
    check.ok(all(not a.endswith(":00") for a in addrs),
             "the last octet is never zero, so an address this produces "
             "can never be one of the mac80211_hwsim radios in the rig -- "
             "they are all 02:00:00:00:NN:00, and a station that took its "
             "AP's address would be a broken rig that looked like a case",
             str([a for a in addrs if a.endswith(":00")][:3]))
    check.ok(all(a.startswith("aa:") for a in addrs),
             "octet 0 is never touched: it carries the field's structure, "
             "the caller's own picker has just set it, and re-applying that "
             "rule here would be a second copy of it",
             str([a for a in addrs if not a.startswith("aa:")][:3]))

    print("\nReproducible, because a repro record has to replay")
    a1, _ = run(binary, 20, env={"FUZZ_ADDRS": "7"})
    a2, _ = run(binary, 20, env={"FUZZ_ADDRS": "7"})
    check.ok([a for _, a in a1] == [a for _, a in a2],
             "two runs of the same domain present the same sequence")
    a3, _ = run(binary, 20, env={"FUZZ_ADDRS": "7"}, seed=0x02)
    check.ok([a[3:] for _, a in a1] == [a[3:] for _, a in a3],
             "and the varying octets do not depend on what the caller's "
             "picker produced -- only octet 0 does")

    print("\nEvery change is reported")
    rets, msgs = run(binary, 6, env={"FUZZ_ADDRS": "3"})
    srcs = [m for m in msgs if m.get("msg") == "source"]
    check.ok(len(srcs) == 6, "one message per change (%d)" % len(srcs))
    check.ok(all(m.get("who") == "t-w14" for m in srcs),
             "each naming WHICH identity changed, so a run can say that "
             "rather than only that one did")
    check.ok([m["addr"] for m in srcs] == [a for _, a in rets],
             "and the address reported is the address produced")
    check.ok([m["k"] for m in srcs] == [0, 1, 2, 0, 1, 2],
             "with the case number in the domain", str([m["k"] for m in srcs]))
    check.ok(all(m["of"] == 3 for m in srcs), "and the size of the domain")
    check.ok([m["changes"] for m in srcs] == [1, 2, 3, 4, 5, 6],
             "changes counts the calls, which is a different number from "
             "the identities and is printed beside it for that reason",
             str([m["changes"] for m in srcs]))

    print("\nA domain larger than the cap is clamped, not wrapped")
    rets, msgs = run(binary, 3, env={"FUZZ_ADDRS": "999999999"})
    srcs = [m for m in msgs if m.get("msg") == "source"]
    check.ok(srcs and srcs[0]["of"] < 999999999,
             "the engine reports the domain it will actually enumerate, not "
             "the one it was asked for",
             str(srcs[0] if srcs else None))
    check.ok(len({a for _, a in rets}) == 3,
             "and still produces distinct addresses")


# --------------------------------------------------------------------------
# C. the ledger
# --------------------------------------------------------------------------

def report_of(led, root):
    buf = io.StringIO()
    led.report(root, out=buf)
    return buf.getvalue()


def inv(addrs, present, roster):
    return {"msg": "inventory", "daemon": "wpa_supplicant", "targets": [],
            "roster": [], "stages": [], "addrs": addrs,
            "sources": present,
            "source_roster": [{"name": n, "guard": g} for n, g in roster]}


def source(who, addr, k, of, changes):
    return {"msg": "source", "who": who, "addr": addr, "k": k, "of": of,
            "changes": changes}


def check_ledger(root, check):
    sys.path.insert(0, os.path.join(root, "fuzzing", "ledger"))
    import ledger as ledger_mod

    print("\nIdentities are counted as a set, not as changes")
    led = ledger_mod.Ledger()
    led.feed(inv(4, ["sta"], [("sta", None)]))
    for i in range(20):
        led.feed(source("sta", "02:00:00:00:00:%02x" % (i % 4 + 1), i % 4, 4,
                        i + 1))
    check.ok(len(led.source_addrs) == 4 and led.source_changes == 20,
             "twenty changes over four addresses is four identities and "
             "twenty reconnections, and the report says both")
    text = report_of(led, root)
    check.ok("changes: 20, distinct addresses presented: 4" in text,
             "in those words", text[-400:])
    check.ok("THE LIMIT" in text and "HASH" in text,
             "with the bound beside it: this is occupancy, not distribution")
    check.ok("THE PRICE" in text and "down and up" in text,
             "and the price beside it too: an address change costs a whole "
             "reconnect, so a case rate is not comparable across runs with "
             "different domains -- measured in this tree, a two-minute run "
             "went from 145 frames to 22 when the domain was turned on")

    print("\nAsked for and never delivered is the interesting failure")
    led = ledger_mod.Ledger()
    led.feed(inv(4, ["sta"], [("sta", None)]))
    text = report_of(led, root)
    check.ok("AND NOT ONE ADDRESS EVER CHANGED" in text,
             "a run that set FUZZ_ADDRS and got nothing says so -- a "
             "station changes its address only where its configuration asks "
             "it to, and without that the run presents ONE identity however "
             "many cases it sends")
    check.ok("mac_addr=" in text,
             "and names what was missing, rather than leaving it to be "
             "found out")

    led = ledger_mod.Ledger()
    text = report_of(led, root)
    check.ok("SOURCE ADDRESSES" not in text,
             "a run that never asked prints nothing about it, rather than "
             "printing zeroes")

    print("\nThe four states, for identities too")
    led = ledger_mod.Ledger()
    led.feed(inv(4, ["sta", "gas"],
                 [("sta", None), ("gas", "defined(CONFIG_DPP)"),
                  ("p2p-dev", "defined(CONFIG_P2P)")]))
    led.feed(source("sta", "02:00:00:00:00:01", 0, 4, 1))
    rows = dict((n, s) for n, s, _ in led.source_states())
    check.ok(rows.get("sta") == "varied", "an identity that varied")
    check.ok(rows.get("gas") == "never",
             "one in the binary that nothing varied is NEVER VARIED")
    check.ok(rows.get("p2p-dev") == "absent",
             "and one the build excluded is ABSENT -- the same distinction "
             "the transmit side makes, for the same reason")

    print("\nMore identities than the domain asked for is reported, not hidden")
    led = ledger_mod.Ledger()
    led.feed(inv(2, ["sta"], [("sta", None)]))
    for i in range(6):
        led.feed(source("sta", "%02x:00:00:00:00:%02x" % (0x02 + 4 * i,
                                                          i % 2 + 1),
                        i % 2, 2, i + 1))
    text = report_of(led, root)
    check.ok("MORE than the domain asked for" in text,
             "because this domain leaves octet 0 to the caller's picker, "
             "and where that randomises it the identities multiply")

    out = led.summary()
    check.ok(out["sources"]["asked"] == 2 and out["sources"]["changes"] == 6,
             "the campaign summary carries the ask and the delivery apart",
             json.dumps(out["sources"]))


# --------------------------------------------------------------------------
# D. the topology
# --------------------------------------------------------------------------

def check_topology(root, check):
    print("\nThe run script turns the station's own randomisation on")
    path = os.path.join(root, "fuzzing", "topology", "sta-vs-ap.sh")
    text = open(path, encoding="utf-8").read()
    check.ok("FUZZ_ADDRS" in text, "sta-vs-ap.sh knows about the domain")
    check.ok("mac_addr=2" in text and "rand_addr_lifetime=0" in text,
             "and sets both halves: the style that changes the address per "
             "connection, and the lifetime that stops it being kept for a "
             "minute -- which at this cadence is one identity per few "
             "hundred cases")
    check.ok('if [ "${FUZZ_ADDRS:-0}" -gt 0 ]' in text,
             "only when asked, so a run that did not ask is the run it was")
    check.ok("export FUZZ_ADDRS" in text,
             "and exports it, or the station would be configured to change "
             "its address while the engine declined to choose one")


def main():
    root = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else
                           os.path.join(HERE, "..", ".."))
    sys.path.insert(0, HERE)
    import sources as src_mod

    check = Check()
    check_generator(root, check, src_mod)
    check_completeness_rule(root, check, src_mod)
    check_guards_against_binaries(root, check, src_mod)

    vs = load_synth(root)
    with tempfile.TemporaryDirectory() as tmp:
        binary = build(root, vs, tmp)
        if not binary:
            return 2
        check_domain(root, check, binary)

    check_ledger(root, check)
    check_topology(root, check)

    total = check.passed + check.failed
    print("\n%d of %d checks pass%s"
          % (check.passed, total,
             ", %d skipped" % check.skipped if check.skipped else ""))
    return 1 if check.failed else 0


if __name__ == "__main__":
    sys.exit(main())
