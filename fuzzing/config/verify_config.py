#!/usr/bin/env python3
"""W15 -- the compile-time axis.

W2 enumerates what hostapd parses at run time. This enumerates what decides
whether a parser is in the binary at all, and the claim under test is narrow
and easy to get subtly wrong:

    a run built without a flag reports clean on code the binary never
    contained, in exactly the words it uses for code it swept and cleared

so the report has to be able to say which it did. Six groups below, and the
weight is in B and E.

  A  the generator reads the tree -- the flag space, the -D ownership that
     decides whether a flag can be witnessed at all, and the include that
     half the driver flags live behind. Synthetic Makefiles that it must
     REFUSE to draw a witness from, because a proxy macro two flags define
     says "one of these two" and that is not what the roster would claim.

  B  the witness against the real build. The generated header's answer is
     compared against the -D list on the compile line the real build uses,
     which is a ground truth from the build system rather than from .config
     -- .config is the input and the Makefile derives a great deal from it.

  C  the defconfig reasons. Every setting on which defconfig-fuzz differs
     from upstream defconfig carries one, no reason outlives its delta, and
     a reason that happens to MENTION another flag does not count as
     covering it.

  D  the recorded build failures, re-derived. Each is a member declared
     under one flag and read under another; the check is that the tree still
     has that shape, so the record fails loudly when upstream fixes it
     rather than going on telling the next person a lie.

  E  the ledger's BUILD section, driven from synthetic inventories: the
     four-state wording, the attribution of an absent roster entry to the
     flag that would bring it back, and the refusal to attribute one that no
     flag explains. Also that a guard out of a log is PARSED and never
     eval()'d.

  F  the real binaries. The inventory each built daemon actually emits,
     against the compile line it was built with.

    python3 fuzzing/config/verify_config.py [checkout]

Offline. B and F need the checkout built; they skip rather than fail if not.
"""

import json
import io
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "ledger"))
sys.path.insert(0, os.path.join(HERE, "..", "synth"))

import config as cfg            # noqa: E402
import ledger as ledger_mod     # noqa: E402
import verify_ledger as vl      # noqa: E402

# The harness exists to make the daemon's own inventory message come out
# without a radio: the first mutation emits it, and nothing else is needed.
HARNESS = """
#include "utils/includes.h"
#include "utils/common.h"
#include "common/fuzz.h"

int main(void)
{
\tu8 frame[64];

\tos_memset(frame, 0x41, sizeof(frame));
\tapply_mutation_defer_log("eapol", FUZZ_TYPE_IEEE802_1X_HDR,
\t\t\t\t frame, sizeof(frame), sizeof(frame));
\treturn 0;
}
"""

OBJECTS = [
    "src/common/fuzz.o",
    "src/utils/json.o",
    "src/utils/wpabuf.o",
    "src/utils/common.o",
    "src/utils/os_unix.o",
    "src/utils/base64.o",
    "src/utils/wpa_debug.o",
]

DAEMONS = ["hostapd", "wpa_supplicant"]


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


def write_tree(base, files):
    for rel, text in files.items():
        path = os.path.join(base, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
    return base


# --------------------------------------------------------------------------
# A. the generator
# --------------------------------------------------------------------------

def check_generator(root, check):
    print("\nA. The flag space comes out of the Makefiles")
    tab = cfg.roster(root)
    check.ok(len(tab) > 200, "flags tested: %d" % len(tab))
    check.ok("CONFIG_FUZZ" in tab and "CONFIG_WPS" in tab,
             "the obvious ones are in it")

    header = os.path.join(root, cfg.HEADER)
    have = open(header, encoding="utf-8").read() \
        if os.path.exists(header) else ""
    check.ok(have == cfg.emit_c(root),
             "%s matches the tree byte for byte" % cfg.HEADER)

    # The include matters: more than half the driver flags are in
    # src/drivers/drivers.mak and neither daemon Makefile mentions them.
    e = tab.get("CONFIG_DRIVER_NL80211")
    check.ok(e is not None and e["daemons"] == 3,
             "CONFIG_DRIVER_NL80211 is in the space for both daemons, which "
             "it only can be if `include ../src/drivers/drivers.mak` was "
             "followed",
             str(e))

    print("\n   whether a flag can be SEEN from C at all")
    fz = tab.get("CONFIG_FUZZ", {})
    check.ok(all(k == cfg.WITNESS_SELF for k, _ in fz.get("wit", {}).values()),
             "CONFIG_FUZZ is self-named in both: -DCONFIG_FUZZ")
    md5 = tab.get("CONFIG_EAP_MD5")
    if md5 is None:
        check.skip("CONFIG_EAP_MD5 has a different witness per daemon",
                   "not in this tree")
    else:
        macros = {m for _, m in md5["wit"].values()}
        check.ok(len(macros) == 2,
                 "CONFIG_EAP_MD5 is witnessed by a DIFFERENT macro in each "
                 "daemon (%s), which is why the witness is kept per daemon: "
                 "one best-of would make the other binary answer 'off' for a "
                 "flag it was built with" % "/".join(sorted(macros)),
                 str(macros))
        guard = cfg.witness_guard(md5)
        check.ok(guard is not None and guard.count("HOSTAPD") == 2,
                 "and its emitted test qualifies each macro by HOSTAPD",
                 str(guard))
    blind = [n for n, e in tab.items() if not e["witness"]]
    check.ok(len(blind) > 20,
             "%d flag(s) reach no -D at all and are reported as "
             "unwitnessable rather than as off" % len(blind))
    check.ok(all(cfg.witness_guard(tab[n]) is None for n in blind),
             "and none of them is emitted into fuzz_config_on[]")

    print("\n   and the trees it must refuse to draw a witness from")
    with tempfile.TemporaryDirectory() as tmp:
        shared = write_tree(os.path.join(tmp, "shared"), {
            "hostapd/Makefile": (
                "ifdef CONFIG_A\nCFLAGS += -DSHARED\nendif\n"
                "ifdef CONFIG_B\nCFLAGS += -DSHARED\nendif\n"),
            "wpa_supplicant/Makefile": "\n",
            "hostapd/defconfig": "\n", "hostapd/defconfig-fuzz": "\n",
            "wpa_supplicant/defconfig": "\n",
            "wpa_supplicant/defconfig-fuzz": "\n",
        })
        t = cfg.roster(shared)
        check.ok(t["CONFIG_A"]["witness"] == 0 and t["CONFIG_B"]["witness"] == 0,
                 "a macro two flags define is NOT used as a proxy for either "
                 "-- it says 'one of these two is on', which is not the "
                 "claim the roster would be making",
                 str({k: v["witness"] for k, v in t.items()}))

        els = write_tree(os.path.join(tmp, "else"), {
            "hostapd/Makefile": (
                "ifdef CONFIG_C\nCFLAGS += -DYES\nelse\n"
                "CFLAGS += -DCONFIG_C\nendif\n"),
            "wpa_supplicant/Makefile": "\n",
            "hostapd/defconfig": "\n", "hostapd/defconfig-fuzz": "\n",
            "wpa_supplicant/defconfig": "\n",
            "wpa_supplicant/defconfig-fuzz": "\n",
        })
        t = cfg.roster(els)
        kinds = {k for k, _ in t["CONFIG_C"]["wit"].values()}
        check.ok(cfg.WITNESS_SELF not in kinds,
                 "a -D of the flag's own name in the ELSE branch does not "
                 "make it self-named: it is defined when the flag is OFF",
                 str(t["CONFIG_C"]["wit"]))

        ifeq = write_tree(os.path.join(tmp, "ifeq"), {
            "hostapd/Makefile": (
                "ifeq ($(CONFIG_TLS), openssl)\nCFLAGS += -DMINE\nendif\n"),
            "wpa_supplicant/Makefile": "\n",
            "hostapd/defconfig": "\n", "hostapd/defconfig-fuzz": "\n",
            "wpa_supplicant/defconfig": "\n",
            "wpa_supplicant/defconfig-fuzz": "\n",
        })
        t = cfg.roster(ifeq)
        check.ok(t["CONFIG_TLS"]["value"] and not t["CONFIG_TLS"]["witness"],
                 "a flag tested for its VALUE is marked as such and owns "
                 "nothing: on/off is the wrong question about CONFIG_TLS, "
                 "and a wrong answer is worse than no answer",
                 str(t["CONFIG_TLS"]))


# --------------------------------------------------------------------------
# B. the witness against the build system
# --------------------------------------------------------------------------

def macro_set(flags):
    return {f[2:].split("=")[0] for f in flags}


def check_ground_truth(root, check):
    print("\nB. The witness against the compile line the build really uses")
    tab = cfg.roster(root)
    for daemon in DAEMONS:
        flags = vl.daemon_cflags(root, daemon)
        if flags is None:
            check.skip("%s: the generated header against the compile line"
                       % daemon,
                       "no .config, or make could not be run")
            continue
        macros = macro_set(flags)
        bit = cfg.DAEMON_BIT[daemon]
        owned = cfg.owned_macros(root)

        # Every CONFIG_/NEED_ macro that reaches the compiler is accounted
        # for: either a flag in the space, or a macro some flag introduces.
        # The compile line carries -DCONFIG_JSON, which comes out of an
        # `ifdef NEED_JSON` block and is not a configuration option at all,
        # and the two must not be confused for each other.
        unknown = sorted(m for m in macros
                         if cfg.FLAG_RE.match(m)
                         and m not in tab and m not in owned)
        check.ok(not unknown,
                 "%s: every CONFIG_/NEED_ macro on the compile line is "
                 "either a flag in the space or a macro a flag introduces"
                 % daemon,
                 " ".join(unknown[:6]))

        # Where .config and the compiler disagree. A flag set in .config
        # whose own -D sits under a FURTHER condition never reaches the
        # compiler, and then the code it guards is not in the binary --
        # which is the question this report asks, so "off" is the right
        # answer and .config is simply not the ground truth.
        asked = cfg.settings(root, os.path.join(daemon, ".config"))
        scan = cfg.scan_makefile(root, dict(
            (d, mf) for d, mf, _, _ in cfg.DAEMONS)[daemon])
        claimed = [n for n in asked
                   if n in tab
                   and tab[n]["wit"].get(daemon,
                                         (0, None))[0] == cfg.WITNESS_SELF]
        bad = [n for n in claimed if n not in macros]
        unexplained = [n for n in bad if n in scan["free"]]
        check.ok(not unexplained,
                 "%s: of the %d self-named flag(s) its .config sets, the %d "
                 "the compiler never sees are exactly the ones whose -D "
                 "sits under a further condition (%s)"
                 % (daemon, len(claimed), len(bad),
                    " ".join(sorted(bad)) or "none"),
                 " ".join(unexplained[:6]))

        # And the header's own answer, evaluated the way the compiler would.
        on = set()
        for name, e in tab.items():
            guard = cfg.witness_guard(e)
            if guard is None:
                continue
            if ledger_mod.guard_true(guard, macros, daemon):
                on.add(name)
        check.ok(all(e["daemons"] & bit for e in (tab[n] for n in on)),
                 "%s: every flag the header would report on is one this "
                 "Makefile tests" % daemon)
        check.ok("CONFIG_FUZZ" in on,
                 "%s: and CONFIG_FUZZ is among them, which it must be for "
                 "any of this to be running at all" % daemon)


# --------------------------------------------------------------------------
# C. the defconfig reasons
# --------------------------------------------------------------------------

def check_reasons(root, check):
    print("\nC. defconfig-fuzz accounts for every setting it changes")
    d = cfg.delta(root)
    r = cfg.reasons(root)
    total = sum(len(v) for v in d.values())
    check.ok(total > 20, "%d setting(s) differ from upstream defconfig"
             % total)
    missing, stale = cfg.reason_gaps(root)
    check.ok(not missing,
             "every one of them carries a # WHY line",
             " ".join("%s/%s" % x for x in missing[:6]))
    check.ok(not stale,
             "and no # WHY line outlives the delta it explains",
             " ".join("%s/%s" % x for x in stale[:6]))

    # The deltas that cost parse surface are the ones worth naming here: the
    # file is allowed to leave a flag out, it is not allowed to do it
    # silently.
    for daemon, flag in (("wpa_supplicant", "CONFIG_WPS"),
                         ("wpa_supplicant", "CONFIG_P2P"),
                         ("hostapd", "CONFIG_DPP")):
        if flag not in d.get(daemon, {}):
            check.skip("%s/%s is accounted for" % (daemon, flag),
                       "no longer a delta")
            continue
        kind = d[daemon][flag][0]
        check.ok(kind == "dropped" and len(r[daemon].get(flag, "")) > 40,
                 "%s/%s is dropped from upstream's defaults and says why in "
                 "more than a word" % (daemon, flag),
                 "%s: %r" % (kind, r[daemon].get(flag)))

    print("\n   and the check refuses a file that does not")
    base = {
        "hostapd/Makefile": "\n", "wpa_supplicant/Makefile": "\n",
        "wpa_supplicant/defconfig": "\n",
        "wpa_supplicant/defconfig-fuzz": "\n",
    }
    with tempfile.TemporaryDirectory() as tmp:
        silent = write_tree(os.path.join(tmp, "silent"), dict(
            base, **{"hostapd/defconfig": "CONFIG_X=y\n",
                     "hostapd/defconfig-fuzz": "CONFIG_Y=y\n"}))
        missing, stale = cfg.reason_gaps(silent)
        check.ok(sorted(f for _, f in missing) == ["CONFIG_X", "CONFIG_Y"],
                 "a delta with no reason is reported, in both directions",
                 str(missing))

        rotten = write_tree(os.path.join(tmp, "rotten"), dict(
            base, **{"hostapd/defconfig": "CONFIG_X=y\n",
                     "hostapd/defconfig-fuzz":
                         "# WHY CONFIG_X: dropped, and said so\n"
                         "# WHY CONFIG_GHOST: never was\n"}))
        missing, stale = cfg.reason_gaps(rotten)
        check.ok([f for _, f in stale] == ["CONFIG_GHOST"] and not missing,
                 "a reason whose delta has gone away is reported too -- "
                 "otherwise the file accumulates explanations of things "
                 "that are no longer true",
                 "%s %s" % (missing, stale))

        wordy = write_tree(os.path.join(tmp, "wordy"), dict(
            base, **{"hostapd/defconfig": "\n",
                     "hostapd/defconfig-fuzz":
                         "# WHY CONFIG_A: off because CONFIG_B would need it\n"
                         "CONFIG_A=y\nCONFIG_B=y\n"}))
        got = cfg.reasons(wordy)["hostapd"]
        check.ok("CONFIG_A" in got and "CONFIG_B" not in got,
                 "a reason that MENTIONS another flag does not count as "
                 "covering it: the names stop at the colon",
                 str(sorted(got)))

        runon = write_tree(os.path.join(tmp, "runon"), dict(
            base, **{"hostapd/defconfig": "\n",
                     "hostapd/defconfig-fuzz":
                         "# WHY CONFIG_A CONFIG_B\n"
                         "#   CONFIG_C: one decision about three\n"
                         "CONFIG_A=y\nCONFIG_B=y\nCONFIG_C=y\n"}))
        got = cfg.reasons(runon)["hostapd"]
        check.ok(sorted(got) == ["CONFIG_A", "CONFIG_B", "CONFIG_C"],
                 "and a list too long for one line runs on across comment "
                 "lines up to the colon",
                 str(sorted(got)))


# --------------------------------------------------------------------------
# D. the build failures, re-derived
# --------------------------------------------------------------------------

def check_failures(root, check):
    print("\nD. The flags that do not compile on their own")
    recs = cfg.failures(root)
    check.ok(len(recs) >= 3, "%d failure(s) recorded" % len(recs))
    for f in recs:
        check.ok(f["ok"],
                 "%s: %s is still declared under %s and read without it at "
                 "%s:%s"
                 % (f["flag"], f["member"],
                    ", ".join(f["guards"]) or "nothing",
                    f["reader"],
                    f["unguarded"][0][0] if f["unguarded"] else "-"),
                 "the tree no longer has this shape -- re-check whether the "
                 "flag builds, then update or delete the record")

    print("\n   and the record goes red when the tree is repaired")
    with tempfile.TemporaryDirectory() as tmp:
        fixed = write_tree(tmp, {
            "h.h": "#ifndef H_H\n#define H_H\nstruct s {\n\tbool m;\n};\n"
                   "#endif\n",
            "r.c": "void f(struct s *p) { bool x = p->m; }\n",
        })
        saved = cfg.BUILD_FAILURES
        try:
            cfg.BUILD_FAILURES = [{"flag": "CONFIG_T", "reader": "r.c",
                                   "header": "h.h", "member": "m",
                                   "note": "synthetic"}]
            got = cfg.failures(fixed)[0]
            check.ok(not got["ok"],
                     "a member that became unconditional makes the record "
                     "fail rather than silently keep claiming the flag is "
                     "broken",
                     str(got["guards"]))
            write_tree(tmp, {
                "h.h": "#ifndef H_H\n#define H_H\nstruct s {\n"
                       "#ifdef CONFIG_OTHER\n\tbool m;\n#endif\n};\n#endif\n",
            })
            got = cfg.failures(fixed)[0]
            check.ok(got["ok"] and got["guards"] == ["defined(CONFIG_OTHER)"],
                     "and the guard is DERIVED from the header rather than "
                     "written down beside the record, so the two cannot "
                     "drift apart",
                     str(got["guards"]))
            write_tree(tmp, {
                "r.c": "#ifdef CONFIG_OTHER\n"
                       "void f(struct s *p) { bool x = p->m; }\n#endif\n",
            })
            got = cfg.failures(fixed)[0]
            check.ok(not got["ok"],
                     "and a read moved INSIDE the same guard is not a "
                     "failure any more, which is the repair this watches for",
                     str(got["unguarded"]))
        finally:
            cfg.BUILD_FAILURES = saved


# --------------------------------------------------------------------------
# E. the ledger
# --------------------------------------------------------------------------

def inventory(daemon, on, roster=None, targets=None, troster=None,
              version="v-test"):
    msg = {"msg": "inventory", "daemon": daemon, "version": version,
           "config": sorted(on), "targets": list(targets or []),
           "roster": [{"name": n, "guard": g}
                      for n, g in sorted((troster or {}).items())],
           "stages": []}
    msg["config_roster"] = [[n, d, w, s, v]
                            for n, (d, w, s, v) in sorted((roster or {}).items())]
    return msg


def render(led, root="."):
    buf = io.StringIO()
    led.report(root, out=buf)
    text = buf.getvalue()
    start = text.index("BUILD --")
    return text[start:text.index("TARGETS", start)]


def check_ledger(root, check):
    print("\nE. The ledger says which build the numbers came from")

    led = ledger_mod.Ledger()
    out = render(led, root)
    check.ok("No build line in this log" in out,
             "with no inventory at all it says so, rather than printing an "
             "empty flag set that reads as a build with nothing on")

    roster = {"CONFIG_WPS": (3, 3, 3, 0),
              "CONFIG_SAE": (3, 3, 3, 0),
              "CONFIG_MESH": (2, 2, 0, 0),
              "CONFIG_LIBNL32": (3, 0, 3, 0)}
    led = ledger_mod.Ledger()
    led.feed(inventory("hostapd", ["CONFIG_SAE"], roster,
                       targets=["a"],
                       troster={"a": "defined(CONFIG_SAE)",
                                "b": "defined(CONFIG_WPS)",
                                "c": "!defined(HOSTAPD) && defined(CONFIG_MESH)",
                                "d": "defined(CONFIG_WPS) @@"}))
    out = render(led, root)
    check.ok("v-test" in out, "the version is printed beside the daemon")
    check.ok(re.search(r"1 flag\(s\) on, of 3 this Makefile tests", out)
             is not None,
             "the denominator is the flags THIS Makefile tests, not all of "
             "them", out)
    check.ok(re.search(r"1 set by upstream defconfig and NOT here", out)
             and "CONFIG_WPS" in out,
             "a flag upstream sets and this build does not is named: that "
             "is parse surface the run did not cover, whatever its numbers "
             "say", out)
    check.ok("CONFIG_LIBNL32" not in out.split("WHAT THE BUILD COST")[0],
             "but a STOCK flag the binary cannot witness is not reported as "
             "dropped -- absent from the on-list means 'cannot tell' for it, "
             "and calling it dropped would invent a narrowing", out)
    check.ok("1 flag(s) it cannot report either way" in out,
             "it is counted under what the binary cannot report instead",
             out)

    cost = out.split("WHAT THE BUILD COST")[1]
    check.ok(re.search(r"CONFIG_WPS\s+1\s+b", cost) is not None,
             "a roster entry absent from the build is attributed to the "
             "flag that alone would bring it back", cost)
    check.ok("c" not in re.findall(r"CONFIG_\w+\s+\d+\s+(\w+)", cost),
             "an entry absent because this is the wrong daemon is NOT "
             "attributed to a flag", cost)
    check.ok("absent for a reason no flag explains" in cost,
             "it is counted apart, in its own words", cost)
    check.ok("cannot parse" in cost,
             "and a guard the report cannot read is counted apart again, "
             "rather than being treated as false -- which would turn an "
             "unreadable condition into a confident 'absent'", cost)

    print("\n   two builds under one name")
    led = ledger_mod.Ledger()
    led.feed(inventory("hostapd", ["CONFIG_SAE"], roster))
    led.feed(inventory("hostapd", ["CONFIG_SAE", "CONFIG_WPS"], roster))
    out = render(led, root)
    check.ok("TWO BUILDS UNDER ONE NAME" in out,
             "a log that unions two runs of the same daemon built "
             "differently says so: nothing else here would notice, and "
             "every number below it is a sum over code that was not the "
             "same code", out)

    print("\n   a guard out of a log is parsed, never executed")
    before = os.environ.get("W15_CANARY")
    check.ok(ledger_mod.guard_true(
        "__import__('os').environ.__setitem__('W15_CANARY','1') or 1",
        set(), "hostapd") is None,
             "a guard containing Python is refused by the grammar")
    check.ok(os.environ.get("W15_CANARY") == before,
             "and nothing in it ran")
    for expr, on, want in (
            ("defined(A)", {"A"}, True),
            ("defined(A) && defined(B)", {"A"}, False),
            ("defined(A) || defined(B)", {"B"}, True),
            ("!defined(A)", set(), True),
            ("(defined(A) && !defined(B)) || defined(C)", {"A", "B"}, False),
            ("(defined(A) && !defined(B)) || defined(C)", {"A"}, True)):
        check.ok(ledger_mod.guard_true(expr, on, "hostapd") is want,
                 "%s with %s is %s" % (expr, sorted(on) or "nothing", want))

    print("\n   and the search for the flag that would undo an absence")
    nonmono = "defined(A) && !defined(B)"
    sets, _ = ledger_mod.absent_because(nonmono, set(), "hostapd")
    check.ok(sets == [["A"]],
             "a guard with a negation in it is not monotone, so turning "
             "every named flag on at once is not a valid probe -- A alone "
             "is the answer and A+B is not", str(sets))
    sets, why = ledger_mod.absent_because("defined(A) && defined(B)", set(),
                                          "hostapd")
    check.ok(sets == [["A", "B"]],
             "a conjunction reports the pair, not one of them", str(sets))
    sets, why = ledger_mod.absent_because("!defined(HOSTAPD)", set(),
                                          "hostapd")
    check.ok(sets == [] and why,
             "and an unsatisfiable guard says so rather than naming a flag",
             str((sets, why)))


# --------------------------------------------------------------------------
# F. the real binaries
# --------------------------------------------------------------------------

def build_harness(root, daemon, workdir):
    objdir = os.path.join(root, "build", daemon)
    if any(not os.path.exists(os.path.join(objdir, o)) for o in OBJECTS):
        return None
    source = os.path.join(workdir, "h-%s.c" % daemon)
    binary = os.path.join(workdir, "h-%s" % daemon)
    with open(source, "w", encoding="utf-8") as f:
        f.write(HARNESS)
    cmd = [os.environ.get("CC", "cc"), "-o", binary, source,
           "-I%s" % os.path.join(root, "src"),
           "-I%s" % os.path.join(root, "src", "utils"),
           "-DCONFIG_FUZZ"] + [os.path.join(objdir, o) for o in OBJECTS]
    if subprocess.run(cmd, capture_output=True, text=True).returncode:
        return None
    return binary


def real_inventory(binary):
    env = dict(os.environ)
    for k in list(env):
        if k.startswith("FUZZ_"):
            del env[k]
    env["FUZZ_START_EAPOL"] = "100"
    out = subprocess.run([binary], capture_output=True, text=True, env=env)
    for line in (out.stdout + out.stderr).splitlines():
        if not line.startswith("[fuzz] "):
            continue
        try:
            msg = json.loads(line[len("[fuzz] "):])
        except ValueError:
            continue
        if msg.get("msg") == "inventory":
            return msg
    return None


def check_real(root, check):
    print("\nF. What the built binaries actually announce")
    tab = cfg.roster(root)
    with tempfile.TemporaryDirectory() as tmp:
        for daemon in DAEMONS:
            binary = build_harness(root, daemon, tmp)
            if binary is None:
                check.skip("%s announces its build" % daemon,
                           "not built, or the harness did not compile")
                continue
            msg = real_inventory(binary)
            if msg is None:
                check.skip("%s announces its build" % daemon,
                           "no inventory message came out")
                continue
            check.ok(bool(msg.get("version")),
                     "%s: the inventory carries a version (%s)"
                     % (daemon, msg.get("version")))
            check.ok(len(msg.get("config_roster") or []) == len(tab),
                     "%s: the roster it announces is the whole space (%d)"
                     % (daemon, len(tab)),
                     str(len(msg.get("config_roster") or [])))
            check.ok(all(isinstance(e, list) and len(e) == 5
                         for e in msg["config_roster"]),
                     "%s: every roster entry is the five-field form the "
                     "ledger reads" % daemon)

            flags = vl.daemon_cflags(root, daemon)
            if flags is None:
                check.skip("%s: against the compile line" % daemon,
                           "make could not be run")
                continue
            macros = macro_set(flags)
            want = set()
            for name, e in tab.items():
                guard = cfg.witness_guard(e)
                if guard and ledger_mod.guard_true(guard, macros, daemon):
                    want.add(name)
            got = set(msg.get("config") or [])
            check.ok(got == want,
                     "%s: the %d flag(s) it reports are exactly the ones the "
                     "compile line implies" % (daemon, len(got)),
                     "only in binary: %s | only in compile line: %s"
                     % (sorted(got - want)[:6], sorted(want - got)[:6]))
            check.ok("CONFIG_FUZZ" in got,
                     "%s: CONFIG_FUZZ among them" % daemon)

            led = ledger_mod.Ledger()
            led.feed(msg)
            st = led.build_states(daemon)
            check.ok(st is not None and st["on"] == sorted(got),
                     "%s: and the ledger reads them back unchanged" % daemon)


def main():
    root = os.path.abspath(sys.argv[1] if len(sys.argv) > 1
                           else os.path.join(HERE, "..", ".."))
    print("W15 -- the compile-time axis, against %s" % root)
    check = Check()
    check_generator(root, check)
    check_ground_truth(root, check)
    check_reasons(root, check)
    check_failures(root, check)
    check_ledger(root, check)
    check_real(root, check)
    print()
    total = check.passed + check.failed
    print("%d of %d checks pass%s"
          % (check.passed, total,
             (", %d skipped" % check.skipped) if check.skipped else ""))
    return 1 if check.failed else 0


if __name__ == "__main__":
    sys.exit(main())
