#!/usr/bin/env python3
"""W13 -- reach instrumentation: what was read, not what was sent.

Every other suite in this tree checks the transmit side. They are all true
and not one of them can tell a case space that is sweeping from one that is
being discarded at the door, because from the transmit side those two look
identical: same frames, same counters, same green run. Two figures from
elsewhere on this product, quoted for the size of the hazard rather than for
anything they found -- a generator aimed at the DPP attribute stream had 206
of 257 cases rejected before any handler ran, and one aimed at WPS reached
the end of the parser zero times in 40 while reporting a clean sweep.

So this suite checks the other side, in four parts:

  the generator   the roster, the guards and the walker census come out of
                  the tree, and a hooked walker that grows a return which
                  does not report fails rather than halving the number.
  the cost        a build without CONFIG_FUZZ_REACH is the build it was.
                  Checked by COMPILING IT BOTH WAYS and comparing the code,
                  because an instrument that changes the thing it measures
                  is not measuring it.
  the ledger      a parse is attributed to a case only when the octets say
                  so, and a target whose cases were never read is reported
                  as a failure rather than as a quiet zero.
  the monitor     the victim's output still reaches its log in full, and its
                  [fuzz] lines also reach the ledger, tagged as the victim's.

    python3 fuzzing/reach/verify_reach.py [checkout]

Offline. The compile check needs a C compiler; it is skipped, loudly, if one
is not there.
"""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))


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


# --------------------------------------------------------------------------
# A. the generator
# --------------------------------------------------------------------------

def check_generator(root, check, reach):
    print("\nThe roster comes out of the tree")
    found, walkers, hooked, problems = reach.scan(root)
    check.ok(not problems, "the tree has no instrumentation problems",
             "; ".join(problems[:3]))
    check.ok(len(found) >= 4,
             "parsers instrumented: %d" % len(found),
             str(sorted(found)))
    check.ok(all(reach.LABEL_RE.match(n) for n in found),
             "every label is in [A-Za-z0-9_-], which the JSON and the "
             "environment folding both assume")

    fns = {}
    for name, e in found.items():
        fns.setdefault((e["file"], e["fn"]), []).append(name)
    check.ok(all(len(v) == 1 for v in fns.values()),
             "one label, one walker -- a label shared by two functions has "
             "no guard that is true of both",
             str({k: v for k, v in fns.items() if len(v) > 1}))

    header = os.path.join(root, reach.HEADER)
    have = open(header, encoding="utf-8").read() if os.path.exists(header) \
        else ""
    check.ok(have == reach.emit_c(root),
             "%s matches the tree byte for byte" % reach.HEADER)

    print("\nThe guards say which binary carries which parser")
    for label, macro in (("wps", "CONFIG_WPS"), ("dpp", "CONFIG_DPP")):
        if label not in found:
            check.skip("%s names %s in its guard" % (label, macro),
                       "%s is not instrumented in this tree" % label)
            continue
        check.ok(macro in (found[label]["guard"] or ""),
                 "%s is guarded by %s, so a build without it announces the "
                 "parser as ABSENT rather than reporting it never reached"
                 % (label, macro), found[label]["guard"])
    for label in ("elems", "kde"):
        if label not in found:
            continue
        check.ok(found[label]["guard"] is None,
                 "%s is unguarded: it is in every binary this tree builds"
                 % label, found[label]["guard"])

    print("\nThe instrument reports its own coverage")
    check.ok(len(walkers) > len(hooked),
             "the tree has more element walkers (%d) than are instrumented "
             "(%d), and the generated header says so -- a reach figure "
             "quoted without that ratio reads as a claim about the product"
             % (len(walkers), len(hooked)))
    check.ok("#define FUZZ_REACH_WALKERS %d" % len(walkers) in have and
             "#define FUZZ_REACH_WALKERS_HOOKED %d" % len(hooked) in have,
             "and both numbers are in the generated header, so the RUN "
             "announces them rather than a document holding them")


def check_return_rule(root, check, reach):
    """The rule that survives a rebase, exercised on a synthetic tree.

    Written against a tree built here rather than against the real one,
    because the thing being checked is that the check FAILS -- and the only
    way to see that is to hand it a walker that breaks the rule.
    """
    print("\nA walker that returns without reporting fails the generator")

    def tree(body):
        tmp = tempfile.mkdtemp()
        for d in ("src/common", "hostapd", "wpa_supplicant"):
            os.makedirs(os.path.join(tmp, d), exist_ok=True)
        for mk in ("hostapd/Makefile", "wpa_supplicant/Makefile"):
            open(os.path.join(tmp, mk), "w").write("OBJS += ../src/common/p.o\n")
        open(os.path.join(tmp, "src/common/p.c"), "w").write(body)
        return tmp

    good = '''int walk(const u8 *buf, size_t len)
{
	const u8 *pos = buf;

	while (pos < buf + len) {
		if (*pos == 0) {
			fuzz_reach("p", buf, len, pos - buf);
			return -1;
		}
		pos++;
	}

	fuzz_reach("p", buf, len, len);
	return 0;
}
'''
    bad = good.replace('''		if (*pos == 0) {
			fuzz_reach("p", buf, len, pos - buf);
			return -1;
		}''', '''		if (*pos == 0)
			return -1;''')

    t = tree(good)
    try:
        _, _, _, problems = reach.scan(t, with_guards=False)
        check.ok(not problems,
                 "a walker whose every return reports passes", str(problems))
    finally:
        shutil.rmtree(t, ignore_errors=True)

    t = tree(bad)
    try:
        _, _, _, problems = reach.scan(t, with_guards=False)
        check.ok(any("returns without reporting reach" in p
                     for p in problems),
                 "an early return with no hook is REJECTED -- this is what "
                 "catches an upstream rebase adding a `return -1` to a "
                 "parser we hook, which would otherwise halve the number "
                 "silently", str(problems))
    finally:
        shutil.rmtree(t, ignore_errors=True)

    # A hook that is somewhere in the function but not on this path is the
    # mistake the strict form exists to refuse.
    far = '''int walk(const u8 *buf, size_t len)
{
	const u8 *pos = buf;

	fuzz_reach("p", buf, len, 0);
	if (len == 0)
		return -1;

	return 0;
}
'''
    t = tree(far)
    try:
        _, _, _, problems = reach.scan(t, with_guards=False)
        check.ok(any("returns without reporting reach" in p
                     for p in problems),
                 "a hook EARLIER in the function does not cover a later "
                 "return: 'somewhere in this function' is satisfied by a "
                 "path the return does not take", str(problems))
    finally:
        shutil.rmtree(t, ignore_errors=True)

    nonliteral = '''int walk(const u8 *buf, size_t len)
{
	fuzz_reach(name, buf, len, len);
	return 0;
}
'''
    t = tree(nonliteral)
    try:
        _, _, _, problems = reach.scan(t, with_guards=False)
        check.ok(any("not a literal" in p for p in problems),
                 "a label that is not a literal is rejected: the roster is "
                 "read from the source, so a computed label is a parser the "
                 "inventory cannot announce", str(problems))
    finally:
        shutil.rmtree(t, ignore_errors=True)

    census = '''int one(const u8 *b, size_t l)
{
	for_each_element(e, b, l) {
	}
	for_each_element_id(e, 0, b, l) {
	}
	return 0;
}

int two(const u8 *b, size_t l)
{
	for_each_element(e, b, l) {
	}
	return 0;
}
'''
    t = tree(census)
    try:
        _, walkers, _, _ = reach.scan(t, with_guards=False)
        check.ok(len(walkers) == 2,
                 "the walker census counts FUNCTIONS, not call sites: three "
                 "walks in two functions is two walkers",
                 str(walkers))
    finally:
        shutil.rmtree(t, ignore_errors=True)


# --------------------------------------------------------------------------
# B. the cost to a build that does not want it
# --------------------------------------------------------------------------

def check_costs_nothing(root, check):
    """Compile a hooked file both ways and compare the code.

    An instrument that changes the thing it measures is not measuring it, and
    on this product the hooked functions are shared parsing code that every
    build links. So the claim is not 'the hook is cheap' -- it is that
    WITHOUT the flag the object is the object it was, and that is checkable
    rather than arguable: compile the file as it stands, compile a copy with
    the hook lines deleted, and compare the generated code.
    """
    print("\nWithout CONFIG_FUZZ_REACH the hooked file is the file it was")
    cc = shutil.which("cc") or shutil.which("gcc")
    if not cc:
        check.skip("a hooked object is unchanged without the flag",
                   "no C compiler on PATH")
        return

    rel = "src/common/ieee802_11_common.c"
    src = open(os.path.join(root, rel), encoding="utf-8").read()
    stripped, drop = [], False
    for line in src.splitlines(True):
        if drop:
            if ";" in line:
                drop = False
            continue
        if line.lstrip().startswith("fuzz_reach("):
            drop = ";" not in line
            continue
        stripped.append(line)
    check.ok(len(stripped) < len(src.splitlines(True)),
             "the hook lines are findable in %s (%d removed)"
             % (rel, len(src.splitlines(True)) - len(stripped)))

    with tempfile.TemporaryDirectory() as tmp:
        cut = os.path.join(tmp, "cut.c")
        open(cut, "w").write("".join(stripped))
        inc = ["-I" + os.path.join(root, d)
               for d in ("src", "src/utils", "src/common")]
        objs = {}
        for name, path in (("with", os.path.join(root, rel)),
                           ("without", cut)):
            out = os.path.join(tmp, name + ".o")
            r = subprocess.run([cc, "-c", "-g0", "-O2", "-o", out, path,
                                "-DCONFIG_SHA256", "-DCONFIG_SHA384"] + inc,
                               capture_output=True, text=True)
            if r.returncode != 0:
                check.skip("a hooked object is unchanged without the flag",
                           "could not compile %s: %s"
                           % (name, r.stderr.strip().splitlines()[-1:]))
                return
            dis = subprocess.run(["objdump", "-d", "--no-show-raw-insn", out],
                                 capture_output=True, text=True)
            if dis.returncode != 0:
                check.skip("a hooked object is unchanged without the flag",
                           "objdump is not available")
                return
            objs[name] = "\n".join(l for l in dis.stdout.splitlines()
                                   if ":" in l and not l.startswith(out))
        check.ok(objs["with"] == objs["without"],
                 "the code generated for %s is IDENTICAL with the hooks and "
                 "with them deleted, when the flag is off -- so a stock "
                 "build pays nothing and, more to the point, behaves the "
                 "same" % rel,
                 "%d vs %d bytes of disassembly"
                 % (len(objs["with"]), len(objs["without"])))


def check_build_wiring(root, check):
    print("\nThe flag is a second flag, not a corner of the first")
    for mk in ("hostapd/Makefile", "wpa_supplicant/Makefile"):
        text = open(os.path.join(root, mk), encoding="utf-8").read()
        check.ok("ifdef CONFIG_FUZZ_REACH" in text,
                 "%s has a CONFIG_FUZZ_REACH block" % mk)
        depth, at, mutating = 0, None, None
        for line in text.splitlines():
            t = line.strip()
            if t.startswith("ifdef CONFIG_FUZZ_REACH"):
                at = depth
            if t.startswith("OBJS += ../src/common/fuzz.o"):
                mutating = depth
            if t.split(" ")[0] in ("ifdef", "ifndef", "ifeq", "ifneq"):
                depth += 1
            elif t == "endif":
                depth -= 1
        check.ok(at == 0,
                 "%s opens it at the TOP LEVEL, not inside the CONFIG_FUZZ "
                 "block: a victim must be able to report what it read "
                 "WITHOUT mutating, and until there were two flags there "
                 "was no build that could do both" % mk,
                 "nested %s deep" % at)
        check.ok(mutating is not None and mutating > at,
                 "and the mutating engine stays behind its own flag, so a "
                 "reach build does not link fuzz.o at all")

    reach_c = open(os.path.join(root, "src/common/fuzz_reach.c"),
                   encoding="utf-8").read()
    check.ok("json_" not in reach_c,
             "fuzz_reach.c writes its own JSON: it is linked into the "
             "VICTIM, and pulling NEED_JSON/NEED_BASE64 into a build whose "
             "job is to be read from would make the instrument a reason to "
             "link code the measurement is not about")
    head = open(os.path.join(root, "src/common/fuzz_reach.h"),
                encoding="utf-8").read()
    check.ok("static inline void fuzz_reach(" in head,
             "and fuzz_reach.h carries a no-op inline, so a parser carrying "
             "a hook needs no #ifdef of its own")
    check.ok("FUZZ_REACH_DISABLE" in reach_c,
             "one binary can be a measured victim and a silent one without "
             "being rebuilt")

    for daemon in ("hostapd/main.c", "wpa_supplicant/main.c"):
        text = open(os.path.join(root, daemon), encoding="utf-8").read()
        check.ok("Reach instrumentation is COMPILED IN" in text,
                 "%s -v says so: a topology script has to tell a measured "
                 "victim from an unmeasured one without reading a log"
                 % daemon)


def check_guards_against_binaries(root, check, reach):
    """The guards are DERIVED, so they are not trusted.

    Hand each one to the C preprocessor under the flags the real build uses,
    and compare the answer against whether the parser's function is in the
    binary that build produced. Both directions fail differently: a parser
    claimed but absent is announced and then reported NEVER REACHED forever,
    and a parser present but unclaimed silently stops being counted.

    The same argument as verify_ledger.py's group B, and the same machinery --
    imported rather than copied, because two copies of it would drift and the
    first thing to go would be the flag extraction.
    """
    print("\nThe guards are checked against the binaries, not believed")
    sys.path.insert(0, os.path.join(root, "fuzzing", "ledger"))
    try:
        import verify_ledger as vl
    except ImportError as exc:
        check.skip("each guard matches the binary it describes", str(exc))
        return

    found, _, _, _ = reach.scan(root)
    guards = [(n, found[n]["guard"]) for n in sorted(found)]

    for daemon, binary in (("hostapd", "hostapd/hostapd"),
                           ("wpa_supplicant",
                            "wpa_supplicant/wpa_supplicant")):
        path = os.path.join(root, binary)
        if not os.path.exists(path):
            check.skip("%s: each guard matches the binary" % daemon,
                       "%s is not built" % binary)
            continue
        flags = vl.daemon_cflags(root, daemon)
        if flags is None:
            check.skip("%s: each guard matches the binary" % daemon,
                       "could not read the build's flags")
            continue
        live = vl.preprocessor_says(guards, flags)
        if live is None:
            check.skip("%s: each guard matches the binary" % daemon,
                       "the preprocessor would not run")
            continue
        try:
            syms = subprocess.run(["nm", path], capture_output=True,
                                  text=True, timeout=120).stdout
        except (OSError, subprocess.SubprocessError) as exc:
            check.skip("%s: each guard matches the binary" % daemon, str(exc))
            continue
        names = set(re.findall(r"\S+\s+[a-zA-Z]\s+(\S+)", syms))

        wrong = []
        for i, (name, _) in enumerate(guards):
            claimed = i in live
            # GCC renames what it partially inlines --
            # "__ieee802_11_parse_elems.part.0" -- so the symbol is the
            # function's name or the function's name and a suffix, and
            # matching on equality alone reported a walker that is plainly
            # in the binary as absent from it.
            fn = found[name]["fn"]
            present = any(sym == fn or sym.startswith(fn + ".")
                          for sym in names)
            if claimed != present:
                wrong.append("%s: guard says %s, binary says %s"
                             % (name, claimed, present))
        check.ok(not wrong,
                 "%s: every guard agrees with whether its walker is in the "
                 "binary (%d parser%s)"
                 % (daemon, len(guards), "" if len(guards) == 1 else "s"),
                 "; ".join(wrong))


# --------------------------------------------------------------------------
# C. the ledger
# --------------------------------------------------------------------------

def load_ledger(root):
    sys.path.insert(0, os.path.join(root, "fuzzing", "ledger"))
    import ledger as ledger_mod
    return ledger_mod


# A management header that is not a counting sequence. It was one, and the
# ambient test then failed: the window scan found 03 04 05 .. inside it,
# which is a true answer to the question asked and the wrong fixture.
HDR = bytes.fromhex("b0003a01" "020000000100" "020000000002" "020000000002"
                    "c010")


def sent(target, case_id, frame_hex):
    return {"msg": "fuzz", "target": target, "case_id": case_id,
            "frame": "mgmt", "hdr": 24, "type": "MUT_BYTE", "idx": 0,
            "opset": "v5/10d/STRIDE/251@0", "data": frame_hex}


def parsed(parser, span, got=None, seq=0):
    got = len(span) if got is None else got
    return {"msg": "reach", "daemon": "hostapd", "parser": parser,
            "seq": seq, "n": len(span), "got": got,
            "whole": 1 if got >= len(span) else 0,
            "span": span.hex()}


def progress(target, case_id):
    return {"msg": "progress", "target": target, "case_id": case_id,
            "opset": "v5/10d/STRIDE/251@0"}


def report_of(led, root):
    import io
    buf = io.StringIO()
    led.report(root, out=buf)
    return buf.getvalue()


def check_ledger(root, check, ledger_mod):
    print("\nA parse is attributed by the octets, not by the clock")
    # Long enough to carry a needle: the correlation is by overlap, and a
    # span shorter than one window cannot be placed at all. That is a real
    # bound and the suite works within it rather than around it.
    frame = HDR + bytes.fromhex(
        "000d686f737461702d7475746f7269616c010882848b960c1218243203010624"
        "02010f")
    chain = frame[24:]

    led = ledger_mod.Ledger()
    led.feed(sent("t-a", 1, frame.hex()))
    led.feed(parsed("elems", chain), source="victim")
    check.ok(led.reach_attributed == 1 and led.reach_ambient == 0,
             "a span that is findable in a frame this run sent is "
             "attributed to it")
    check.ok(led.reach_by_target["t-a"]["read"] == {1},
             "and to the right case")

    led = ledger_mod.Ledger()
    led.feed(sent("t-a", 1, frame.hex()))
    led.feed(parsed("elems", bytes.fromhex(
        "dd0a0050f2040102030405060708090a0b0c0d0e0f1011121314")),
             source="victim")
    check.ok(led.reach_ambient == 1 and led.reach_attributed == 0,
             "a span that is not in any frame this run sent is AMBIENT -- "
             "the receiver parses ordinary traffic too, and counting that "
             "would report the run as read perfectly while every mutated "
             "frame was dropped at the door")

    led = ledger_mod.Ledger()
    led.feed(sent("t-a", 1, frame.hex()))
    led.feed(parsed("elems", chain, got=4), source="victim")
    p = led.reach_parsers["elems"]
    check.ok(p["whole"] == 0 and p["stopped"] == 1,
             "a walk that stopped part way is counted as stopped, which is "
             "the receive-side counterpart of the pre/post depth every "
             "element case already reports")
    check.ok(led.reach_by_target["t-a"]["through"] == set(),
             "and the case is read but not walked through")

    print("\nThe correlation window is bounded")
    led = ledger_mod.Ledger()
    led.feed(sent("t-a", 0, frame.hex()))
    for i in range(1, 40):
        other = bytes([i]) + HDR[1:] + bytes.fromhex("00020102")
        led.feed(sent("t-b", i, other.hex()))
    led.feed(parsed("elems", chain), source="victim")
    check.ok(led.reach_ambient == 1,
             "a parse of a frame sent forty cases ago is NOT attributed: a "
             "deep window would start crediting a parse to a case from a "
             "second ago, and would do it most often exactly where the run "
             "is repetitive")

    print("\nA span too short to be a needle is not attributed to anything")
    led = ledger_mod.Ledger()
    led.feed(sent("t-a", 1, frame.hex()))
    led.feed(parsed("elems", b"\x00\x01"), source="victim")
    check.ok(led.reach_short == 1 and led.reach_ambient == 0 and
             led.reach_attributed == 0,
             "it is counted apart, because a run where most parses are "
             "unattributable is a run whose reach figure means less than it "
             "looks like it does")

    print("\nA target whose cases were never read is a FAILURE")
    led = ledger_mod.Ledger()
    led.feed({"msg": "reach_inventory", "daemon": "hostapd",
              "parsers": ["elems"], "walkers": [20, 1],
              "roster": [{"name": "elems", "fn": "__ieee802_11_parse_elems",
                          "guard": None},
                         {"name": "wps", "fn": "wps_parse_msg",
                          "guard": "defined(CONFIG_WPS)"}]},
             source="victim")
    led.feed(sent("t-read", 1, frame.hex()))
    led.feed(parsed("elems", chain), source="victim")
    for i in range(4):
        led.feed(sent("t-dead", i, (bytes([0xaa, i]) * 20).hex()))
    text = report_of(led, root)
    check.ok("TARGETS WHOSE CASES WERE NEVER READ" in text,
             "the report names it")
    check.ok("t-dead" in text and "4 cases sent, 0 reached" in text,
             "with the count", text)
    check.ok("This is a FAILURE and is printed as one." in text,
             "and says so in those words: until this item there was no way "
             "to tell it apart from a target that was working perfectly")
    check.ok("THE LIMIT" in text and "no INSTRUMENTED" in text,
             "and prints the bound of the claim beside the number, because "
             "a number gets quoted without its bound otherwise")
    check.ok("element walkers in the tree: 20, instrumented: 1" in text,
             "the walker ratio is printed, so a reach figure cannot be read "
             "as a claim about the product")
    check.ok("t-dead" in led.summary()["reach"]["never_read"],
             "and the campaign summary carries it, because a campaign "
             "unioning runs must not lose exactly this fact")

    print("\nThe four states, on the receive side too")
    rows = dict((n, s) for n, s, _ in led.reach_states())
    check.ok(rows.get("elems") == "reached", "a parser that reported")
    check.ok(rows.get("wps") == "absent",
             "a parser the build excluded is ABSENT, not never reached -- "
             "the same distinction the transmit side makes, for the same "
             "reason")
    led2 = ledger_mod.Ledger()
    led2.feed({"msg": "reach_inventory", "daemon": "hostapd",
               "parsers": ["elems", "kde"], "walkers": [20, 1],
               "roster": []}, source="victim")
    rows2 = dict((n, s) for n, s, _ in led2.reach_states())
    check.ok(rows2.get("kde") == "never",
             "a parser in the binary that nothing reached is NEVER REACHED")
    led3 = ledger_mod.Ledger()
    led3.feed(parsed("elems", chain), source="victim")
    check.ok([s for _, s, _ in led3.reach_states()] == ["unknown"],
             "and with no inventory at all the state is unknown rather "
             "than guessed")

    print("\nWith nothing reporting, the report says NOT MEASURED")
    led = ledger_mod.Ledger()
    led.feed(sent("t-a", 1, frame.hex()))
    led.victim_line("Configuration file: /tmp/ap.conf\n")
    text = report_of(led, root)
    check.ok("NOT MEASURED" in text,
             "which is a different statement from zero, and is the one that "
             "was true of every run before this item")
    check.ok("WITHOUT INSTRUMENTATION" in text and "a log line is not a "
             "parse" in text,
             "and the weaker signal -- the victim said something -- is "
             "printed with its limit, because it is all there is where the "
             "victim is not ours to build")

    print("\nThe span the walker got is not always the span that was sent")
    # A run of octets long enough to be found by the window scan, which is
    # the bound: 23 octets of agreement, and 23 is not chance.
    ours = bytes.fromhex("30140100000fac040100000fac040100000fac0180000000")
    led = ledger_mod.Ledger()
    led.feed(sent("t-assoc", 1, (HDR + ours).hex()))
    # What mac80211 actually builds: its own elements in FRONT of the
    # driver's buffer and a WMM element AFTER it. Measured, not supposed --
    # 85 of the 143 octets the AP walked were the ones the station sent, and
    # they were in the middle.
    bigger = (bytes.fromhex("0004777966690108828488") + ours +
              bytes.fromhex("dd070050f202000100"))
    led.feed(parsed("elems", bigger), source="victim")
    check.ok(led.reach_attributed == 1,
             "a walk over a chain this run's octets are in the MIDDLE of is "
             "attributed: matching the head found nothing, matching head "
             "and tail found nothing, and both reported every association "
             "request as a frame nobody read")
    check.ok(led.reach_parsers["elems"]["enclosing"] == 1,
             "and it is counted apart, because a walker handed MORE than "
             "the run sent is a different fact from one handed exactly it")
    text = report_of(led, root)
    check.ok("MORE than this run" in text,
             "and the report says so rather than folding it into the total")

    led = ledger_mod.Ledger()
    led.feed(sent("t-a", 1, frame.hex()))
    led.feed(parsed("elems", bytes(range(100, 200))), source="victim")
    check.ok(led.reach_ambient == 1,
             "but a span with no run of octets in common is still ambient: "
             "the window scan widens the match, it does not remove it")

    led = ledger_mod.Ledger()
    led.feed(sent("t-a", 1, frame.hex()))
    led.feed(parsed("elems", frame[24:44] + bytes(60)), source="victim")
    check.ok(led.reach_attributed == 1,
             "and 20 shared octets in a 80-octet span are enough, because "
             "the scan steps by half a needle: any run of 23 or more is "
             "found")

    print("\nThe receive side does not move a transmit-side counter")
    # The regression this tree has already had once: a new counter reusing a
    # name that meant something else, which every offline suite passed and
    # only a live run exposed. The arrangement that makes it visible is both
    # kinds of message in one stream, so that is the arrangement.
    led = ledger_mod.Ledger()
    led.feed(sent("t-a", 1, frame.hex()))
    before = {k: v for k, v in vars(led).items()
              if isinstance(v, int) and not k.startswith("reach_")
              and k not in ("victim_lines",)}
    for i in range(5):
        led.feed(parsed("elems", chain, seq=i), source="victim")
    after = {k: v for k, v in vars(led).items() if k in before}
    check.ok(before == after,
             "five parses move no counter that is not a reach counter",
             str({k: (before[k], after[k])
                  for k in before if before[k] != after[k]}))
    check.ok(led.frames == 1 and led.reach_parsers["elems"]["parses"] == 5,
             "and the two sides are counted apart: one frame sent, five "
             "parses of it")

    print("\nThe case number comes from the message that carries it")
    led = ledger_mod.Ledger()
    for i in range(3):
        led.feed(progress("t-a", 100 + i))
        led.feed(sent("t-a", None, (bytes([i]) + frame[1:]).hex()))
    check.ok(led.sent_cases["t-a"] == {100, 101, 102},
             "'progress' is emitted immediately before the mutation and is "
             "the only message that carries the case number, so a ledger "
             "that waited for the 'fuzz' message would file every case of "
             "a run under None -- and then report one case per target",
             str(led.sent_cases))

    print("\nThe two speakers are kept apart")
    led = ledger_mod.Ledger()
    led.feed(sent("t-a", 1, frame.hex()))
    led.feed(parsed("elems", chain), source="victim")
    led.feed(parsed("elems", chain, seq=2))
    check.ok(led.reach_sources.get(("victim", "elems")) == 1 and
             led.reach_sources.get(("subject", "elems")) == 1,
             "a run in the inverted direction has two processes that speak, "
             "and merging them would report the victim's parses of ordinary "
             "traffic as the subject's coverage")

    led = ledger_mod.Ledger()
    led.feed(sent("t-a", 1, frame.hex()))
    led.feed(parsed("elems", chain))
    check.ok(led.reach_attributed == 1,
             "feed() without a source still works: every existing consumer "
             "calls it that way")


# --------------------------------------------------------------------------
# D. the monitor
# --------------------------------------------------------------------------

def check_monitor(root, check):
    print("\nThe victim's output reaches its log AND the ledger")
    with tempfile.TemporaryDirectory() as tmp:
        subj = os.path.join(tmp, "subject.sh")
        vic = os.path.join(tmp, "victim.sh")
        chain = bytes.fromhex(
            "000d686f737461702d7475746f7269616c010882848b960c121824")
        frame = (HDR + chain).hex()
        open(subj, "w").write(
            "#!/bin/sh\n"
            "echo '[fuzz] {\"msg\":\"inventory\",\"daemon\":\"wpa_supplicant\","
            "\"targets\":[\"t-a\"],\"roster\":[{\"name\":\"t-a\",\"guard\":null}],"
            "\"stages\":[]}'\n"
            "echo '[fuzz] {\"msg\":\"fuzz\",\"target\":\"t-a\",\"case_id\":1,"
            "\"frame\":\"mgmt\",\"hdr\":24,\"type\":\"MUT_BYTE\",\"idx\":0,"
            "\"data\":\"%s\"}'\n"
            "sleep 1\n" % frame)
        open(vic, "w").write(
            "#!/bin/sh\n"
            "echo 'ordinary victim chatter'\n"
            "sleep 0.3\n"
            "echo '[fuzz] {\"msg\":\"reach_inventory\",\"daemon\":\"hostapd\","
            "\"parsers\":[\"elems\"],\"walkers\":[20,1],\"roster\":[]}'\n"
            "echo '[fuzz] {\"msg\":\"reach\",\"daemon\":\"hostapd\","
            "\"parser\":\"elems\",\"seq\":0,\"n\":%d,\"got\":%d,\"whole\":1,"
            "\"span\":\"%s\"}'\n"
            "sleep 5\n" % (len(chain), len(chain), chain.hex()))
        for p in (subj, vic):
            os.chmod(p, 0o755)

        log = os.path.join(tmp, "victim.log")
        ledger_json = os.path.join(tmp, "ledger.json")
        r = subprocess.run(
            [sys.executable, os.path.join(root, "monitor_fuzzing.py"),
             "--subject", "/bin/sh " + subj,
             "--victim", "/bin/sh " + vic,
             "--victim-log", log,
             "--repro-dir", os.path.join(tmp, "repro"),
             "--ledger-json", ledger_json, "--quiet"],
            capture_output=True, text=True, timeout=120, cwd=root)

        text = open(log, encoding="utf-8").read() if os.path.exists(log) \
            else ""
        check.ok("ordinary victim chatter" in text,
                 "every line the victim printed is still in its log file, "
                 "verbatim -- reading it here must not cost the log")
        check.ok('"msg":"reach"' in text,
                 "including the [fuzz] ones")

        summary = json.load(open(ledger_json)) if os.path.exists(ledger_json) \
            else {}
        reach = summary.get("reach") or {}
        check.ok(reach.get("measured") is True,
                 "the ledger saw the victim's inventory", r.stdout[-400:])
        check.ok(reach.get("attributed") == 1,
                 "and attributed its parse to the case the subject sent",
                 json.dumps(reach))
        check.ok(reach.get("walkers") == [20, 1],
                 "and carried the walker census into the campaign summary")
        check.ok(summary.get("victim_lines", 0) >= 1,
                 "the weaker signal is counted too, for a victim that is "
                 "not ours")
        check.ok("WHAT THE VICTIM READ" in r.stdout,
                 "and the end-of-run report has the section",
                 r.stdout[-400:])


def main():
    root = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else
                           os.path.join(HERE, "..", ".."))
    sys.path.insert(0, HERE)
    import reach as reach_mod
    ledger_mod = load_ledger(root)

    check = Check()
    check_generator(root, check, reach_mod)
    check_return_rule(root, check, reach_mod)
    check_build_wiring(root, check)
    check_costs_nothing(root, check)
    check_guards_against_binaries(root, check, reach_mod)
    check_ledger(root, check, ledger_mod)
    check_monitor(root, check)

    total = check.passed + check.failed
    print("\n%d of %d checks pass%s"
          % (check.passed, total,
             ", %d skipped" % check.skipped if check.skipped else ""))
    return 1 if check.failed else 0


if __name__ == "__main__":
    sys.exit(main())
