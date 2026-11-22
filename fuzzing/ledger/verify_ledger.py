#!/usr/bin/env python3
"""Verify W1: the inventory says which targets exist, and where they do not.

Two claims are under test here and they are different in kind.

The first is about the GENERATED TABLE. src/common/fuzz_targets.h wraps each
target label in the build condition of its own call site, so that the inventory
a binary announces is what that binary contains. That condition is derived --
from the #if nesting around the call, from the Makefile block that links the
object, and from the -DHOSTAPD that tells the two daemons apart -- and anything
derived can be derived wrongly. So it is not trusted: for every label and every
daemon, the condition is evaluated by the C preprocessor and compared against
whether the label's string is actually in an object file that was linked. That
comparison is the point of this file.

The second is about the LEDGER'S REPORT. "No cases for this target" has four
causes and only one of them is a gap in the sweep:

    reached   cases were sent
    never     the hook is in a binary that ran and nothing drove it
    absent    the label is in no process of this run, by build or by topology
    unknown   no inventory, so nothing can be told apart

The checks below drive those from synthetic message streams rather than from a
captured run, so they test the rule rather than one log that happened to
exercise it.

    python3 verify_ledger.py [CHECKOUT]
    python3 verify_ledger.py [CHECKOUT] --no-build   skip the checks that need
                                                     a built tree

Exit 0 when every check passes.
"""

import io
import os
import re
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ledger as ledger_mod      # noqa: E402
import targets as targets_mod    # noqa: E402

DAEMONS = [("hostapd", "hostapd"), ("wpa_supplicant", "wpa_supplicant")]

# fuzz.o carries the roster, which names every label in the tree by design, so
# it would answer "present" for all of them in both binaries. It is the one
# object that must not be consulted for presence.
ROSTER_OBJ = os.path.join("src", "common", "fuzz.o")


class Checks:
    def __init__(self):
        self.passed = 0
        self.failed = []
        self.skipped = []

    def ok(self, name, cond, detail=""):
        if cond:
            self.passed += 1
            print("PASS  %s" % name)
        else:
            self.failed.append((name, detail))
            print("FAIL  %s%s" % (name, ("  -- " + detail) if detail else ""))
        return bool(cond)

    def skip(self, name, why):
        self.skipped.append((name, why))
        print("SKIP  %s  -- %s" % (name, why))

    def done(self):
        print()
        print("%d passed, %d failed, %d skipped"
              % (self.passed, len(self.failed), len(self.skipped)))
        return 1 if self.failed else 0


# --------------------------------------------------------------------------
# Group A -- the generated table itself
# --------------------------------------------------------------------------

def group_a(c, root):
    header = os.path.join(root, targets_mod.HEADER)

    c.ok("A1 generated header exists", os.path.exists(header), header)
    if not os.path.exists(header):
        return None

    text = io.open(header, encoding="utf-8").read()
    found = targets_mod.extract(root, with_guards=True)

    c.ok("A2 header is not stale",
         text == targets_mod.emit_c(root),
         "regenerate: targets.py . --emit-c > %s" % targets_mod.HEADER)

    roster = re.search(r"fuzz_target_roster\[\] = \{(.*?)\n\};", text, re.S)
    table = re.search(r"fuzz_known_targets\[\] = \{(.*?)\n\};", text, re.S)
    c.ok("A3 both arrays are present", bool(roster and table))
    if not (roster and table):
        return None

    names = re.findall(r'\{\s*"([^"]+)"', roster.group(1))
    c.ok("A4 roster covers every label the tree emits",
         set(names) == set(found),
         "tree-only %s / roster-only %s"
         % (sorted(set(found) - set(names)), sorted(set(names) - set(found))))

    # Index alignment is what lets a consumer read the two arrays together: a
    # NULL at position i means roster[i] is the label this build excluded.
    # Each guarded entry is one #if/#else/#endif contributing exactly one
    # slot, so counting the arms would double every guarded label -- count the
    # blocks and the bare entries instead.
    blocks = re.findall(
        r'^#if [^\n]*\n\t"([^"]+)",\n#else\n\tNULL,\n#endif$',
        table.group(1), re.M)
    bare = re.findall(r'^\t"([^"]+)",$', table.group(1), re.M)
    bare = [b for b in bare if b not in blocks]
    c.ok("A5 table has exactly one slot per roster entry",
         len(blocks) + len(bare) == len(names),
         "%d guarded + %d bare = %d slots, %d roster entries"
         % (len(blocks), len(bare), len(blocks) + len(bare), len(names)))
    c.ok("A5b the slots are in roster order",
         sorted(blocks + bare) == sorted(names)
         and (blocks + bare) == [n for n in names if n in set(blocks + bare)])

    # Every entry that can be excluded must have both arms, or a false guard
    # would drop the slot and shift every index after it.
    arms = len(re.findall(r"^#else$", table.group(1), re.M))
    guarded = sum(1 for n in names if found.get(n, {}).get("guard"))
    c.ok("A6 every guarded entry has an #else NULL arm",
         arms == guarded, "%d #else, %d guarded labels" % (arms, guarded))

    # A label with no guard at all is a claim that every build has it. That is
    # true for none of them today, and if it ever becomes true the claim should
    # be deliberate rather than the result of a parse that learned nothing.
    unguarded = sorted(n for n in names if not found.get(n, {}).get("guard"))
    c.ok("A7 no label claims to exist in every build",
         not unguarded,
         "unguarded: %s -- a parse that learned nothing looks like this"
         % unguarded)
    return found


# --------------------------------------------------------------------------
# Group B -- the guards predict what is actually in each binary
# --------------------------------------------------------------------------

def daemon_cflags(root, subdir):
    """The -D flags the real build uses for src/common/fuzz.c.

    Taken from the build system rather than from .config, because .config is
    the input and the Makefile derives a great deal from it -- NEED_AP_MLME
    among them, which three guards depend on.
    """
    path = os.path.join(root, subdir)
    if not os.path.exists(os.path.join(path, ".config")):
        return None
    try:
        os.utime(os.path.join(root, "src", "common", "fuzz.c"), None)
        out = subprocess.run(["make", "-n", "V=1", subdir],
                             cwd=path, capture_output=True, text=True,
                             timeout=300).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    for line in out.split("\n"):
        if "common/fuzz.c" in line and line.strip().startswith("cc "):
            return re.findall(r"-D[A-Za-z_][A-Za-z_0-9]*(?:=[^\s]*)?", line)
    return None


def preprocessor_says(guards, flags):
    """Evaluate each guard with the C preprocessor under one build's flags.

    The guard is a C expression, so the only honest evaluator is the thing
    that will evaluate it for real. Re-implementing #if in Python here would
    make this check agree with the generator by construction, which is the one
    thing it must not do.
    """
    src = ["#define MARK(n) __MARK__ n __MARK__"]
    for i, (name, guard) in enumerate(guards):
        src.append("#if %s" % (guard if guard else "1"))
        src.append("MARK(%d)" % i)
        src.append("#endif")
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "probe.c")
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(src) + "\n")
        try:
            out = subprocess.run(["cc", "-E", "-P"] + list(flags) + [path],
                                 capture_output=True, text=True,
                                 timeout=120)
        except (OSError, subprocess.SubprocessError):
            return None
        if out.returncode != 0:
            return None
    live = set()
    for m in re.finditer(r"__MARK__\s+(\d+)\s+__MARK__", out.stdout):
        live.add(int(m.group(1)))
    return live


def linked_objects(root, daemon):
    """Every object this daemon's LINK LINE names.

    Not the contents of build/<daemon>/, which is what this used to be and
    what it looks like it should be. make does not delete the object of a
    file that left OBJS, so a tree that was once built with CONFIG_WPS keeps
    wps.o forever and a directory walk reports it as linked -- which makes
    this a ground truth that agrees with whatever the tree was built with
    last, and that is the one thing a ground truth must not do. It was found
    by exactly that: a build made to compile-test some hooks left objects
    behind and B went red on a tree that was correct.

    None when the link line cannot be read, because guessing here is worse
    than skipping.
    """
    path = os.path.join(root, daemon)
    if not os.path.exists(os.path.join(path, ".config")):
        return None
    try:
        # make prints the link line only when it thinks a link is due, so
        # touch one input the daemon definitely links.
        os.utime(os.path.join(root, "src", "common", "fuzz.c"), None)
        out = subprocess.run(["make", "-n", "V=1", daemon], cwd=path,
                             capture_output=True, text=True,
                             timeout=300).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    for line in out.split("\n"):
        if ("-o " + daemon) not in line:
            continue
        objs = re.findall(r"\S+\.o\b", line)
        if len(objs) > 10:
            return [os.path.normpath(os.path.join(path, o)) for o in objs]
    return None


def objects_of(root, daemon):
    """Every object linked into one daemon, bar the one holding the roster."""
    objs = linked_objects(root, daemon)
    if objs is None:
        return None
    base = os.path.join(root, "build", daemon)
    return [o for o in objs
            if os.path.relpath(o, base) != ROSTER_OBJ]


def object_for(root, daemon, rel):
    """Where a source file's object lands under build/<daemon>/.

    A daemon's own directory is flattened -- wpa_supplicant/offchannel.c
    becomes build/wpa_supplicant/offchannel.o -- while src/ keeps its path."""
    stem = rel[:-2] + ".o"
    for d in ("hostapd/", "wpa_supplicant/"):
        if stem.startswith(d):
            stem = stem[len(d):]
            break
    return os.path.join(root, "build", daemon, stem)


def derived_in_objects(root, daemon, found, names):
    """Ground truth for a label with no string at its call site.

    A label the engine reads out of the frame has no literal to look for: the
    only copy of it is in the generated table, which is compiled into the one
    object this check excludes. So the question becomes the one the string was
    standing in for anyway -- did the compiler build the object that holds the
    call site, and does this daemon link it.
    """
    present = set()
    for name in names:
        if not found[name].get("derived"):
            continue
        for rel in found[name]["files"]:
            if os.path.isfile(object_for(root, daemon, rel)):
                present.add(name)
                break
    return present


def labels_in_objects(objs, names):
    """Which labels actually survived into the linked objects.

    Ground truth for group B, and deliberately not derived from anything the
    generator knows: a label is present when the compiler kept the call site
    that holds its string, in an object this daemon links.
    """
    present = set()
    wanted = set(names)
    for obj in objs:
        try:
            out = subprocess.run(["strings", "-a", obj],
                                 capture_output=True, text=True, timeout=60)
        except (OSError, subprocess.SubprocessError):
            continue
        for line in out.stdout.split("\n"):
            if line in wanted:
                present.add(line)
    return present


def group_b(c, root, found, build):
    if found is None:
        c.skip("B* guards predict the binaries", "no generated header")
        return
    if not build:
        c.skip("B* guards predict the binaries", "--no-build")
        return

    names = sorted(found)
    guards = [(n, found[n]["guard"]) for n in names]

    for subdir, daemon in DAEMONS:
        flags = daemon_cflags(root, subdir)
        if not flags:
            c.skip("B:%s guards predict the binary" % daemon,
                   "no .config or no compile line for %s" % subdir)
            continue
        objs = objects_of(root, daemon)
        if not objs:
            c.skip("B:%s guards predict the binary" % daemon,
                   "nothing built under build/%s" % daemon)
            continue

        live = preprocessor_says(guards, flags)
        if live is None:
            c.skip("B:%s guards predict the binary" % daemon,
                   "the preprocessor refused a guard expression")
            continue
        predicted = {names[i] for i in live}
        literal_names = [n for n in names if not found[n].get("derived")]
        actual = labels_in_objects(objs, literal_names)
        actual |= derived_in_objects(root, daemon, found, names)

        over = sorted(predicted - actual)
        under = sorted(actual - predicted)

        # Over-claiming is the failure that matters: a label the table says is
        # present but the binary does not have is announced in the inventory
        # and then reported as NEVER REACHED forever, which is exactly the
        # confusion the guards exist to remove.
        c.ok("B:%s no label is claimed that the binary lacks" % daemon,
             not over, "claimed but absent: %s" % over)
        # Under-claiming is the other direction: the label is in the binary and
        # the table hides it, so a real target silently stops being counted.
        c.ok("B:%s no label in the binary is hidden by its guard" % daemon,
             not under, "present but not claimed: %s" % under)
        c.ok("B:%s the two daemons do not both claim everything" % daemon,
             len(predicted) < len(names),
             "every label claimed by %s: the daemon split is not working"
             % daemon)

    # The point of the whole exercise: the two binaries must differ. If they
    # claimed the same set, the flat-list problem would still be here under a
    # generated name.
    sets = {}
    for subdir, daemon in DAEMONS:
        flags = daemon_cflags(root, subdir)
        if not flags:
            continue
        live = preprocessor_says(guards, flags)
        if live is not None:
            sets[daemon] = {names[i] for i in live}
    if len(sets) == 2:
        a, b = sets.values()
        c.ok("B9 the two daemons announce different target sets", a != b)
        c.ok("B10 each daemon has targets the other does not",
             bool(a - b) and bool(b - a),
             "only-a %s only-b %s" % (sorted(a - b)[:3], sorted(b - a)[:3]))
    else:
        c.skip("B9/B10 the daemons differ", "fewer than two builds available")


# --------------------------------------------------------------------------
# Group C -- the ledger's four states
# --------------------------------------------------------------------------

def inv(daemon, targets, roster=None, stages=None):
    msg = {"msg": "inventory", "daemon": daemon, "targets": list(targets),
           "stages": list(stages or [])}
    if roster is not None:
        msg["roster"] = [{"name": n, "guard": g} for n, g in roster]
    return msg


def states_of(msgs):
    led = ledger_mod.Ledger()
    for m in msgs:
        led.feed(m)
    return {n: (s, d) for n, s, d in led.target_states()}


def group_c(c):
    roster = [("ap-only", "defined(HOSTAPD)"),
              ("sta-only", "!defined(HOSTAPD)"),
              ("flagged", "defined(CONFIG_X)"),
              ("ran", "defined(HOSTAPD)")]

    st = states_of([inv("hostapd", ["ap-only", "ran", "flagged"], roster),
                    {"msg": "progress", "target": "ran"}])
    c.ok("C1 a target with cases reads reached", st["ran"][0] == "reached")
    c.ok("C2 a target in this binary with no cases reads never",
         st["ap-only"][0] == "never")
    c.ok("C3 a target of the other daemon reads absent, not never",
         st["sta-only"][0] == "absent", str(st.get("sta-only")))
    c.ok("C4 absent carries the build condition that explains it",
         st["sta-only"][1] == "!defined(HOSTAPD)")
    c.ok("C5 a label this build excluded is absent, not never",
         # 'flagged' is announced by this binary, so it is never; the exclusion
         # case is the one the binary does NOT announce.
         st["flagged"][0] == "never")

    st = states_of([inv("hostapd", ["ap-only"], roster)])
    c.ok("C6 a label absent from the inventory is absent",
         st["flagged"][0] == "absent", str(st.get("flagged")))

    # Two hooked processes: the union is what the run could reach, so a label
    # either one announces is never rather than absent.
    st = states_of([inv("hostapd", ["ap-only"], roster),
                    inv("wpa_supplicant", ["sta-only"], roster)])
    c.ok("C7 two daemons union: each one's targets read never",
         st["ap-only"][0] == "never" and st["sta-only"][0] == "never")
    c.ok("C8 a label neither daemon has stays absent",
         st["flagged"][0] == "absent")

    st = states_of([{"msg": "progress", "target": "something"}])
    c.ok("C9 with no inventory every row reads unknown",
         all(s == "unknown" for s, _ in st.values()) and st)

    # The four states must partition: every label in the roster, in an
    # inventory, or seen gets exactly one row and no label is lost.
    led = ledger_mod.Ledger()
    led.feed(inv("hostapd", ["ap-only", "ran"], roster))
    led.feed({"msg": "progress", "target": "ran"})
    led.feed({"msg": "progress", "target": "not-in-any-table"})
    rows = led.target_states()
    seen_names = [n for n, _, _ in rows]
    c.ok("C10 every row appears exactly once",
         len(seen_names) == len(set(seen_names)))
    c.ok("C11 a target seen but in no table is still reported",
         ("not-in-any-table", "reached", "") in rows)
    universe = {n for n, _ in roster} | {"ran", "ap-only", "not-in-any-table"}
    c.ok("C12 the rows cover the whole universe",
         set(seen_names) == universe,
         "missing %s" % sorted(universe - set(seen_names)))

    # Ordering: the interesting state must not be buried below the long tail.
    order = [s for _, s, _ in rows]
    c.ok("C13 never-reached rows sort above reached and absent",
         order == sorted(order, key=lambda s:
                         {"never": 0, "reached": 1, "absent": 2,
                          "unknown": 3}[s]))


# --------------------------------------------------------------------------
# Group D -- per-field domain fractions and the tier
# --------------------------------------------------------------------------

def field_report(msgs):
    led = ledger_mod.Ledger()
    for m in msgs:
        led.feed(m)
    out = io.StringIO()
    led.report(os.devnull, out)
    return out.getvalue(), led


def fuzz_field(field, width, tier, opset, n=1):
    return [{"msg": "fuzz", "type": "MUT_FIELD", "target": "t",
             "field": field, "width": width, "tier": tier, "opset": opset,
             "data": "00" * 32, "at": 0, "before": 0, "after": 1,
             "frame": "mgmt"} for _ in range(n)]


def group_d(c):
    msgs = [inv("hostapd", ["t"], [("t", "defined(HOSTAPD)")])]
    msgs += fuzz_field("auth.status_code", 2, "STRIDE", "v2/7d/STRIDE/251@0",
                       n=270)
    text, led = field_report(msgs)

    c.ok("D1 the stride is read from the opset, not assumed",
         led.stride_modulus() == 251, str(led.stride_modulus()))

    row = [l for l in text.split("\n") if "auth.status_code" in l]
    c.ok("D2 the field has a row", bool(row))
    if row:
        c.ok("D3 the row carries the field's own domain", "65536" in row[0],
             row[0])
        # 270 of 65,536 in this run.
        c.ok("D4 the per-run fraction is cases over the domain",
             "0.41%" in row[0], row[0])
        # 270 x 251 = 67,770, which covers the domain: a complete campaign.
        c.ok("D5 a STRIDE field reports a campaign fraction too",
             "100.00%" in row[0], row[0])
        c.ok("D6 the tier is named on the row", "STRIDE" in row[0], row[0])

    c.ok("D7 the report says how many runs complete the campaign",
         "251 runs at stride 251" in text)

    # A FULL u8 field: one run is the whole domain and both columns say so.
    text, _ = field_report(
        [inv("hostapd", ["t"], [("t", "defined(HOSTAPD)")])]
        + fuzz_field("action.category", 1, "FULL", "v2/7d/FULL/1@0", n=256))
    row = [l for l in text.split("\n") if "action.category" in l]
    c.ok("D8 a FULL field at its whole domain reads 100% in both columns",
         bool(row) and row[0].count("100.00%") == 2, row[0] if row else "")

    # Without an opset there is no stride, so no campaign claim may be made.
    text, led = field_report(
        [inv("hostapd", ["t"], [("t", "defined(HOSTAPD)")])]
        + fuzz_field("auth.status_code", 2, "STRIDE", None, n=270))
    c.ok("D9 no opset means no stride is claimed",
         led.stride_modulus() is None)
    c.ok("D10 and the report says the campaign figure is unknown",
         "unknown, no opset in this log" in text)


# Group E -- W10: one hostile field, and a chain that is still read


def elem_msg(dom, walks, tail, pre, post, **extra):
    m = {"msg": "fuzz", "type": "MUT_ELEM", "target": "t", "dom": dom,
         "eid": 221, "reg": "element id", "shape": "BASIC", "declared": 0,
         "body": 0, "pos": 0, "npos": 4, "at": 30, "copies": 1,
         "walks": walks, "tail": tail, "pre": pre, "post": post,
         "was": 60, "len": 62, "data": "00" * 62, "frame": "mgmt",
         "opset": "v4/10d/STRIDE/251@0"}
    m.update(extra)
    return m


def group_e(c):
    base = [inv("hostapd", ["t"], [("t", "defined(HOSTAPD)")])]

    # A clean run: honest elements everywhere, plus a liar that went last.
    text, led = field_report(
        base + [elem_msg("elem", 1, 0, 3, 4) for _ in range(5)]
        + [elem_msg("elen", 0, 1, 3, 3, pos=3, declared=200)])
    c.ok("E1 the ledger counts the cases that stop the walk",
         led.unwalkable == 1 and led.walk_seen == 6,
         "%d of %d" % (led.unwalkable, led.walk_seen))
    c.ok("E2 and reports none of them absorbed when every one went last",
         led.absorbed == 0 and
         "place an overrun can leave the buffer" in text)
    c.ok("E3 and no case costing the consumer an element",
         led.chain_lost == 0 and
         "0 case(s) cost the consumer an element" in text)

    # The arrangement W10 forbids: a liar in the middle of the chain. The
    # engine will not build it; the ledger must still say so if one ever
    # arrives, or this whole item is an assertion nothing checks.
    text, led = field_report(
        base + [elem_msg("elen", 0, 0, 3, 1, declared=200)])
    c.ok("E4 a case that stops the walk anywhere but last is counted",
         led.absorbed == 1, str(led.absorbed))
    c.ok("E5 and the report says the case space is broken",
         "BROKEN CASE SPACE" in text)
    c.ok("E6 and a chain the case truncated is counted from pre and post",
         led.chain_lost == 1 and "FEWER" in text)

    # An older engine says nothing about either, and the section stays out
    # rather than reporting zeroes it did not measure.
    text, led = field_report(base + [{"msg": "fuzz", "type": "MUT_ELEM",
                                      "target": "t", "dom": "elem",
                                      "eid": 221, "reg": "element id",
                                      "was": 60, "len": 62,
                                      "data": "00" * 62, "frame": "mgmt"}])
    c.ok("E7 a log without the keys makes no claim either way",
         led.walk_seen == 0 and "ONE HOSTILE FIELD" not in text)

    # The two numbers are about different things and must not share a
    # counter. They did, for one commit: a length case that shortened the
    # frame was reported as a chain the consumer could no longer read, and the
    # end-to-end run said 39 where the engine's own messages said none.
    text, led = field_report(
        base + [elem_msg("elem", 1, 0, 3, 4)]
        + [{"msg": "fuzz", "type": "MUT_LEN", "target": "t", "was": 60,
            "len": 40, "data": "00" * 40, "frame": "mgmt"} for _ in range(3)])
    c.ok("E8 a length case that shortened the frame is not a chain the "
         "consumer lost",
         led.chain_lost == 0 and led.truncated == 3,
         "chain_lost=%d truncated=%d" % (led.chain_lost, led.truncated))

    # The clamp is reported where it happened, and only there.
    text, led = field_report(
        base + [elem_msg("mult", 1, 0, 3, 4, copies=2, copies_req=5),
                elem_msg("mult", 1, 0, 3, 4, copies=5)])
    c.ok("E9 a clamped multiplicity case is counted",
         led.clamped == 1 and "clamped to the" in text, str(led.clamped))


# Group F -- W11: the window above the parser's own minimum


def group_f(c, root):
    base = [inv("hostapd", ["t"], [("t", "defined(HOSTAPD)")])]

    c.ok("F1 the ledger takes the minimums from the checkout, not from a "
         "copy of its own",
         bool(ledger_mod.MINIMA) and ledger_mod.MINIMA_DENOM is not None,
         "%d row(s)" % len(ledger_mod.MINIMA))
    sys.path.insert(0, os.path.join(root, "fuzzing", "ledger"))
    import minima as minima_mod
    rows = minima_mod.extract(root)
    c.ok("F2 and it is the same table minima.py emits",
         len(ledger_mod.MINIMA) == len({(r[0], r[1]) for r in rows}),
         "%d against %d" % (len(ledger_mod.MINIMA),
                            len({(r[0], r[1]) for r in rows})))

    aimed = [elem_msg("elen", 0, 1, 3, 3, eid=45, declared=d, min=26,
                      min_known=1, min_rel="LT",
                      min_expr="sizeof(struct ieee80211_ht_capabilities)")
             for d in (24, 26, 27, 200)]
    blind = [elem_msg("elen", 0, 1, 3, 3, eid=1, declared=0, min=0,
                      min_known=0)]
    text, led = field_report(base + aimed + blind)

    c.ok("F3 the ids with a guard are counted apart from those without",
         len(led.aimed) == 1 and len(led.unaimed) == 1,
         "%d aimed, %d not" % (len(led.aimed), len(led.unaimed)))
    c.ok("F4 and only the lengths inside the window count as landing in it",
         led.in_window == 3 and led.aimed_cases == 4,
         "%d of %d" % (led.in_window, led.aimed_cases))
    c.ok("F5 the report carries the guard's own words, not just its number",
         "sizeof(struct ieee80211_ht_capabilities)" in text and
         "-> 26" in text)
    c.ok("F6 and the denominator the run is against",
         "78 length field(s)" in text, "")

    # An id is counted once however many cases it got: a thousand lengths
    # against one element is not coverage of the family.
    text, led = field_report(
        base + [elem_msg("elen", 0, 1, 3, 3, eid=45, declared=26, min=26,
                         min_known=1, min_rel="LT", min_expr="x")
                for _ in range(50)])
    c.ok("F7 an id aimed at fifty times is still one id",
         len(led.aimed) == 1 and led.aimed_cases == 50,
         "%d id(s), %d case(s)" % (len(led.aimed), led.aimed_cases))

    text, led = field_report(base + [{"msg": "fuzz", "type": "MUT_ELEM",
                                      "target": "t", "dom": "elen",
                                      "eid": 45, "reg": "element id",
                                      "was": 60, "len": 62,
                                      "data": "00" * 62, "frame": "mgmt"}])
    c.ok("F8 a log from an engine that does not report a minimum makes no "
         "claim about one",
         not led.aimed and not led.unaimed and
         "AIMED AT THE MINIMUM" not in text)


# Group G -- W12: the span under test, last, and the limit of that claim


def group_g(c):
    base = [inv("hostapd", ["t"], [("t", "defined(HOSTAPD)")])]

    tail = [elem_msg("elen", 0, 1, 3, 1, tail_mode=1, pos=3, declared=200)
            for _ in range(4)]
    tail += [{"msg": "fuzz", "type": "MUT_BYTE_XOR", "target": "t",
              "idx": 7, "mask": 2, "before": 0, "after": 2, "hdr": 24,
              "tail_mode": 1, "cut": 5, "len": 55, "data": "00" * 55,
              "frame": "mgmt"} for _ in range(3)]
    text, led = field_report(base + tail)

    c.ok("G1 the tail case space is counted, from the element cases and the "
         "octet sweep alike",
         led.tail_cases == 7, str(led.tail_cases))
    c.ok("G2 and what it cut", led.cut_cases == 3 and led.cut_octets == 15,
         "%d case(s), %d octet(s)" % (led.cut_cases, led.cut_octets))
    c.ok("G3 the report states the limit rather than claiming detection",
         "does not make it DETECTABLE" in text and
         "depends on" in text)
    c.ok("G4 and the dimension it cost",
         "THE PRICE" in text and "pinning the span removes it" in text)

    # The chain the cut dropped is the point here, and calling it breakage
    # would report a working case space as a broken one.
    c.ok("G5 a chain the cut shortened is not reported as a broken case "
         "space",
         led.chain_lost == 4 and "BROKEN CASE SPACE" not in text and
         "that is the point, not a fault" in text,
         "chain_lost=%d" % led.chain_lost)

    # ... and outside the tail case space it still is.
    text, led = field_report(
        base + [elem_msg("elen", 0, 0, 3, 1, declared=200)])
    c.ok("G6 while outside it, the same shape of case still is",
         "BROKEN CASE SPACE" in text and led.tail_cases == 0)

    text, led = field_report(base + [elem_msg("elem", 1, 0, 3, 4)])
    c.ok("G7 a run that never pinned anything makes no claim about it",
         led.tail_cases == 0 and "THE SPAN UNDER TEST, LAST" not in text)


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    root = os.path.abspath(args[0]) if args else os.getcwd()
    build = "--no-build" not in sys.argv

    print("verify_ledger.py -- W1: the inventory, and the four states")
    print("checkout: %s" % root)
    print()
    c = Checks()
    found = group_a(c, root)
    group_b(c, root, found, build)
    group_c(c)
    group_d(c)
    group_e(c)
    group_f(c, root)
    group_g(c)
    return c.done()


if __name__ == "__main__":
    sys.exit(main())
