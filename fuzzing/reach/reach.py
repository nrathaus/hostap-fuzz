#!/usr/bin/env python3
"""Extract the receive-side reach roster: which parsers report what they read.

fuzz.c reports what LEFT the radio. fuzz_reach.c reports what the receiver
READ, and this is the generator that keeps the two honest about each other.

Three things come out of the tree here, and none of them is typed:

  the labels      the first argument of every fuzz_reach() call. A label that
                  is added at a call site and not here would be invisible to
                  the ledger, which is the same failure targets.py exists to
                  stop on the transmit side.

  the guards      the preprocessor condition under which the call site is
                  compiled, plus the Makefile block that decides whether its
                  object is linked. Without them a binary announces parsers it
                  does not contain, and "never reached" stops meaning anything
                  -- the distinction the four-state report is for.

  the walkers     how many functions in the tree walk an element chain at all,
                  against how many of them report. THIS IS THE NUMBER THAT
                  KEEPS THE INSTRUMENT HONEST ABOUT ITSELF: a reach figure of
                  100% over one hooked walker out of thirteen is not coverage,
                  and a report that cannot say so invites exactly that reading.

And one rule is ENFORCED rather than reported:

  **Every return in a hooked function passes through the hook.** A walker with
  an unmarked early return reports fewer parses than happened, and every one
  it fails to report looks like a frame that never arrived. This is the check
  that survives a rebase: upstream adding a `return -1` to a parser we hook
  fails the build rather than quietly halving the number.

    python3 reach.py [CHECKOUT]            list the labels, guards and walkers
    python3 reach.py [CHECKOUT] --check    compare against the tree, exit 1 on drift
    python3 reach.py [CHECKOUT] --emit-c   write src/common/fuzz_reach_targets.h
    python3 reach.py [CHECKOUT] --gaps     the element walkers with no hook
"""

import os
import re
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "..", "ledger"))

import targets as targets_mod

HOOK = "fuzz_reach"
HEADER = "src/common/fuzz_reach_targets.h"

# The file that DEFINES the hook is not a call site of it.
SKIP = {"src/common/fuzz_reach.c"}

SCAN_DIRS = ["src", "hostapd", "wpa_supplicant"]

# What counts as walking an element chain, for the self-report above. These
# are the shared macros in ieee802_11_common.h; anything that walks a chain on
# this product goes through one of them, which is what makes the denominator a
# property of the tree rather than of somebody's reading of it.
WALK_MACROS = ("for_each_element(", "for_each_element_id(",
               "for_each_element_extid(", "for_each_element_completed(")

LABEL_RE = re.compile(r"^[A-Za-z0-9_-]+$")


def functions(src):
    """[(name, start_offset, end_offset)] for every function in a .c file.

    hostap's style puts a function body's opening brace in column 0 and its
    closing brace in column 0, and nothing else in the file does. That makes
    the split exact without a C parser -- and exactness matters here, because
    the return-coverage check below is only as good as its idea of where a
    function ends.
    """
    out = []
    for m in re.finditer(r"^\{$", src, re.M):
        head = src[:m.start()].rstrip()
        # The name is the identifier before the signature's '('.
        depth, i = 0, len(head) - 1
        while i >= 0:
            c = head[i]
            if c == ")":
                depth += 1
            elif c == "(":
                depth -= 1
                if depth == 0:
                    break
            i -= 1
        if i < 0:
            continue
        name = re.search(r"(\w+)\s*$", head[:i])
        if not name:
            continue
        end = re.search(r"^\}$", src[m.end():], re.M)
        if not end:
            continue
        out.append((name.group(1), m.end(), m.end() + end.start()))
    return out


def preceded_by_hook(body, ret_off):
    """True when the return at 'ret_off' is immediately preceded by a hook
    call -- nothing between them but whitespace and preprocessor lines.

    Deliberately strict. 'Somewhere earlier in the function' would be
    satisfied by a hook on a path this return does not take, which is the
    exact mistake that makes an instrument report a number it did not measure.
    """
    pre = body[:ret_off]
    i = pre.rfind(HOOK + "(")
    if i < 0:
        return False
    j = pre.find(";", i)
    if j < 0:
        return False
    for line in pre[j + 1:].splitlines():
        t = line.strip()
        if t and not t.startswith("#"):
            return False
    return True


def scan(root, with_guards=True):
    """label -> {'fn', 'file', 'guard', 'sites'}, plus the walker census."""
    objcond = targets_mod.object_conditions(root) if with_guards else {}
    labels = {}
    walkers, hooked_walkers = set(), set()
    problems = []

    for d in SCAN_DIRS:
        for dirpath, _, names in os.walk(os.path.join(root, d)):
            for name in sorted(names):
                if not name.endswith(".c"):
                    continue
                path = os.path.join(dirpath, name)
                rel = os.path.relpath(path, root).replace(os.sep, "/")
                if rel in SKIP:
                    continue
                with open(path, encoding="utf-8", errors="replace") as f:
                    raw = f.read()
                if HOOK not in raw and not any(w in raw for w in WALK_MACROS):
                    continue
                src = targets_mod.strip_comments(raw)
                stacks = targets_mod.guard_stack(src) if with_guards else {}
                filecond = [targets_mod.file_guard(rel, name[:-2], objcond)] \
                    if with_guards else []

                for fn, start, end in functions(src):
                    body = src[start:end]
                    if any(w in body for w in WALK_MACROS):
                        walkers.add((rel, fn))
                    if HOOK + "(" not in body:
                        continue
                    if any(w in body for w in WALK_MACROS):
                        hooked_walkers.add((rel, fn))

                    # Every return in this function must pass through a hook.
                    for m in re.finditer(r"\breturn\b", body):
                        if not preceded_by_hook(body, m.start()):
                            line = src.count("\n", 0, start + m.start()) + 1
                            problems.append(
                                "%s:%d: %s() returns without reporting reach"
                                % (rel, line, fn))

                    for args, off in targets_mod.call_args_at(body, HOOK):
                        lit = targets_mod.literal(args[0]) if args else None
                        if lit is None:
                            line = src.count("\n", 0, start + off) + 1
                            problems.append(
                                "%s:%d: %s() calls %s() with a label that is "
                                "not a literal" % (rel, line, fn, HOOK))
                            continue
                        if not LABEL_RE.match(lit):
                            problems.append(
                                "%s: label %r is outside [A-Za-z0-9_-]"
                                % (rel, lit))
                        line = src.count("\n", 0, start + off) + 1
                        site = targets_mod._and(
                            list(filecond) + list(stacks.get(line, []))) \
                            if with_guards else None
                        e = labels.setdefault(
                            lit, {"fn": fn, "file": rel, "sites": 0,
                                  "guards": []})
                        if (e["fn"], e["file"]) != (fn, rel):
                            problems.append(
                                "label %r is used by %s() in %s and by %s() "
                                "in %s; one label, one walker"
                                % (lit, e["fn"], e["file"], fn, rel))
                        e["sites"] += 1
                        e["guards"].append(site)

    out = {}
    for lit, e in labels.items():
        out[lit] = {"fn": e["fn"], "file": e["file"], "sites": e["sites"],
                    "guard": targets_mod._or(e["guards"])
                    if with_guards else None}
    return out, sorted(walkers), sorted(hooked_walkers), problems


def emit_c(root):
    found, walkers, hooked, problems = scan(root)
    names = sorted(found)
    out = []
    w = out.append
    w("/*")
    w(" * Receive-side reach roster: the parsers that report what they read,")
    w(" * and the build conditions that decide which of them exist here.")
    w(" *")
    w(" * GENERATED by fuzzing/reach/reach.py from the call sites of")
    w(" * fuzz_reach(), plus the Makefile blocks that decide which objects")
    w(" * are linked. Do not edit: regenerate with")
    w(" *")
    w(" *     python3 fuzzing/reach/reach.py . --emit-c \\")
    w(" *             > %s" % HEADER)
    w(" *")
    w(" * and check it has not gone stale with --check.")
    w(" *")
    w(" * FUZZ_REACH_WALKERS is the honesty figure. It is how many functions")
    w(" * in this tree walk an element chain at all, against how many of them")
    w(" * report doing it. A reach number read without that ratio beside it")
    w(" * is a claim about one parser being quoted as a claim about the")
    w(" * product, and the run announces both so it cannot be.")
    w(" */")
    w("")
    w("#ifndef FUZZ_REACH_TARGETS_H")
    w("#define FUZZ_REACH_TARGETS_H")
    w("")
    w("#define FUZZ_REACH_WALKERS %d" % len(walkers))
    w("#define FUZZ_REACH_WALKERS_HOOKED %d" % len(hooked))
    w("")
    w("/* Parsers this binary contains. NULL where the build excludes one;")
    w(" * the index still matches fuzz_reach_roster[]. */")
    w("static const char * const fuzz_reach_present[] = {")
    for name in names:
        guard = found[name]["guard"]
        if guard:
            w("#if %s" % guard)
            w('\t"%s",' % name)
            w("#else")
            w("\tNULL,")
            w("#endif")
        else:
            w('\t"%s",' % name)
    w("};")
    w("")
    w("/* Every parser the tree instruments, with the function it lives in")
    w(" * and the condition under which it exists. Identical in every binary,")
    w(" * which is what lets a run say \"absent from this build\" rather than")
    w(" * \"never reached\". */")
    w("struct fuzz_reach_roster_entry {")
    w("\tconst char *name;")
    w("\tconst char *fn;")
    w("\tconst char *guard;")
    w("};")
    w("")
    w("static const struct fuzz_reach_roster_entry fuzz_reach_roster[] = {")
    for name in names:
        guard = found[name]["guard"]
        w('\t{ "%s", "%s", %s },'
          % (name, found[name]["fn"],
             ('"%s"' % guard.replace('"', '\\"')) if guard else "NULL"))
    w("};")
    w("")
    w("#endif /* FUZZ_REACH_TARGETS_H */")
    return "\n".join(out) + "\n"


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    flags = {a for a in sys.argv[1:] if a.startswith("--")}
    root = args[0] if args else os.path.join(_HERE, "..", "..")
    root = os.path.abspath(root)

    found, walkers, hooked, problems = scan(root)

    if "--emit-c" in flags:
        if problems:
            for p in problems:
                print("error: %s" % p, file=sys.stderr)
            return 1
        sys.stdout.write(emit_c(root))
        return 0

    if "--gaps" in flags:
        hooked_set = set(hooked)
        print("element walkers with no reach hook:")
        for rel, fn in walkers:
            if (rel, fn) not in hooked_set:
                print("  %-40s %s()" % (rel, fn))
        print()
        print("%d walker(s), %d instrumented" % (len(walkers), len(hooked)))
        return 0

    if "--check" in flags:
        bad = list(problems)
        path = os.path.join(root, HEADER)
        if not os.path.exists(path):
            bad.append("%s does not exist; run --emit-c" % HEADER)
        else:
            with open(path, encoding="utf-8") as f:
                have = f.read()
            if have != emit_c(root):
                bad.append("%s does not match the tree; run --emit-c" % HEADER)
        if bad:
            for b in bad:
                print("error: %s" % b, file=sys.stderr)
            return 1
        print("OK: %d parser(s) instrumented, %d of %d element walkers, "
              "header matches the tree"
              % (len(found), len(hooked), len(walkers)))
        return 0

    for name in sorted(found):
        e = found[name]
        print("%-10s %s() in %s  (%d site%s)"
              % (name, e["fn"], e["file"], e["sites"],
                 "" if e["sites"] == 1 else "s"))
        print("%-10s   guard: %s" % ("", e["guard"] or "(always)"))
    print()
    print("%d element walker(s) in the tree, %d instrumented"
          % (len(walkers), len(hooked)))
    for p in problems:
        print("error: %s" % p, file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
