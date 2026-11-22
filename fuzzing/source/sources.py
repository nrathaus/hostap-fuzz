#!/usr/bin/env python3
"""Extract the source-address roster: which identities a run can vary.

W14's domain is the number of DISTINCT SOURCE ADDRESSES one peer presents.
This is the generator that keeps it honest, and it has three jobs.

  the roster      the first argument of every fuzz_source_addr() call, with
                  the build condition under which its call site exists --
                  derived the way targets.py derives a transmit label's. A
                  run can then say "p2p-dev is absent from this build"
                  rather than reporting it never varied, which is the same
                  four-state distinction the transmit side makes.

  completeness    every function that calls the tree's own address picker
                  also calls the hook, at least as many times. **This is the
                  check that matters**: the failure mode here is not a bug in
                  the hook, it is a NEW call site nobody hooked, and a new
                  call site is an identity that stays fixed all run while the
                  report says the domain is on.

  the rule        the tree builds a locally administered address in exactly
                  two functions, and both are the pickers above. Anything
                  that open-codes those two bit operations somewhere else is
                  a third picker, and this says so. That is what makes
                  "every picker is hooked" a statement about the tree rather
                  than about the list someone happened to write down.

    python3 sources.py [CHECKOUT]            list the identities and guards
    python3 sources.py [CHECKOUT] --check    compare against the tree, exit 1 on drift
    python3 sources.py [CHECKOUT] --emit-c   write src/common/fuzz_sources.h
"""

import os
import re
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "..", "ledger"))
sys.path.insert(0, os.path.join(_HERE, "..", "reach"))

import targets as targets_mod
import reach as reach_mod

HOOK = "fuzz_source_addr"
HEADER = "src/common/fuzz_sources.h"

# The tree's own pickers. Hooking these directly is not possible: they live in
# src/utils/common.c, which is linked into hostapd_cli and wpa_cli as well,
# and those do not link the engine. So the hook sits at the CALLERS, and the
# completeness check below is what replaces the single point it would have
# had.
PICKERS = ("random_mac_addr", "random_mac_addr_keep_oui")

# Where the field's structure is applied. Two lines, in two functions, and
# the check is that there are no others.
STRUCTURE = ("[0] &= 0xfe", "[0] |= 0x02")
STRUCTURE_IN = "src/utils/common.c"

SCAN_DIRS = ["src", "hostapd", "wpa_supplicant"]

LABEL_RE = re.compile(r"^[A-Za-z0-9_-]+$")

# Every label begins with this, and the reason is not cosmetic. The ground
# truth a verifier has for "is this call site in the build" is the label's
# STRING surviving into that file's object -- and the compiler merges a short
# string that is a suffix of a longer one, so a label of "sta" is invisible to
# that check in any object that also holds "...sta". A prefix nothing else in
# the tree ends with keeps the check possible. It also reads correctly: these
# are the addresses a daemon presents as its OWN.
LABEL_PREFIX = "own-"


def picker_calls(body):
    """How many times this function asks the tree for an address."""
    n = 0
    for fn in PICKERS:
        n += len(re.findall(r"\b%s\s*\(" % re.escape(fn), body))
    return n


def scan(root, with_guards=True):
    objcond = targets_mod.object_conditions(root) if with_guards else {}
    labels = {}
    problems = []
    structure = []

    for d in SCAN_DIRS:
        for dirpath, _, names in os.walk(os.path.join(root, d)):
            for name in sorted(names):
                if not name.endswith(".c"):
                    continue
                path = os.path.join(dirpath, name)
                rel = os.path.relpath(path, root).replace(os.sep, "/")
                with open(path, encoding="utf-8", errors="replace") as f:
                    raw = f.read()
                if HOOK not in raw and not any(p in raw for p in PICKERS) \
                        and not any(t in raw for t in STRUCTURE):
                    continue
                src = targets_mod.strip_comments(raw)
                stacks = targets_mod.guard_stack(src) if with_guards else {}
                filecond = [targets_mod.file_guard(rel, name[:-2], objcond)] \
                    if with_guards else []

                for fn, start, end in reach_mod.functions(src):
                    body = src[start:end]
                    want = picker_calls(body)
                    have = len(re.findall(r"\b%s\s*\(" % HOOK, body))
                    if want and have < want:
                        line = src.count("\n", 0, start) + 1
                        problems.append(
                            "%s:%d: %s() asks the tree for %d address(es) "
                            "and reports %d to the sweep"
                            % (rel, line, fn, want, have))
                    for args, off in targets_mod.call_args_at(body, HOOK):
                        lit = targets_mod.literal(args[0]) if args else None
                        line = src.count("\n", 0, start + off) + 1
                        if lit is None:
                            problems.append(
                                "%s:%d: %s() calls %s() with a label that is "
                                "not a literal" % (rel, line, fn, HOOK))
                            continue
                        if not LABEL_RE.match(lit):
                            problems.append(
                                "%s: label %r is outside [A-Za-z0-9_-]"
                                % (rel, lit))
                        if not lit.startswith(LABEL_PREFIX):
                            problems.append(
                                "%s: label %r does not begin with %r, so a "
                                "verifier cannot find it in an object: the "
                                "compiler merges a short string that is a "
                                "suffix of a longer one"
                                % (rel, lit, LABEL_PREFIX))
                        site = targets_mod._and(
                            list(filecond) + list(stacks.get(line, []))) \
                            if with_guards else None
                        e = labels.setdefault(lit, {"sites": [], "guards": []})
                        e["sites"].append("%s:%s()" % (rel, fn))
                        e["guards"].append(site)

                    for t in STRUCTURE:
                        if t in body:
                            structure.append((rel, fn))
                            break

    # The two bit operations belong to the tree's own pickers and nowhere
    # else. A third place that applies them is a third picker.
    stray = sorted({(rel, fn) for rel, fn in structure
                    if rel != STRUCTURE_IN or fn not in PICKERS})
    for rel, fn in stray:
        problems.append(
            "%s: %s() builds a locally administered address outside the "
            "tree's own pickers; it is a source of identities nothing "
            "sweeps" % (rel, fn))

    out = {}
    for lit, e in labels.items():
        out[lit] = {"sites": sorted(set(e["sites"])),
                    "guard": targets_mod._or(e["guards"])
                    if with_guards else None}
    return out, sorted(set(structure)), problems


def emit_c(root):
    found, _, _ = scan(root)
    names = sorted(found)
    out = []
    w = out.append
    w("/*")
    w(" * Source-address identities, and the build conditions that decide")
    w(" * which of them exist in this binary.")
    w(" *")
    w(" * GENERATED by fuzzing/source/sources.py from the call sites of")
    w(" * fuzz_source_addr(), plus the Makefile blocks that decide which")
    w(" * objects are linked. Do not edit: regenerate with")
    w(" *")
    w(" *     python3 fuzzing/source/sources.py . --emit-c \\")
    w(" *             > %s" % HEADER)
    w(" *")
    w(" * and check it has not gone stale with --check.")
    w(" *")
    w(" * The roster is here for the same reason the transmit one is: an")
    w(" * identity this build does not contain and an identity nothing")
    w(" * varied look identical in a report that only counts what it saw,")
    w(" * and they mean opposite things.")
    w(" */")
    w("")
    w("#ifndef FUZZ_SOURCES_H")
    w("#define FUZZ_SOURCES_H")
    w("")
    w("/* Identities this binary can vary. NULL where the build excludes")
    w(" * one; the index still matches fuzz_source_roster[]. */")
    w("static const char * const fuzz_sources_present[] = {")
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
    w("struct fuzz_source_roster_entry {")
    w("\tconst char *name;")
    w("\tconst char *guard;")
    w("};")
    w("")
    w("static const struct fuzz_source_roster_entry fuzz_source_roster[] = {")
    for name in names:
        guard = found[name]["guard"]
        w('\t{ "%s", %s },'
          % (name, ('"%s"' % guard.replace('"', '\\"')) if guard else "NULL"))
    w("};")
    w("")
    w("#endif /* FUZZ_SOURCES_H */")
    return "\n".join(out) + "\n"


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    flags = {a for a in sys.argv[1:] if a.startswith("--")}
    root = os.path.abspath(args[0] if args else os.path.join(_HERE, "..", ".."))

    found, structure, problems = scan(root)

    if "--emit-c" in flags:
        if problems:
            for p in problems:
                print("error: %s" % p, file=sys.stderr)
            return 1
        sys.stdout.write(emit_c(root))
        return 0

    if "--check" in flags:
        bad = list(problems)
        path = os.path.join(root, HEADER)
        if not os.path.exists(path):
            bad.append("%s does not exist; run --emit-c" % HEADER)
        elif open(path, encoding="utf-8").read() != emit_c(root):
            bad.append("%s does not match the tree; run --emit-c" % HEADER)
        if bad:
            for b in bad:
                print("error: %s" % b, file=sys.stderr)
            return 1
        print("OK: %d source identit%s, %d picker(s), header matches the tree"
              % (len(found), "y" if len(found) == 1 else "ies",
                 len(structure)))
        return 0

    for name in sorted(found):
        e = found[name]
        print("%-12s %s" % (name, ", ".join(e["sites"])))
        print("%-12s   guard: %s" % ("", e["guard"] or "(always)"))
    print()
    print("the tree picks an address in: %s"
          % ", ".join("%s()" % fn for _, fn in structure))
    for p in problems:
        print("error: %s" % p, file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
