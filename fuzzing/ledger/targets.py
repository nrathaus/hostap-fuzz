#!/usr/bin/env python3
"""Extract the set of fuzz target labels the tree can actually emit, and the
build conditions under which each one exists.

A target label is the first argument of apply_mutation()/apply_mutation_defer_log().
Most call sites pass a literal, but src/ap/ieee802_11.c passes send_auth_reply()'s
'dbg' parameter straight through, so the literals for every authentication frame
live at send_auth_reply()'s own call sites instead -- as its LAST argument.

Both forms are extracted here. Run with --check to compare the result against the
table compiled into src/common/fuzz.c and fail on drift; a label added at a call
site without being added to the table would otherwise be invisible to the ledger,
which is the one failure mode this guards.

A label also carries a GUARD: the preprocessor condition under which its call
site is compiled. Two things make one, and both matter:

  site   the #if/#ifdef nesting around the call itself. "sta-auth-fils" is
         inside #ifdef CONFIG_FILS; a build without it has the label in no
         binary at all.
  file   whether the .c file is linked. wpa_supplicant/Makefile adds
         mesh_mpm.o under `ifdef CONFIG_MESH` and the same block does
         `CFLAGS += -DCONFIG_MESH`, so the macro that governs the object is
         testable from inside fuzz.c. That equivalence is what makes a
         generated table exact rather than inferred, and it is checked rather
         than assumed -- see verify_ledger.py, which compares this table
         against the strings actually present in the built binaries.

Why it is worth the trouble: fuzz_known_targets[] is announced once per run as
the inventory, and the ledger subtracts the targets it saw from it to report
what was never reached. An unguarded table makes every binary announce every
label, so hostapd reports the station's labels as NEVER REACHED and the
station reports hostapd's. That is not a missing case -- it is a target that
is not in this process at all, and conflating the two is exactly what W1's
second item says not to do.

    python3 targets.py [CHECKOUT]            list the labels and guards
    python3 targets.py [CHECKOUT] --check    compare against the tree, exit 1 on drift
    python3 targets.py [CHECKOUT] --emit-c   write src/common/fuzz_targets.h
"""

import os
import re
import sys

# (function, which argument carries the label). A pass-through wrapper is listed
# here rather than special-cased below, so adding another one is a one-line change.
SOURCES = [
    ("apply_mutation", 0),
    ("apply_mutation_resize", 0),
    ("apply_mutation_elements", 0),
    ("apply_mutation_defer_log", 0),
    ("apply_mutation_copy", 0),
    ("send_auth_reply", -1),
    ("sme_fuzz_auth_frame", 0),
    ("sme_fuzz_auth_body", 0),
]

# Entry points whose label is not a literal at the call site because it is
# read out of the frame. The roster still has to name every label they can
# produce, or a run announces nothing for them and the ledger cannot tell
# "never reached" from "not in this build" -- the distinction the whole
# four-state report exists for.
#
# The expansion comes from the same generator that gives the engine its
# table, so the roster and the engine cannot disagree about what the set is.
DERIVED = [("fuzz_action_mutate", "action")]

SCAN_DIRS = ["src", "hostapd", "wpa_supplicant"]

# Which binaries a directory's objects can end up in. hostapd/Makefile does an
# unconditional `CFLAGS += -DHOSTAPD` at top level, so that macro is an exact
# test for "this translation unit is being compiled into hostapd" -- which is
# the one distinction no CONFIG_ macro makes and the one that matters most
# here, since src/rsn_supp and wpa_supplicant are simply not linked into
# hostapd at all.
#
# src/ap is in hostapd always and in wpa_supplicant under CONFIG_AP, which is
# a structural fact about the tree rather than a per-file table: anything that
# builds an AP builds src/ap.
DAEMON_GUARD = [
    ("hostapd/", "defined(HOSTAPD)"),
    ("wpa_supplicant/", "!defined(HOSTAPD)"),
    ("src/rsn_supp/", "!defined(HOSTAPD)"),
    ("src/ap/", "(defined(HOSTAPD) || defined(CONFIG_AP))"),
]

# The two Makefiles that decide what is linked, and the daemon each builds.
# They are read separately and never merged: hostapd/Makefile:1282 adds
# ieee802_11.o unconditionally while wpa_supplicant/Makefile:1148 adds it
# under CONFIG_AP, so a single condition over both would make the AP's own
# frames look conditional on an option the AP does not have.
MAKEFILES = [("hostapd/Makefile", "hostapd"),
             ("wpa_supplicant/Makefile", "wpa_supplicant")]

# The table inside fuzz.c, as emitted by this script's --emit output.
TABLE_RE = re.compile(
    r"static const char \* const fuzz_known_targets\[\] = \{(.*?)\n\};",
    re.S)

HEADER = "src/common/fuzz_targets.h"


def guard_stack(src):
    """Line number (1-based) -> list of preprocessor conditions in force.

    Models #if/#ifdef/#ifndef/#elif/#else/#endif. Conditions are returned as C
    expressions so the emitted table can use them verbatim; a condition this
    cannot model is kept as its raw text, which still compiles, rather than
    being dropped. Dropping would claim a site is unconditional, and the one
    direction this must not fail in is claiming more reach than the build has.
    """
    out, stack = {}, []
    for lineno, line in enumerate(src.split("\n"), 1):
        out[lineno] = [c for frame in stack for c in frame[1:2] if c]
        t = line.strip()
        if not t.startswith("#"):
            continue
        m = re.match(r"#\s*(ifdef|ifndef|if|elif|else|endif)\b(.*)", t)
        if not m:
            continue
        kw, rest = m.group(1), m.group(2).strip()
        # Strip a trailing comment: `#endif /* CONFIG_X */`.
        rest = re.sub(r"/\*.*?\*/", "", rest).strip()
        if kw == "ifdef":
            stack.append(["ifdef", "defined(%s)" % rest])
        elif kw == "ifndef":
            stack.append(["ifndef", "!defined(%s)" % rest])
        elif kw == "if":
            stack.append(["if", "(%s)" % rest if rest else None])
        elif kw == "elif":
            if stack:
                prev = stack[-1][1]
                stack[-1] = ["elif",
                             "(!(%s) && (%s))" % (prev, rest) if prev
                             else "(%s)" % rest]
        elif kw == "else":
            if stack:
                prev = stack[-1][1]
                stack[-1] = ["else", "!(%s)" % prev if prev else None]
        elif kw == "endif":
            if stack:
                stack.pop()
        # out[lineno] was recorded before this directive was applied, which
        # is what a call on the same line as a directive would see. No call
        # site does that, but recording it the other way round would be wrong
        # for the #ifdef line itself.
    return out


def _mk_scan(path):
    """Read one Makefile into (conditions per object, var assignments, -D set).

    Three things come out of it, all keyed on the variable names the Makefile
    itself uses:

      objs      object base name -> list of condition stacks under which the
                Makefile adds it. A list, not one condition: several blocks may
                add the same object and any one of them links it.
      assigns   variable -> list of condition stacks under which it is set to y
      defined   variables that reach the compiler as -D, so a C preprocessor
                test for them is meaningful

    `NEED_RSN_AUTHENTICATOR` is the case that makes the third one necessary: it
    gates ../src/ap/wpa_auth.o and is never -D'd, so a guard naming it would be
    false in every build. It has to be resolved back to what sets it.
    """
    objs, assigns, defined = {}, {}, set()
    stack = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            t = line.strip()
            m = re.match(r"ifdef\s+(\w+)", t)
            if m:
                stack.append(m.group(1))
                continue
            if re.match(r"ifn?eq\b|ifndef\b", t):
                stack.append(None)
                continue
            if t.startswith("endif"):
                if stack:
                    stack.pop()
                continue
            if t.startswith("else"):
                # Not modelled: an object added in an else-branch keeps the
                # branch's own condition, which over-claims rather than
                # under-claims. The empirical check is what catches it.
                continue
            m = re.match(r"OBJS\w*\s*\+=\s*(\S+\.o)", t)
            if m:
                base = os.path.basename(m.group(1))[:-2]
                objs.setdefault(base, []).append(list(stack))
                continue
            m = re.match(r"(\w+)\s*=\s*y\s*$", t)
            if m:
                assigns.setdefault(m.group(1), []).append(list(stack))
                continue
            for name in re.findall(r"-D(\w+)", t):
                defined.add(name)
    return objs, assigns, defined


def _resolve(var, assigns, defined, depth=0, seen=None):
    """A Makefile variable as a C preprocessor expression, or None.

    None means "not expressible", which the caller treats as no constraint --
    an over-claim. Under-claiming would be worse: it would report a label as
    not compiled in while it is present, and the whole point of this table is
    to stop a present-but-unreached target being hidden among absent ones.
    """
    if var is None:
        return None
    if var in defined:
        return "defined(%s)" % var
    seen = seen or set()
    if var in seen or depth > 3:
        return None
    seen = seen | {var}
    branches = []
    for stack in assigns.get(var, []):
        terms = [_resolve(v, assigns, defined, depth + 1, seen) for v in stack]
        terms = [t for t in terms if t]
        if not terms:
            return None               # set unconditionally somewhere: no guard
        branches.append(_and(terms))
    if not branches:
        return None
    uniq = sorted(set(branches))
    return uniq[0] if len(uniq) == 1 else " || ".join("(%s)" % b for b in uniq)


def object_conditions(root):
    """(daemon, object base name) -> condition under which it is linked.

    The value is None when the Makefile links the object unconditionally, and
    the key is absent when the Makefile never names it. The two are
    deliberately different: absent means this parse learned nothing and the
    structural rule in DAEMON_GUARD stands alone, while None means the object
    is linked whenever that daemon is built.
    """
    cond = {}
    for rel, daemon in MAKEFILES:
        path = os.path.join(root, rel)
        if not os.path.exists(path):
            continue
        objs, assigns, defined = _mk_scan(path)
        for base, stacks in objs.items():
            branches = []
            for stack in stacks:
                terms = [_resolve(v, assigns, defined) for v in stack]
                terms = [t for t in terms if t]
                if not terms:
                    branches = None     # one unconditional mention links it
                    break
                branches.append(_and(terms))
            if branches is None:
                cond[(daemon, base)] = None
            else:
                uniq = sorted(set(branches))
                cond[(daemon, base)] = uniq[0] if len(uniq) == 1 else \
                    " || ".join("(%s)" % b for b in uniq)
    return cond


def strip_comments(src):
    """Blank out comments, keeping every offset and every string literal.

    Without this a call written inside a comment -- a usage example in a
    docstring, a commented-out call site -- registers as a real one, and the
    table is then "wrong" in a way that can only be fixed by writing the
    phantom into it.
    """
    out = list(src)
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        if c == "/" and i + 1 < n and src[i + 1] in "*/":
            if src[i + 1] == "*":
                j = src.find("*/", i + 2)
                j = n if j < 0 else j + 2
            else:
                j = src.find("\n", i)
                j = n if j < 0 else j
            for k in range(i, j):
                if out[k] != "\n":
                    out[k] = " "
            i = j
            continue
        if c in "\"'":
            j = i + 1
            while j < n:
                if src[j] == "\\":
                    j += 2
                    continue
                if src[j] == c:
                    break
                j += 1
            i = min(j + 1, n)
            continue
        i += 1
    return "".join(out)


def split_args(text):
    """Split a call's argument text on top-level commas."""
    args, depth, cur, i = [], 0, [], 0
    while i < len(text):
        c = text[i]
        if c == '"':                      # a string literal may contain commas
            j = i + 1
            while j < len(text):
                if text[j] == "\\":
                    j += 2
                    continue
                if text[j] == '"':
                    break
                j += 1
            cur.append(text[i:j + 1])
            i = j + 1
            continue
        if c in "([":
            depth += 1
        elif c in ")]":
            depth -= 1
        if c == "," and depth == 0:
            args.append("".join(cur))
            cur = []
        else:
            cur.append(c)
        i += 1
    args.append("".join(cur))
    return [a.strip() for a in args]


def call_args(src, fn):
    """Yield the argument list of every call to 'fn', across line breaks."""
    for args, _ in call_args_at(src, fn):
        yield args


def call_args_at(src, fn):
    """As call_args(), but yields (args, offset of the call)."""
    for m in re.finditer(r"\b%s\s*\(" % re.escape(fn), src):
        # A declaration or definition, not a call.
        line_start = src.rfind("\n", 0, m.start()) + 1
        if re.match(r"\s*(static\s+)?\w[\w \t*]*\b%s\s*\(" % re.escape(fn),
                    src[line_start:m.end()]) and "=" not in src[line_start:m.start()]:
            tail = src[m.end():]
            close = _match_paren(tail)
            if close is not None and re.match(r"\s*\{", tail[close + 1:]):
                continue        # definition: the body follows
        tail = src[m.end():]
        close = _match_paren(tail)
        if close is None:
            continue
        yield split_args(tail[:close]), m.start()


def _match_paren(text):
    depth, i = 0, 0
    while i < len(text):
        c = text[i]
        if c == '"':
            j = i + 1
            while j < len(text):
                if text[j] == "\\":
                    j += 2
                    continue
                if text[j] == '"':
                    break
                j += 1
            i = j + 1
            continue
        if c == "(":
            depth += 1
        elif c == ")":
            if depth == 0:
                return i
            depth -= 1
        i += 1
    return None


def literal(arg):
    """The string a C argument denotes, or None if it is not a plain literal."""
    parts = re.findall(r'"((?:[^"\\]|\\.)*)"', arg)
    if not parts:
        return None
    if re.sub(r'"(?:[^"\\]|\\.)*"', "", arg).strip():
        return None             # concatenated with something non-literal
    return "".join(parts)


def file_guard(rel, base, objcond):
    """The condition under which this translation unit is in a binary at all.

    Composed per daemon rather than globally, because the same object can be
    unconditional in one Makefile and gated in the other:

        hostapd:        OBJS += ../src/ap/ieee802_11.o      (unconditional)
        wpa_supplicant: OBJS += ../src/ap/ieee802_11.o      under CONFIG_AP

    so the answer is "in hostapd always, in the supplicant under CONFIG_AP",
    which no single conjunction says.
    """
    can = {"hostapd": True, "wpa_supplicant": True}
    for prefix, guard in DAEMON_GUARD:
        if rel.startswith(prefix):
            if guard == "defined(HOSTAPD)":
                can["wpa_supplicant"] = False
            elif guard == "!defined(HOSTAPD)":
                can["hostapd"] = False
            break

    terms = []
    for daemon, tag in (("hostapd", "defined(HOSTAPD)"),
                        ("wpa_supplicant", "!defined(HOSTAPD)")):
        if not can[daemon]:
            continue
        key = (daemon, base)
        extra = objcond.get(key)
        if key not in objcond:
            # This Makefile never names the object. Nothing was learned, so
            # nothing is claimed beyond the daemon itself.
            terms.append(tag)
        elif extra is None:
            terms.append(tag)
        else:
            terms.append("(%s)" % _and([tag, extra]))

    if not terms:
        return None
    if len(terms) == 2 and terms == ["defined(HOSTAPD)", "!defined(HOSTAPD)"]:
        return None                       # both, unconditionally: no guard
    return terms[0] if len(terms) == 1 else " || ".join(terms)


def _and(conds):
    """Conjunction, parenthesising any term that contains a disjunction.

    C gives && higher precedence than ||, so joining
    "A || B" with "C" unparenthesised yields "A || (B && C)" -- which for a
    daemon-split guard means one daemon silently escapes every later
    condition. That is a wrong table that compiles, which is the worst kind.
    """
    conds = [c for c in conds if c]
    if not conds:
        return None
    if len(conds) == 1:
        return conds[0]
    return " && ".join("(%s)" % c if "||" in c else c for c in conds)


def _or(conds):
    """None means unconditional, and unconditional absorbs everything.

    One unguarded call site is enough for the label to exist in the build, so
    OR-ing a guard with nothing yields nothing. Getting this backwards would
    guard a label that is always present and report it as not compiled in.
    """
    conds = list(conds)
    if any(c is None for c in conds):
        return None
    uniq = sorted(set(conds))
    if not uniq:
        return None
    return uniq[0] if len(uniq) == 1 else " || ".join(
        "(%s)" % c for c in uniq)


_derived_cache = {}


def derived_labels(root, kind):
    """Every label an entry point that reads its label from the frame can
    produce, from the generator that gives the engine the same table."""
    if kind in _derived_cache:
        return _derived_cache[kind]
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import registries as registries_mod
    if kind != "action":
        raise ValueError("no expansion for derived labels of kind %r" % kind)
    labels = sorted({row[3] for row in registries_mod.action_labels(root)})
    # The one the generated table names for a category it could not name.
    labels.append("act-other")
    _derived_cache[kind] = sorted(set(labels))
    return _derived_cache[kind]


def extract(root, with_guards=False):
    """label -> set of files, or label -> {"files": ..., "guard": ...}."""
    objcond = object_conditions(root) if with_guards else {}
    found, guards = {}, {}
    # Labels with no string at the call site, because the call site reads them
    # out of the frame. A consumer checking the table against the binaries has
    # to look for the OBJECT rather than for the string.
    derived_from = set()
    for d in SCAN_DIRS:
        for dirpath, _, names in os.walk(os.path.join(root, d)):
            for name in names:
                if not name.endswith(".c"):
                    continue
                path = os.path.join(dirpath, name)
                rel = os.path.relpath(path, root).replace(os.sep, "/")
                with open(path, encoding="utf-8", errors="replace") as f:
                    src = strip_comments(f.read())
                stacks = guard_stack(src) if with_guards else {}
                filecond = [file_guard(rel, name[:-2], objcond)] \
                    if with_guards else []
                for fn, pos in SOURCES:
                    if fn not in src:
                        continue
                    for args, off in call_args_at(src, fn):
                        if not args:
                            continue
                        lit = literal(args[pos])
                        if lit is None:
                            continue
                        found.setdefault(lit, set()).add(rel)
                        if with_guards:
                            line = src.count("\n", 0, off) + 1
                            site = _and(list(filecond) +
                                        list(stacks.get(line, [])))
                            guards.setdefault(lit, []).append(site)

                for fn, kind in DERIVED:
                    if fn not in src:
                        continue
                    derived_from.update(derived_labels(root, kind))
                    for _, off in call_args_at(src, fn):
                        line = src.count("\n", 0, off) + 1
                        site = _and(list(filecond) +
                                    list(stacks.get(line, []))) \
                            if with_guards else None
                        for lit in derived_labels(root, kind):
                            found.setdefault(lit, set()).add(rel)
                            if with_guards:
                                guards.setdefault(lit, []).append(site)
    if not with_guards:
        return found
    return {name: {"files": sorted(found[name]),
                   "guard": _or(guards.get(name, [])),
                   "derived": name in derived_from}
            for name in found}



def emit_c(root):
    """The generated header: a per-binary table and a tree-wide roster.

    Index-aligned on purpose. fuzz_known_targets[i] is NULL exactly when entry
    i of the roster is not in this build, so the two arrays answer different
    questions about the same label without either needing a search:

        roster[i].name          every label the tree has
        fuzz_known_targets[i]   the ones this binary can actually emit
        roster[i].guard         why, when it cannot

    A NULL hole rather than a shorter array is what keeps that alignment, and
    it also sidesteps a build where every guard is false leaving a zero-length
    array, which C does not have.
    """
    found = extract(root, with_guards=True)
    names = sorted(found)
    out = []
    w = out.append
    w("/*")
    w(" * Fuzz target labels, and the build conditions that decide which of")
    w(" * them exist in this binary.")
    w(" *")
    w(" * GENERATED by fuzzing/ledger/targets.py from the call sites of")
    w(" * apply_mutation() and friends, plus the Makefile blocks that decide")
    w(" * which objects are linked. Do not edit: regenerate with")
    w(" *")
    w(" *     python3 fuzzing/ledger/targets.py . --emit-c \\")
    w(" *             > %s" % HEADER)
    w(" *")
    w(" * and check it has not gone stale with --check.")
    w(" *")
    w(" * Why the guards are here rather than a flat list: the inventory is")
    w(" * announced once per run and the ledger subtracts what it saw from it")
    w(" * to report what was never reached. A flat list makes every binary")
    w(" * announce every label, so hostapd reports the station's targets as")
    w(" * NEVER REACHED and the station reports hostapd's. A target that is")
    w(" * not in this process is not a target that was missed, and a report")
    w(" * that cannot tell them apart buries the second in the first.")
    w(" */")
    w("")
    w("#ifndef FUZZ_TARGETS_H")
    w("#define FUZZ_TARGETS_H")
    w("")
    w("/* Labels this binary contains. NULL where the build excludes one; the")
    w(" * index still matches fuzz_target_roster[] so the two can be read")
    w(" * together. */")
    w("static const char * const fuzz_known_targets[] = {")
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
    w("/* Every label the tree has, with the condition under which it exists.")
    w(" * Identical in every binary, which is what lets a run say \"absent from")
    w(" * this build\" rather than \"never reached\". */")
    w("struct fuzz_target_roster_entry {")
    w("\tconst char *name;")
    w("\tconst char *guard;")
    w("};")
    w("")
    w("static const struct fuzz_target_roster_entry fuzz_target_roster[] = {")
    for name in names:
        guard = found[name]["guard"]
        w('\t{ "%s", %s },'
          % (name, ('"%s"' % guard.replace('"', '\\"')) if guard else "NULL"))
    w("};")
    w("")
    w("#endif /* FUZZ_TARGETS_H */")
    return "\n".join(out) + "\n"


def table_in_fuzz_c(root):
    """The labels in the generated header's roster.

    The roster rather than fuzz_known_targets[], because the latter is now
    guarded per entry: reading it textually would count a label whose #if is
    false, which is the whole point of the guards. The roster is the complete
    set by construction and is what --check compares against the tree.
    """
    path = os.path.join(root, HEADER)
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as f:
        text = f.read()
    m = re.search(r"fuzz_target_roster\[\] = \{(.*?)\n\};", text, re.S)
    if not m:
        return None
    return set(re.findall(r'\{\s*"((?:[^"\\]|\\.)*)"', m.group(1)))


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    root = os.path.abspath(args[0]) if args else os.getcwd()
    check = "--check" in sys.argv
    emit_h = "--emit-c" in sys.argv
    emit = "--emit" in sys.argv and not emit_h

    if emit_h:
        sys.stdout.write(emit_c(root))
        return 0

    found = extract(root)

    if emit:
        print("static const char * const fuzz_known_targets[] = {")
        for name in sorted(found):
            print('\t"%s",' % name)
        print("};")
        return 0

    if not check:
        guarded = extract(root, with_guards=True)
        for name in sorted(found):
            print("%-28s %-26s %s"
                  % (name, " ".join(sorted(found[name])),
                     guarded[name]["guard"] or "(unconditional)"))
        print("\n%d labels" % len(found))
        return 0

    table = table_in_fuzz_c(root)
    if table is None:
        print("FAIL: no fuzz_target_roster[] found in %s" % HEADER)
        print("      generate it: python3 %s %s --emit-c > %s"
              % (os.path.basename(__file__), root, HEADER))
        return 1

    # fuzz_report_inventory() writes these into JSON without escaping, and
    # fuzz_env_name() folds them into environment variable names. Both are safe
    # only while the labels stay in this charset, so it is checked rather than
    # assumed.
    bad = sorted(n for n in found if not re.fullmatch(r"[A-Za-z0-9_-]+", n))
    for name in bad:
        print("FAIL: label is not [A-Za-z0-9_-]: %r" % name)
    if bad:
        return 1

    missing = sorted(set(found) - table)
    extra = sorted(table - set(found))
    for name in missing:
        print("FAIL: emitted by the tree but absent from the roster: %s" % name)
    for name in extra:
        print("FAIL: in the roster but no call site emits it: %s" % name)

    # The header is generated, so the only way it can be right is to be
    # byte-identical with what this script produces now. A guard that drifted
    # while the label set stayed the same is the failure the label comparison
    # above cannot see, and it is the likely one: upstream moves an #ifdef far
    # more often than it moves a hook.
    stale = False
    path = os.path.join(root, HEADER)
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            if f.read() != emit_c(root):
                stale = True
                print("FAIL: %s is stale -- a guard or label has moved" % HEADER)

    if missing or extra or stale:
        print("\n%d label(s) differ. Regenerate with:"
              % (len(missing) + len(extra)))
        print("  python3 %s %s --emit-c > %s"
              % (os.path.basename(__file__), root, HEADER))
        return 1
    print("OK: %d labels, generated header matches the tree" % len(table))
    return 0


if __name__ == "__main__":
    sys.exit(main())
