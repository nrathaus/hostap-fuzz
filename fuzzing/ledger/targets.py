#!/usr/bin/env python3
"""Extract the set of fuzz target labels the tree can actually emit.

A target label is the first argument of apply_mutation()/apply_mutation_defer_log().
Most call sites pass a literal, but src/ap/ieee802_11.c passes send_auth_reply()'s
'dbg' parameter straight through, so the literals for every authentication frame
live at send_auth_reply()'s own call sites instead -- as its LAST argument.

Both forms are extracted here. Run with --check to compare the result against the
table compiled into src/common/fuzz.c and fail on drift; a label added at a call
site without being added to the table would otherwise be invisible to the ledger,
which is the one failure mode this guards.

    python3 targets.py [CHECKOUT]            list the labels
    python3 targets.py [CHECKOUT] --check    compare against fuzz.c, exit 1 on drift
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
    ("send_auth_reply", -1),
    ("sme_fuzz_auth_frame", 0),
    ("sme_fuzz_auth_body", 0),
]

SCAN_DIRS = ["src", "hostapd", "wpa_supplicant"]

# The table inside fuzz.c, as emitted by this script's --emit output.
TABLE_RE = re.compile(
    r"static const char \* const fuzz_known_targets\[\] = \{(.*?)\n\};",
    re.S)


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
        yield split_args(tail[:close])


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


def extract(root):
    found = {}
    for d in SCAN_DIRS:
        for dirpath, _, names in os.walk(os.path.join(root, d)):
            for name in names:
                if not name.endswith(".c"):
                    continue
                path = os.path.join(dirpath, name)
                with open(path, encoding="utf-8", errors="replace") as f:
                    src = strip_comments(f.read())
                for fn, pos in SOURCES:
                    if fn not in src:
                        continue
                    for args in call_args(src, fn):
                        if not args:
                            continue
                        lit = literal(args[pos])
                        if lit is not None:
                            found.setdefault(lit, set()).add(
                                os.path.relpath(path, root))
    return found


def table_in_fuzz_c(root):
    path = os.path.join(root, "src", "common", "fuzz.c")
    with open(path, encoding="utf-8") as f:
        m = TABLE_RE.search(f.read())
    if not m:
        return None
    return set(re.findall(r'"((?:[^"\\]|\\.)*)"', m.group(1)))


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    root = os.path.abspath(args[0]) if args else os.getcwd()
    check = "--check" in sys.argv
    emit = "--emit" in sys.argv

    found = extract(root)

    if emit:
        print("static const char * const fuzz_known_targets[] = {")
        for name in sorted(found):
            print('\t"%s",' % name)
        print("};")
        return 0

    if not check:
        for name in sorted(found):
            print("%-28s %s" % (name, " ".join(sorted(found[name]))))
        print("\n%d labels" % len(found))
        return 0

    table = table_in_fuzz_c(root)
    if table is None:
        print("FAIL: no fuzz_known_targets[] table found in src/common/fuzz.c")
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
        print("FAIL: emitted by the tree but absent from fuzz_known_targets[]: %s"
              % name)
    for name in extra:
        print("FAIL: in fuzz_known_targets[] but no call site emits it: %s" % name)
    if missing or extra:
        print("\n%d label(s) differ. Regenerate with: python3 %s %s --emit"
              % (len(missing) + len(extra), os.path.basename(__file__), root))
        return 1
    print("OK: %d labels, table matches the tree" % len(table))
    return 0


if __name__ == "__main__":
    sys.exit(main())
