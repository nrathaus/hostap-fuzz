#!/usr/bin/env python3
"""The lengths this tree's element parser enforces, taken from the parser.

W11. Every domain this engine SAMPLES rather than enumerates has a
distribution, and a uniform one is a decision nobody made. The distribution
that earns its place in a length domain is the window just above each minimum
the parser enforces: a fixed-offset read behind a `len >= N` guard is wrong,
where it is wrong at all, for lengths in N .. N+k for small k and nowhere else.

Those minimums are in the tree, one per element id, in the switch statements of
`src/common/ieee802_11_common.c`. This file reads them out and emits
`src/common/fuzz_minima.h`. Nothing is typed here:

  * The element ids come from `registries.py`, which is the same generated
    registry the synthesis domain walks. A case label this file cannot find a
    member for is drift and raises, rather than being dropped -- a dropped
    label is a window the sweep stops aiming at, and a sweep that stops aiming
    reports exactly as clean as one that never aimed.
  * The guard expressions are evaluated by the COMPILER, against the same
    headers the daemon is built from. `sizeof(struct rsn_mdie)`,
    `2 * ETH_ALEN` and `HE_CAPABILITIES_ELEM_MIN_LEN` are all the tree's own
    arithmetic; re-implementing it here would be a second opinion about a
    number that has only one.
  * Which variable a guard tests, and whether it has already had the extension
    id subtracted from it, are derived from each function's own body.

`--check` regenerates and compares byte for byte, so a minimum that moves
upstream fails the build rather than detuning the sweep in silence.
"""

import os
import re
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import registries as reg                                   # noqa: E402
from registries import Drift                               # noqa: E402

SOURCE = os.path.join("src", "common", "ieee802_11_common.c")
ELEMS_H = os.path.join("src", "common", "ieee802_11_common.h")
HEADER = os.path.join("src", "common", "fuzz_minima.h")

# The three parse functions, each the authority for one registry. Named here
# because which function parses which registry is a fact about this tree that
# no pattern recovers; everything else about them is read out of their bodies.
PARSERS = [
    ("__ieee802_11_parse_elems", "element id"),
    ("ieee802_11_parse_extension", "element id extension"),
    ("ieee802_11_parse_ext_len_elem", "extended length element id"),
]

# The guard relations worth recording. '<' and '!=' both say "shorter than
# this is not parsed"; '>' says the opposite and is kept because the boundary
# is the interesting window either way, and because a consumer that saw only
# the number could not tell the two apart.
RELATIONS = {"<": "LT", "<=": "LE", "!=": "NE", ">": "GT", ">=": "GE"}


def strip_comments(src):
    out, i, n = [], 0, len(src)
    while i < n:
        if src.startswith("/*", i):
            j = src.find("*/", i + 2)
            i = n if j < 0 else j + 2
            out.append(" ")
        elif src.startswith("//", i):
            j = src.find("\n", i)
            i = n if j < 0 else j
        elif src[i] in "\"'":
            q, j = src[i], i + 1
            while j < n and src[j] != q:
                j += 2 if src[j] == "\\" else 1
            out.append(src[i:j + 1])
            i = j + 1
        else:
            out.append(src[i])
            i += 1
    return "".join(out)


def length_var(body, name):
    """(the variable a guard in this function tests, how it relates to the
    element's declared length).

    Two shapes in this tree, and both are read rather than assumed. A parser
    handed the whole element assigns its own local from `->datalen`. The
    extension parser is handed a length that has already been advanced past
    the extension id, and says so with a `--` on its own parameter; the offset
    matters, because the engine builds a DECLARED length and the guard is
    against what is left after the header.
    """
    m = re.search(r"\b(\w+)\s*=\s*(?:le_to_host16\s*\(\s*)?\w+->datalen",
                  body)
    if m:
        return m.group(1), 0

    m = re.search(r"\(([^)]*)\)", body[:body.index("{")] if "{" in body
                  else body)
    # The body alone does not carry the signature, so fall back to the one
    # variable this function decrements before its switch.
    dec = re.search(r"\b(\w+)\s*--\s*;", body)
    if dec:
        return dec.group(1), 1
    raise Drift("%s: %s() has no length variable this file can name"
                % (SOURCE, name))


def switch_body(body, name):
    """The outermost switch statement's body, by brace matching."""
    m = re.search(r"\bswitch\s*\([^)]*\)\s*\{", body)
    if not m:
        raise Drift("%s: %s() has no switch" % (SOURCE, name))
    depth, i = 0, m.end() - 1
    while i < len(body):
        if body[i] == "{":
            depth += 1
        elif body[i] == "}":
            depth -= 1
            if depth == 0:
                return body[m.end():i]
        i += 1
    raise Drift("%s: %s()'s switch does not close" % (SOURCE, name))


CASE = re.compile(r"\bcase\s+([A-Za-z_]\w*)\s*:")


def case_blocks(sw):
    """[( [label names], the statements under them )].

    Labels fall through to the next one, so a run of consecutive `case` labels
    shares one block and every label in it gets the same guard.
    """
    marks = [(m.start(), m.end(), m.group(1)) for m in CASE.finditer(sw)]
    marks.append((len(sw), len(sw), None))
    out, pending = [], []
    for k, (start, end, label) in enumerate(marks):
        if label is None:
            break
        pending.append(label)
        text = sw[end:marks[k + 1][0]]
        if text.strip():                       # not a bare fall-through
            out.append((pending, text))
            pending = []
    if pending:
        raise Drift("%s: case labels with no statements under them: %s"
                    % (SOURCE, pending))
    return out


def terms(cond):
    """A condition's top-level operands, split on && and ||.

    `if (elen < 2 || elen % 2 != 0)` states a minimum of 2 and then something
    else about the same variable. Taking the whole condition as the bound
    would hand the compiler an expression with a free variable in it; taking
    the first operand that compares the length variable takes the bound.
    """
    out, depth, start = [], 0, 0
    i = 0
    while i < len(cond):
        if cond[i] == "(":
            depth += 1
        elif cond[i] == ")":
            depth -= 1
        elif not depth and cond[i:i + 2] in ("&&", "||"):
            out.append(cond[start:i].strip())
            i += 2
            start = i
            continue
        i += 1
    out.append(cond[start:].strip())
    return [t for t in out if t]


def guard_of(text, var):
    """(relation, expression) of the first length guard in a case block.

    First, and only before the block does anything else with the element:
    a guard after an assignment is a guard on a different question, and
    taking it would aim the ladder at a number the parser does not use to
    decide whether to parse at all.
    """
    for m in re.finditer(r"\bif\s*\(", text):
        depth, j = 1, m.end()
        while j < len(text) and depth:
            if text[j] == "(":
                depth += 1
            elif text[j] == ")":
                depth -= 1
            j += 1
        cond = text[m.end():j - 1].strip()
        for term in terms(cond):
            g = re.match(r"^%s\s*(<=|>=|!=|<|>)\s*(.+)$" % re.escape(var),
                         term, re.S)
            if g:
                return RELATIONS[g.group(1)], " ".join(g.group(2).split())
        if "=" in text[:m.start()].replace("==", "").replace("!=", ""):
            break                              # already acted on the element
    return None


def includes(root):
    """The include block of the file the guards come from, verbatim.

    The probe below has to see exactly what the parser sees, and the list of
    what that is already exists at the top of the parser.
    """
    text = reg._read(root, SOURCE)
    head = text[:text.index("\n\n\n")] if "\n\n\n" in text else text[:4000]
    out = re.findall(r'^#include\s+(["<][^">]+[">])', head, re.M)
    if not out:
        raise Drift("%s: no include block" % SOURCE)
    return out


def evaluate(root, exprs):
    """{expression: value}, from the compiler, against the tree's headers."""
    if not exprs:
        return {}
    lines = ["#include %s" % h for h in includes(root)]
    lines += ["#include <stdio.h>", "", "int main(void)", "{"]
    for e in exprs:
        lines.append('\tprintf("%%lld\\n", (long long) (%s));' % e)
    lines += ["\treturn 0;", "}", ""]

    with tempfile.TemporaryDirectory() as tmp:
        src = os.path.join(tmp, "minima_probe.c")
        binary = os.path.join(tmp, "minima_probe")
        with open(src, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        # The build's own two include paths, plus the directory the guards
        # live in: a quoted include resolves against the including file's
        # directory, and the probe is not in that directory. Adding it is
        # what makes the probe see the same "defs.h" the parser does.
        cmd = [os.environ.get("CC", "cc"), "-o", binary, src,
               "-I%s" % os.path.join(root, "src"),
               "-I%s" % os.path.join(root, "src", "utils"),
               "-I%s" % os.path.join(root, os.path.dirname(SOURCE))]
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode:
            raise Drift("the minima probe did not compile:\n%s"
                        % r.stderr.strip()[:1500])
        r = subprocess.run([binary], capture_output=True, text=True)
        if r.returncode:
            raise Drift("the minima probe did not run")
    vals = r.stdout.split()
    if len(vals) != len(exprs):
        raise Drift("the probe printed %d values for %d expressions"
                    % (len(vals), len(exprs)))
    return dict(zip(exprs, (int(v) for v in vals)))


def pairs(root):
    """(pointers, length fields, pairs where both names exist).

    The denominator this item is about: every one of those lengths is a
    sampled domain the moment the engine can set it. Three numbers rather
    than one, because they differ and the difference is real -- two of the
    length fields name something that is not a `const u8 *` in this struct,
    so a reader given only "78" and only "76" would each think the other
    was a miscount.
    """
    text = strip_comments(reg._read(root, ELEMS_H))
    m = re.search(r"struct\s+ieee802_11_elems\s*\{(.*?)\n\};", text, re.S)
    if not m:
        raise Drift("%s: struct ieee802_11_elems is gone" % ELEMS_H)
    body = m.group(1)
    ptrs = set(re.findall(r"\bconst\s+u8\s*\*\s*(\w+)\s*;", body))
    lens = set(re.findall(r"\b(?:size_t|u8|u16)\s+(\w+)_len\s*;", body))
    return len(ptrs), len(lens), len(ptrs & lens)


def extract(root):
    """[(registry, id value, constant name, relation, expression, value,
         how far the guard's variable is past the declared length)]"""
    text = strip_comments(reg._read(root, SOURCE))
    members = reg.extract(root)
    by_name = {}
    for registry, table in members.items():
        for value, names in table.items():
            for n in names:
                by_name[n] = (registry, value)

    rows, exprs = [], []
    for fn, registry in PARSERS:
        body = reg._func(text, fn, SOURCE)
        var, offset = length_var(body, fn)
        for labels, block in case_blocks(switch_body(body, fn)):
            g = guard_of(block, var)
            if not g:
                continue
            rel, expr = g
            for label in labels:
                if label not in by_name:
                    raise Drift(
                        "%s: case %s in %s() is in no generated registry"
                        % (SOURCE, label, fn))
                where, value = by_name[label]
                if where != registry:
                    raise Drift(
                        "%s: case %s is a %s but %s() parses %s"
                        % (SOURCE, label, where, fn, registry))
                rows.append([registry, value, label, rel, expr, None, offset])
            if expr not in exprs:
                exprs.append(expr)

    values = evaluate(root, exprs)
    for row in rows:
        row[5] = values[row[4]]
    rows.sort(key=lambda r: (r[0], r[1]))
    return [tuple(r) for r in rows]


# The registries, in the order the generated identity table walks them, so a
# reader comparing the two tables is comparing like with like.
ORDER = ["element id", "element id extension", "extended length element id"]
SELECTOR = {
    "element id": "FUZZ_MIN_REG_BASIC",
    "element id extension": "FUZZ_MIN_REG_EXT",
    "extended length element id": "FUZZ_MIN_REG_EXTLEN",
}


def emit_c(root, out=sys.stdout):
    rows = extract(root)
    nptr, nlen, npair = pairs(root)

    w = out.write
    w("/*\n")
    w(" * Generated by fuzzing/ledger/minima.py -- do not edit.\n")
    w(" *\n")
    w(" * The lengths %s enforces, one row per\n" % SOURCE)
    w(" * element id that has a guard, with the guard's own expression\n")
    w(" * beside the number so a crash record names what it was aiming at.\n")
    w(" *\n")
    w(" * 'past' is how far the guard's variable is beyond the element's\n")
    w(" * declared length: the extension parser is handed a length that has\n")
    w(" * already been advanced past the extension id, so a guard of N there\n")
    w(" * is a declared length of N + 1. The engine adds it back from the\n")
    w(" * shape table rather than this file guessing a header width.\n")
    w(" *\n")
    w(" * struct ieee802_11_elems holds %d pointer fields and %d length\n"
      % (nptr, nlen))
    w(" * fields, %d of which name the same thing. That is the denominator:\n"
      % npair)
    w(" * every one of those lengths is a sampled domain the moment an\n")
    w(" * element can be synthesised with it, and %d element ids have a\n"
      % len({(r[0], r[1]) for r in rows}))
    w(" * minimum here to aim at.\n")
    w(" */\n\n")
    w("#ifndef FUZZ_MINIMA_H\n")
    w("#define FUZZ_MINIMA_H\n\n")
    w("#define FUZZ_ELEMS_PTRS %d\n" % nptr)
    w("#define FUZZ_ELEMS_LENS %d\n" % nlen)
    w("#define FUZZ_ELEMS_LEN_PAIRS %d\n\n" % npair)

    for i, name in enumerate(ORDER):
        w("#define %s %d\n" % (SELECTOR[name], i))
    w("\n")
    w("struct fuzz_min_entry {\n")
    w("\tu8 reg;\t\t/* which registry the id belongs to */\n")
    w("\tu16 id;\t\t/* the member */\n")
    w("\tu8 past;\t/* octets the guard's variable is past 'declared' */\n")
    w("\tu32 n;\t\t/* what the guard compares against */\n")
    w("\tconst char *rel;\t/* how it compares */\n")
    w("\tconst char *expr;\t/* the tree's own words for n */\n")
    w("\tconst char *name;\t/* the id's constant name */\n")
    w("};\n\n")
    w("static const struct fuzz_min_entry fuzz_minima[] = {\n")
    for registry, value, label, rel, expr, n, past in rows:
        w('\t{ %s, %d, %d, %d, "%s", "%s", "%s" },\n'
          % (SELECTOR[registry], value, past, n, rel,
             expr.replace("\\", "\\\\").replace('"', '\\"'), label))
    w("};\n\n")
    w("#endif /* FUZZ_MINIMA_H */\n")


def check_c(root):
    import io
    buf = io.StringIO()
    emit_c(root, buf)
    path = os.path.join(root, HEADER)
    if not os.path.isfile(path):
        print("MISSING: %s has not been generated" % HEADER)
        return 1
    with open(path, encoding="utf-8") as f:
        have = f.read()
    if have != buf.getvalue():
        print("DRIFT: %s does not match the tree" % HEADER)
        return 1
    rows = extract(root)
    nptr, nlen, npair = pairs(root)
    print("OK: %d minima over %d id(s), %d length field(s) in "
          "struct ieee802_11_elems"
          % (len(rows), len({(r[0], r[1]) for r in rows}), nlen))
    return 0


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    root = os.path.abspath(args[0]) if args else os.getcwd()

    if "--check" in sys.argv:
        return check_c(root)
    if "--emit-c" in sys.argv:
        with open(os.path.join(root, HEADER), "w", encoding="utf-8") as f:
            emit_c(root, f)
        print("wrote %s" % HEADER)
        return 0

    rows = extract(root)
    nptr, nlen, npair = pairs(root)
    print("struct ieee802_11_elems: %d pointers, %d lengths, %d paired"
          % (nptr, nlen, npair))
    for registry, value, label, rel, expr, n, past in rows:
        print("  %-26s %-44s %3d %-3s %-34s %d%s"
              % (registry, label, value, rel, expr, n,
                 "  (+%d past declared)" % past if past else ""))
    print("%d guard(s) over %d id(s)"
          % (len(rows), len({(r[0], r[1]) for r in rows})))
    return 0


if __name__ == "__main__":
    sys.exit(main())
