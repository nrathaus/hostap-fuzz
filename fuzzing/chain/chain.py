#!/usr/bin/env python3
"""The TLV shapes this product has, read out of the walkers that parse them.

W5b synthesises every element as `u8 id, u8 len, body` and inserts it into a
flat chain. That is ONE of the five chain formats in this tree, and emitting
an attribute under the wrong one is not a weaker case, it is a different one:
the parser takes its length from octets the engine filled with body, so the
length domain the run believes it swept is not the field the parser read.

Measured here rather than asserted:

    surface                     id        length     byte order
    IEEE 802.11 elements        u8        u8         --
    WPS                         u16       u16        big endian
    DPP                         u16       u16        little endian
    NAN                         u8        u16        little endian
    P2P                         u8        u16        little endian

Four of those five are what W9's hooks reach, and until the engine took the
shape as a parameter they got the octet domain and nothing structural. So:

  THE FORMAT comes from each walker's own loop. The first two reads of its
  cursor are the identity and the length, in that order, and the width and the
  byte order of each come from which accessor the tree used -- WPA_GET_BE16,
  WPA_GET_LE16, *pos++. The header size that falls out is CROSS-CHECKED
  against the minimum-remaining test the same loop makes, which is a second,
  independent statement of the same number; a disagreement fails rather than
  picking one.

  THE IDENTITIES come from each protocol's own enum. W6b's rule -- the width
  decides the kind, so a u16 field swept 0..65535 already contains every
  registry member -- is true and, for a SPARSE 16-bit registry, is the stride
  problem of W11 all over again: every defined attribute type is reached, in
  one run out of 251. A generated registry of defined types, synthesised the
  way element ids are, reaches them all in run 1.

  THE GUARD is the Makefile block that decides whether the walker's object is
  linked, for the reason every other roster here carries one: a chain whose
  parser is in no binary is not a chain that was never reached.

WHAT THIS DOES NOT DO, said plainly. A chain format is a property of the
BUFFER, and the engine is told which one by the call site, because only the
call site knows. Three of the five are therefore mechanism without a caller
today: DPP over TCP multiplexes encapsulations whose prefixes differ on one
socket, and the Action convergence point reads a LABEL out of the frame but
not a chain -- naming which protocol's attributes follow which label is the
same category-keyed guess W16c declined to make one level up.

    python3 chain.py [CHECKOUT]            list the formats and registries
    python3 chain.py [CHECKOUT] --emit-c   the generated header
    python3 chain.py [CHECKOUT] --check    compare against the header, exit 1
"""

import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "ledger"))

import targets as targets_mod                             # noqa: E402

HEADER = "src/common/fuzz_chains.h"

# (name, the file and function whose loop walks the chain, the file and enum
# that names its members, and the prefix those members carry).
#
# Declared by NAME and by nothing else: the function is looked up in the tree
# and its loop is read, so a walker that is renamed or rewritten fails the
# check rather than leaving the engine synthesising into a format nothing
# parses. The prefix is a CHECK on the enum, not a filter -- the same rule
# registries.py arrived at after a prefix filter put five element ids in the
# wrong table.
CHAINS = [
    ("wps", "src/wps/wps_attr_parse.c", "wps_parse_msg",
     "src/wps/wps_defs.h", "wps_attribute", "ATTR_"),
    ("dpp", "src/common/dpp.c", "dpp_get_attr",
     "src/common/dpp.h", "dpp_attribute_id", "DPP_ATTR_"),
    ("p2p", "src/p2p/p2p_parse.c", "p2p_parse_p2p_ie",
     "src/common/ieee802_11_defs.h", "p2p_attr_id", "P2P_ATTR_"),
    ("nan", "src/common/nan_de.c", "nan_de_get_attr",
     "src/common/nan_defs.h", "nan_attr_id", "NAN_ATTR_"),
]

# How the tree reads its cursor, and what each accessor says about width and
# byte order. A read this table does not know fails the extraction: the
# alternative is a format built from the reads it happened to recognise, which
# compiles and is wrong.
# (what the read looks like, its width, 1 when least significant octet
# first, and how far the accessor ITSELF moves the cursor). WPA_GET_* reads
# in place and the loop advances explicitly afterwards; *pos++ does both at
# once, which is why the two are not the same row.
READS = [
    (re.compile(r"=\s*WPA_GET_BE16\s*\(\s*pos\s*\)"), 2, 0, 0),
    (re.compile(r"=\s*WPA_GET_LE16\s*\(\s*pos\s*\)"), 2, 1, 0),
    (re.compile(r"=\s*WPA_GET_BE24\s*\(\s*pos\s*\)"), 3, 0, 0),
    (re.compile(r"=\s*WPA_GET_BE32\s*\(\s*pos\s*\)"), 4, 0, 0),
    (re.compile(r"=\s*WPA_GET_LE32\s*\(\s*pos\s*\)"), 4, 1, 0),
    (re.compile(r"=\s*\*pos\s*\+\+"), 1, 0, 1),
]
ADVANCE = re.compile(r"\bpos\s*\+=\s*(\d+)")


class Drift(Exception):
    """A walker no longer has the shape this extractor reads.

    Raised rather than worked around. Every fallback available here produces
    a chain format that compiles and is wrong, and a wrong format is
    invisible: the engine writes a length into octets the parser reads as
    part of the identity, the chain walks anyway, and the run reports a
    length domain it did not sweep."""


def read(root, rel):
    path = os.path.join(root, rel)
    if not os.path.isfile(path):
        raise Drift("%s: not in the checkout" % rel)
    with open(path, encoding="utf-8", errors="replace") as f:
        return f.read()


def strip_comments(src):
    return targets_mod.strip_comments(src)


def func_body(src, name, rel):
    """The body of a function DEFINITION, by brace matching from its '{'."""
    for m in re.finditer(r"\b%s\s*\(" % re.escape(name), src):
        depth, j = 1, m.end()
        while j < len(src) and depth:
            if src[j] == "(":
                depth += 1
            elif src[j] == ")":
                depth -= 1
            j += 1
        if depth:
            continue
        k = j
        while k < len(src) and src[k] in " \t\n":
            k += 1
        if k >= len(src) or src[k] != "{":
            continue                        # a call, or a prototype
        depth, i = 0, k
        while i < len(src):
            if src[i] == "{":
                depth += 1
            elif src[i] == "}":
                depth -= 1
                if depth == 0:
                    return src[k:i + 1]
            i += 1
        raise Drift("%s: %s() does not close" % (rel, name))
    raise Drift("%s: %s() is gone" % (rel, name))


def _block_at(text, open_at):
    depth, i = 0, open_at
    while i < len(text):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[open_at + 1:i]
        i += 1
    raise Drift("a block does not close")


def walk_loop(body, rel, fn):
    """(the loop's condition, its block) for the loop that walks the chain.

    The first while loop whose block reads the cursor at least twice. A
    function that has none is not a walker any more, which is a failure and
    not a default.
    """
    for m in re.finditer(r"\bwhile\s*\(", body):
        depth, j = 1, m.end()
        while j < len(body) and depth:
            if body[j] == "(":
                depth += 1
            elif body[j] == ")":
                depth -= 1
            j += 1
        cond = body[m.end():j - 1]
        k = j
        while k < len(body) and body[k] in " \t\n":
            k += 1
        if k >= len(body) or body[k] != "{":
            continue
        block = _block_at(body, k)
        n = sum(len(rx.findall(block)) for rx, _, _, _ in READS)
        if n >= 2:
            return cond, block
    raise Drift("%s: %s() has no loop that reads its cursor twice, so it no "
                "longer walks a chain this extractor can read" % (rel, fn))


def _consts(root):
    """Integer #defines, for the minimum-remaining cross-check."""
    out = {}
    for rel in ("src/common/nan_defs.h", "src/common/ieee802_11_defs.h",
                "src/wps/wps_defs.h", "src/common/dpp.h",
                "src/common/wpa_common.h"):
        path = os.path.join(root, rel)
        if not os.path.isfile(path):
            continue
        for m in re.finditer(r"(?m)^#define\s+([A-Z][A-Z0-9_]*)\s+"
                             r"(0x[0-9a-fA-F]+|\d+)\s*$",
                             strip_comments(read(root, rel))):
            out.setdefault(m.group(1), int(m.group(2), 0))
    return out


def format_of(root, name, rel, fn):
    """(id_off, id_width, id_le, len_off, len_width, len_le, hdr)."""
    src = strip_comments(read(root, rel))
    cond, block = walk_loop(func_body(src, fn, rel), rel, fn)

    at, fields, done = 0, [], False
    for stmt in block.split(";"):
        if done:
            break
        hit = None
        for rx, width, le, advance in READS:
            m = rx.search(stmt)
            if m and (hit is None or m.start() < hit[0]):
                hit = (m.start(), width, le, advance)
        if hit:
            if len(fields) < 2:
                fields.append((at, hit[1], hit[2]))
            at += hit[3]
            # A self-advancing read of the length closes the header by
            # itself; anything else is closed by the advance that follows.
            if len(fields) == 2 and hit[3]:
                done = True
            continue
        m = ADVANCE.search(stmt)
        if m:
            at += int(m.group(1))
            if len(fields) == 2:
                done = True

    if len(fields) < 2:
        raise Drift("%s: %s() reads its cursor fewer than twice in the walk "
                    "loop, so the identity and the length cannot both be "
                    "placed" % (rel, fn))
    if at <= fields[1][0]:
        raise Drift("%s: %s() does not advance past the length field" %
                    (rel, fn))

    # The same number, stated twice: the header this extractor measured, and
    # the minimum the loop refuses to walk below. A disagreement means one of
    # the two readings is wrong and there is no way to tell which, so neither
    # is used.
    consts = _consts(root)
    want = None
    for text in (cond, block.split(";")[0] if ";" in block else block,
                 block):
        m = re.search(r"end\s*-\s*pos\s*(<|>=)\s*(\w+)", text)
        if not m:
            continue
        tok = m.group(2)
        if re.match(r"^\d+$", tok):
            want = int(tok)
        elif tok in consts:
            want = consts[tok]
        if want is not None:
            break
    if want is None:
        raise Drift("%s: %s()'s walk loop no longer states a minimum number "
                    "of octets, so the header size has nothing to check it "
                    "against" % (rel, fn))
    if want != at:
        raise Drift("%s: %s() reads a %d-octet header but refuses to walk "
                    "below %d octets; the two disagree and this extractor "
                    "will not choose between them" % (rel, fn, at, want))

    # And the length counts what FOLLOWS the header rather than including it.
    # A format where it did would need a different builder, and the engine
    # must not assume which.
    if not re.search(r"\b\w+\s*>\s*end\s*-\s*pos\b", block):
        raise Drift("%s: %s() no longer bounds the declared length by what "
                    "is left after the header, so this extractor cannot say "
                    "what the length counts" % (rel, fn))

    return (fields[0][0], fields[0][1], fields[0][2],
            fields[1][0], fields[1][1], fields[1][2], at)


def registry(root, rel, enum, prefix):
    """[(value, constant name)] of an enum, in value order."""
    src = strip_comments(read(root, rel))
    m = re.search(r"enum\s+%s\s*\{(.*?)\n\}" % re.escape(enum), src, re.S)
    if not m:
        raise Drift("%s: enum %s is gone, so the identity domain for this "
                    "chain has no members" % (rel, enum))
    out, value, carried = {}, 0, 0
    for item in m.group(1).split(","):
        item = item.strip()
        if not item:
            continue
        parts = item.split("=")
        cname = parts[0].strip()
        if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", cname):
            continue
        if len(parts) > 1:
            try:
                value = int(parts[1].strip(), 0)
            except ValueError:
                raise Drift("%s: enum %s member %s has a value this reader "
                            "cannot evaluate" % (rel, enum, cname))
        out.setdefault(value, cname)
        if cname.startswith(prefix):
            carried += 1
        value += 1
    if not out:
        raise Drift("%s: enum %s has no members" % (rel, enum))
    # The prefix is a check that the enum is still the one meant, not a
    # filter on its members: a member named for something else is still a
    # member of this registry, and dropping it would shrink the denominator
    # silently.
    if carried * 2 < len(out):
        raise Drift("%s: fewer than half of enum %s's members carry '%s', so "
                    "this is no longer the registry it was"
                    % (rel, enum, prefix))
    if max(out) > 0xFFFF:
        raise Drift("%s: enum %s has a member past 0xFFFF, which no chain "
                    "format here can carry" % (rel, enum))
    return sorted(out.items())


def _label(const, prefix):
    name = const[len(prefix):] if const.startswith(prefix) else const
    return name.lower().replace("_", "-").strip("-") or "unnamed"


def scan(root):
    """[(name, file, fn, guard, format, [(value, const)])]."""
    objcond = targets_mod.object_conditions(root)
    out = []
    for name, rel, fn, erel, enum, prefix in CHAINS:
        base = os.path.basename(rel)[:-2]
        guard = targets_mod.file_guard(rel, base, objcond)
        out.append((name, rel, fn, guard, format_of(root, name, rel, fn),
                    registry(root, erel, enum, prefix), prefix))
    return out


def emit_c(root):
    rows = scan(root)
    o = []
    w = o.append
    w("/*")
    w(" * The TLV chain formats this product has, read out of the")
    w(" * walkers that parse them.")
    w(" *")
    w(" * GENERATED by fuzzing/chain/chain.py. Do not edit:")
    w(" * regenerate with")
    w(" *")
    w(" *     python3 fuzzing/chain/chain.py . --emit-c \\")
    w(" *             > src/common/fuzz_chains.h")
    w(" *")
    w(" * and check it has not gone stale with --check.")
    w(" *")
    w(" * W5b synthesised every item as 'u8 id, u8 len, body'. That is")
    w(" * one of five formats here, and emitting an attribute under the")
    w(" * wrong one is not a weaker case but a different one: the parser")
    w(" * takes its length from octets the engine filled with body, the")
    w(" * chain walks anyway, and the run reports a length domain it did")
    w(" * not sweep.")
    w(" *")
    w(" * Each format's header size was measured from the walk loop's")
    w(" * reads AND checked against the minimum that loop refuses to walk")
    w(" * below -- the same number stated twice, by two different lines")
    w(" * of the same function.")
    w(" */")
    w("")
    w("#ifndef FUZZ_CHAINS_H")
    w("#define FUZZ_CHAINS_H")
    w("")
    w("/*")
    w(" * The enum is unconditional and the TABLES are not. fuzz.h")
    w(" * names a chain in the signature of the one entry point whose")
    w(" * caller can know which one it is holding, so every file that")
    w(" * includes fuzz.h sees this enum -- and would otherwise also")
    w(" * get five static arrays it never names. fuzz.c defines")
    w(" * FUZZ_CHAINS_TABLES; nothing else does.")
    w(" */")
    w("enum fuzz_chain {")
    w("\t/* The 802.11 element chain: three header shapes selected by")
    w("\t * the id, Fragment elements that continue the one before")
    w("\t * them, and containers whose body is a chain of its own. The")
    w("\t * other formats have none of that, which is not a")
    w("\t * simplification here -- it is what their walkers do. */")
    w("\tFUZZ_CHAIN_ELEM = 0,")
    for name, rel, fn, guard, fmt, reg, prefix in rows:
        w("\tFUZZ_CHAIN_%s," % name.upper())
    w("\tFUZZ_NUM_CHAINS")
    w("};")
    w("")
    w("#endif /* FUZZ_CHAINS_H */")
    w("")
    w("/* A guard of its own, so the tables arrive whatever order the")
    w(" * two includes happen in: fuzz.h pulls this header in for the")
    w(" * enum alone, and fuzz.c then asks for the rest. */")
    w("#if defined(FUZZ_CHAINS_TABLES) && !defined(FUZZ_CHAINS_H_TABLES)")
    w("#define FUZZ_CHAINS_H_TABLES")
    w("")
    w("struct fuzz_chain_fmt {")
    w("\tconst char *name;")
    w("\t/* The function this was read out of, so a record names the")
    w("\t * parser whose format a case was built for. */")
    w("\tconst char *walker;")
    w("\tconst char *file;")
    w("\t/* The build condition of the object that holds the walker.")
    w("\t * A chain whose parser is in no binary is not a chain that")
    w("\t * was never reached. */")
    w("\tconst char *guard;")
    w("\tunsigned char id_off, id_width, id_le;")
    w("\tunsigned char len_off, len_width, len_le;")
    w("\tunsigned char hdr;")
    w("\t/* 1 for the element chain, whose shape is per ITEM and comes")
    w("\t * from fuzz_elem_shapes[] rather than from this row. */")
    w("\tunsigned char elem;")
    w("\tconst unsigned short *ids;")
    w("\tconst char * const *names;")
    w("\tunsigned short nids;")
    w("};")
    w("")
    for name, rel, fn, guard, fmt, reg, prefix in rows:
        w("/* %s: %d member(s) of enum, %s */"
          % (name, len(reg), fn))
        w("static const unsigned short fuzz_chain_ids_%s[] = {" % name)
        for value, const in reg:
            w("\t%d," % value)
        w("};")
        w("static const char * const fuzz_chain_names_%s[] = {" % name)
        for value, const in reg:
            w('\t"%s",' % _label(const, prefix))
        w("};")
        w("")
    w("static const struct fuzz_chain_fmt fuzz_chains[] = {")
    w('\t{ "elem", "__ieee802_11_parse_elems", '
      '"src/common/ieee802_11_common.c", NULL,')
    w("\t  0, 1, 0, 1, 1, 0, 2, 1, NULL, NULL, 0 },")
    for name, rel, fn, guard, fmt, reg, prefix in rows:
        io, iw, ile, lo, lw, lle, hdr = fmt
        w('\t{ "%s", "%s", "%s",' % (name, fn, rel))
        w("\t  %s,"
          % (('"%s"' % guard.replace('"', '\\"')) if guard else "NULL"))
        w("\t  %d, %d, %d, %d, %d, %d, %d, 0,"
          % (io, iw, ile, lo, lw, lle, hdr))
        w("\t  fuzz_chain_ids_%s, fuzz_chain_names_%s, %d },"
          % (name, name, len(reg)))
    w("};")
    w("")
    w("#endif /* FUZZ_CHAINS_TABLES */")
    return "\n".join(o) + "\n"


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    root = os.path.abspath(args[0]) if args else os.getcwd()

    try:
        text = emit_c(root)
        rows = scan(root)
    except Drift as e:
        print("FAIL: %s" % e)
        return 1

    if "--emit-c" in sys.argv:
        sys.stdout.write(text)
        return 0

    path = os.path.join(root, HEADER)
    if "--check" in sys.argv:
        if not os.path.isfile(path):
            print("FAIL: %s does not exist" % HEADER)
            return 1
        with open(path, encoding="utf-8") as f:
            have = f.read()
        if have != text:
            print("FAIL: %s does not match the tree" % HEADER)
            print("Regenerate with: python3 fuzzing/chain/chain.py %s "
                  "--emit-c > %s" % (root, HEADER))
            return 1
        print("OK: %d chain format(s) beside the element chain, %d identity "
              "member(s), header matches the tree"
              % (len(rows), sum(len(r[5]) for r in rows)))
        return 0

    print("%-6s %-24s %-34s %s" % ("chain", "walker", "format", "members"))
    print("%-6s %-24s %-34s %s"
          % ("elem", "__ieee802_11_parse_elems",
             "id u8@0, len u8@1, hdr 2", "241 (three registries)"))
    for name, rel, fn, guard, fmt, reg, prefix in rows:
        io, iw, ile, lo, lw, lle, hdr = fmt
        print("%-6s %-24s %-34s %d"
              % (name, fn,
                 "id u%d@%d %s, len u%d@%d %s, hdr %d"
                 % (iw * 8, io, "le" if ile else "be",
                    lw * 8, lo, "le" if lle else "be", hdr),
                 len(reg)))
        print("%-6s   guard: %s" % ("", guard or "(always)"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
