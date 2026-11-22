#!/usr/bin/env python3
"""Extract the IEEE 802.11 id registries, and the element shapes, from the
checkout's own sources.

Every number this fuzzer treats as a member of a family comes from here, never
from a hand-written list: a literal in an operator table is a lit spot, and a
hand-written list goes stale the first time upstream adds a member. The sources
are the only copy that cannot drift from the tree being fuzzed.

Two things are extracted.

*The registries* -- which numbers are members of which family. Membership is
decided by the SECTION of the header a define sits in, not by its name. The
name is not enough and never was: WLAN_EID_EXT_SUPP_RATES, _CHANSWITCH_ANN,
_CAPAB and _LENGTH are element ids whose names begin with the element id
extension registry's prefix, and WLAN_EID_EXT_LEN_PQC_PARAMETER is a member of
a third registry whose prefix begins with the second one's. A longest-prefix
rule files all five under the wrong family, in both directions at once: four
element ids that are never emitted as element ids, and five numbers emitted as
extension ids that the extension registry does not contain.

*The element shapes* -- how many octets of header an element has, where its
length field is and how wide. This tree has three shapes, and which one applies
is decided by the element id. They are read out of element_hdr_size(),
element_datalen() and the element parse loop, so a fourth shape appearing
upstream fails --check rather than being silently built as the first one.

    python3 registries.py [CHECKOUT]
    python3 registries.py [CHECKOUT] --emit-c > src/common/fuzz_registries.h
    python3 registries.py [CHECKOUT] --check    exit 1 if the sources moved
"""

import os
import re
import sys

HEADER = os.path.join("src", "common", "ieee802_11_defs.h")
COMMON_H = os.path.join("src", "common", "ieee802_11_common.h")
COMMON_C = os.path.join("src", "common", "ieee802_11_common.c")
GENERATED = os.path.join("src", "common", "fuzz_registries.h")


class Drift(Exception):
    """A source no longer has the shape this extractor reads.

    Raised rather than worked around. Every fallback available here -- assume
    the old layout, skip the registry, take the default shape -- produces a
    table that compiles and is wrong, and a wrong table is invisible: an id
    filed under the wrong family is emitted into frames all run long and
    counted against a denominator it is not a member of."""


# (report name, the regex that opens its section, the prefix its members
# usually carry). Order is the report order.
#
# The PREFIX IS NOT A FILTER. It is a check that the banner regex still names
# the block it used to: a section whose defines have mostly stopped carrying
# it is a section that moved, and that fails rather than silently returning
# somebody else's numbers. Members are every #define in the section, because
# the section is what the registry is -- WLAN_TDLS_DISCOVERY_RESPONSE is a
# Public Action code that happens to be named for TDLS, and a prefix filter
# drops it while a section does not.
REGISTRIES = [
    ("authentication algorithm", r"^/\* Authentication algorithms \*/",
     "WLAN_AUTH_"),
    ("status code", r"^/\* Status codes \(", "WLAN_STATUS_"),
    ("reason code", r"^/\* Reason codes \(", "WLAN_REASON_"),
    ("element id", r"^/\* Element IDs \(", "WLAN_EID_"),
    ("element id extension", r"^/\* Element ID Extension \(",
     "WLAN_EID_EXT_"),
    ("extended length element id",
     r"^/\*.*\(Extended Length Element IDs\)", "WLAN_EID_EXT_LEN_"),
    ("action category", r"^/\* Action frame categories \(", "WLAN_ACTION_"),
    ("public action", r"^/\* Public action codes \(", "WLAN_PA_"),
    ("protected dual action",
     r"^/\* Protected Dual of Public Action frames", "WLAN_PROT_"),
]

DEFINE_RE = re.compile(r"^#define\s+(\w+)\s+(.+?)\s*(?:/\*.*)?$")


def _value(text):
    text = text.strip().rstrip("UuLl")
    try:
        return int(text, 0)
    except ValueError:
        return None


def extract(root):
    """{report name: {value: [constant names]}}, from the checkout's header.

    Empty tables when the header is not there. The registries are a
    denominator -- how many members a family has -- and a denominator is the
    one part of this report that cannot be recovered from a log. A run handed
    to someone with the binary and no checkout still has every numerator it
    recorded, so the report says what was sent and declines to say out of how
    many, rather than failing and saying nothing.

    A header that IS there and has lost a section is a different thing, and
    raises: that is drift, not absence."""
    path = os.path.join(root, HEADER)
    out = {name: {} for name, _, _ in REGISTRIES}
    if not os.path.isfile(path):
        return out
    with open(path, encoding="utf-8", errors="replace") as f:
        lines = f.read().splitlines()

    opens = {}
    for name, banner, _ in REGISTRIES:
        rx = re.compile(banner)
        hits = [i for i, line in enumerate(lines) if rx.match(line)]
        if not hits:
            raise Drift("%s: no section comment for '%s' (looked for %s)"
                        % (HEADER, name, banner))
        if len(hits) > 1:
            raise Drift("%s: the section comment for '%s' matches %d lines"
                        % (HEADER, name, len(hits)))
        opens[name] = hits[0]

    # A section ends where the next one begins, and a section begins at a
    # comment in column 0 that has a #define close behind it. That is the
    # header's own structure, so it needs no list of where the sections are
    # -- which is the point, since a list would be the hand-written table
    # this file exists to replace.
    bounds = {i for i, line in enumerate(lines)
              if line.startswith("/*")
              and any(DEFINE_RE.match(x.rstrip())
                      for x in lines[i + 1:i + 5])}

    for name, _, prefix in REGISTRIES:
        start = opens[name]
        members = out[name]
        total = 0
        for i in range(start + 1, len(lines)):
            if i in bounds:
                break
            m = DEFINE_RE.match(lines[i].rstrip("\n"))
            if not m:
                continue
            const, raw = m.group(1), m.group(2)
            total += 1
            val = _value(raw)
            if val is not None and 0 <= val <= 0xFFFF:
                members.setdefault(val, []).append(const)
        if not members:
            raise Drift("%s: section '%s' has no members" % (HEADER, name))
        carried = sum(1 for names in members.values()
                      for c in names if c.startswith(prefix))
        if carried * 2 < total:
            raise Drift("%s: only %d of %d defines in the '%s' section carry "
                        "'%s', so that banner no longer opens that registry"
                        % (HEADER, carried, total, name, prefix))

    return out


# ---------------------------------------------------------------------------
# Action frames: the label is read out of the frame.
# ---------------------------------------------------------------------------
#
# Two functions carry eight protocols between them, with over a hundred call
# sites. Naming each site is a hundred hooks to carry across the monthly
# rebase, and it files every case under whichever caller happened to reach the
# convergence point. So the label comes from the frame: the Action category,
# the code after it for the two categories that have a code registry, and the
# vendor type after THAT for the code that says a vendor follows. Which is how
# the receiver decides what it is holding, so it is how the ledger should.
#
# The nesting -- which registry sits inside which -- is declared here by
# CONSTANT NAME, never by value. The values are generated like everything
# else; what is stated is the structure, and a constant that disappears
# upstream fails the check rather than silently flattening two protocols into
# one label.
NESTED = [
    ("WLAN_ACTION_PUBLIC", "public action", "public",
     "WLAN_PA_VENDOR_SPECIFIC"),
    ("WLAN_ACTION_PROTECTED_DUAL", "protected dual action", "prot-dual",
     "WLAN_PROT_VENDOR_SPECIFIC"),
]

VENDOR_OUI = "OUI_WFA"


def _label(const, *prefixes):
    """A constant's name as a target label: lowercase, dashes, prefix gone."""
    name = const
    for p in prefixes:
        if name.startswith(p):
            name = name[len(p):]
            break
        if p and name.endswith(p):
            name = name[:-len(p)]
            break
    return name.lower().replace("_", "-").strip("-") or "unnamed"


def vendor_types(root):
    """{oui type: [constant names]} for the vendor OUI this tree uses.

    Not a section: these defines are scattered through the header, so they are
    identified by the SUFFIX of their names and by the OUI they carry. Two
    spellings exist and both are read -- a bare type, and the 32-bit
    OUI-and-type that the element form uses -- because a protocol defines
    whichever of the two it needs and DPP, P2P and NAN between them use both.
    """
    path = os.path.join(root, HEADER)
    if not os.path.isfile(path):
        return {}
    with open(path, encoding="utf-8", errors="replace") as f:
        lines = f.read().splitlines()

    oui = None
    out = {}
    for line in lines:
        m = DEFINE_RE.match(line.rstrip())
        if not m:
            continue
        const, raw = m.group(1), m.group(2)
        val = _value(raw)
        if val is None:
            continue
        if const == VENDOR_OUI:
            oui = val
    if oui is None:
        raise Drift("%s: %s is gone, so a vendor-specific Action frame "
                    "cannot be told from any other" % (HEADER, VENDOR_OUI))

    for line in lines:
        m = DEFINE_RE.match(line.rstrip())
        if not m:
            continue
        const, raw = m.group(1), m.group(2)
        val = _value(raw)
        if val is None:
            continue
        if const.endswith("_OUI_TYPE") and 0 <= val <= 0xFF:
            out.setdefault(val, []).append(const)
        elif const.endswith("_IE_VENDOR_TYPE") and (val >> 8) == oui:
            out.setdefault(val & 0xFF, []).append(const)
    if not out:
        raise Drift("%s: no vendor OUI types found" % HEADER)
    return out


def action_labels(root):
    """[(category, code or None, oui type or None, label)].

    Most specific first, so a lookup takes the first match."""
    reg = extract(root)
    vend = vendor_types(root)

    def value_of(const):
        for members in reg.values():
            for val, names in members.items():
                if const in names:
                    return val
        raise Drift("%s: %s is gone, so the Action label cannot be built "
                    "from the frame" % (HEADER, const))

    out = []
    for cat_const, sub_name, short, vendor_const in NESTED:
        cat = value_of(cat_const)
        vendor_code = value_of(vendor_const)
        for v, names in sorted(vend.items()):
            out.append((cat, vendor_code, v,
                        "act-%s-vendor-%s"
                        % (short, _label(names[0], "_OUI_TYPE",
                                         "_IE_VENDOR_TYPE"))))
        for code, names in sorted(reg[sub_name].items()):
            out.append((cat, code, None,
                        "act-%s-%s" % (short, _label(names[0], "WLAN_PA_",
                                                     "WLAN_PROT_", "WLAN_"))))
    for cat, names in sorted(reg["action category"].items()):
        out.append((cat, None, None,
                    "act-%s" % _label(names[0], "WLAN_ACTION_")))
    return out


# ---------------------------------------------------------------------------
# Element shapes.
# ---------------------------------------------------------------------------
#
# 5b built every id as "u8 id, u8 len, body". That is one of three shapes in
# this tree, and the other two are selected by ids the registry above
# contains. Emitting an id under the wrong shape is not a weaker case, it is a
# different one: the parser takes its length from octets the engine filled with
# body, so the length domain the run believes it swept is not the field the
# parser read, and the ledger counts the id as reached either way.

WIDTHS = {"u8": 1, "u16": 2, "u32": 4, "u64": 8,
          "le16": 2, "le32": 4, "le64": 8,
          "be16": 2, "be32": 4, "be64": 8}
LITTLE = ("le16", "le32", "le64")


def _read(root, rel):
    path = os.path.join(root, rel)
    if not os.path.isfile(path):
        raise Drift("%s: not in the checkout" % rel)
    with open(path, encoding="utf-8", errors="replace") as f:
        return f.read()


def _func(text, name, rel):
    """The body of a function definition, by brace matching from its '{'.

    Definitions only. A call to the function appears earlier in the file than
    the definition for every one of these, and matching a call would brace
    match from some unrelated '{' and hand back a region that happens to
    contain most of what is being looked for -- which is how a reader like
    this returns a plausible wrong answer instead of failing."""
    for m in re.finditer(r"\b%s\s*\(" % re.escape(name), text):
        # The parameter list, then whatever follows it.
        depth, j = 1, m.end()
        while j < len(text) and depth:
            if text[j] == "(":
                depth += 1
            elif text[j] == ")":
                depth -= 1
            j += 1
        if depth:
            continue
        k = j
        while k < len(text) and text[k] in " \t\n":
            k += 1
        if k >= len(text) or text[k] != "{":
            continue            # a call, or a prototype
        depth, i = 0, k
        while i < len(text):
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
                if depth == 0:
                    return text[k:i + 1]
            i += 1
        raise Drift("%s: %s() does not close" % (rel, name))
    raise Drift("%s: %s() is gone" % (rel, name))


def _struct(text, name, rel):
    """[(field name, C type)] of a struct, in declaration order."""
    m = re.search(r"struct\s+%s\s*\{(.*?)\n\}" % re.escape(name), text, re.S)
    if not m:
        raise Drift("%s: struct %s is gone" % (rel, name))
    out = []
    for line in m.group(1).splitlines():
        line = re.sub(r"/\*.*?\*/", "", line).strip()
        f = re.match(r"^(\w+)\s+(\w+)(\[\s*\])?\s*;$", line)
        if f:
            out.append((f.group(2), f.group(1), bool(f.group(3))))
    if not out:
        raise Drift("%s: struct %s has no fields this reader understands"
                    % (rel, name))
    return out


def _layout(fields, rel, name):
    """(offsets, total header size, the flexible body member's name)."""
    offs, at, body = {}, 0, None
    for fname, ctype, flexible in fields:
        if flexible:
            body = fname
            break
        if ctype not in WIDTHS:
            raise Drift("%s: struct %s field '%s' has type '%s', which has no "
                        "width here" % (rel, name, fname, ctype))
        offs[fname] = (at, WIDTHS[ctype], ctype in LITTLE)
        at += WIDTHS[ctype]
    if body is None:
        raise Drift("%s: struct %s has no flexible array member, so it is not "
                    "an element header" % (rel, name))
    return offs, at, body


def shapes(root):
    """The element shapes this tree has, read out of its own accessors.

    Returns {"shapes": [...], "selectors": {...}, "defrag": {...}}."""
    ch = _read(root, COMMON_H)
    cc = _read(root, COMMON_C)

    # Which id takes which header struct. element_hdr_size() IS the mapping;
    # it is not re-stated here.
    hdr_fn = _func(ch, "element_hdr_size", COMMON_H)
    special = re.search(r"if\s*\(\s*elem->id\s*==\s*(\w+)\s*\)\s*"
                        r"return\s+sizeof\(struct\s+(\w+)\)", hdr_fn)
    default = re.search(r"return\s+sizeof\(struct\s+(\w+)\)\s*;\s*\}\s*$",
                        hdr_fn)
    if not special or not default:
        raise Drift("%s: element_hdr_size() is no longer one id test and a "
                    "default; the shape table cannot be derived from it"
                    % COMMON_H)
    extlen_id, extlen_struct = special.group(1), special.group(2)
    basic_struct = default.group(1)

    # A second id test would be a fourth shape, and this reader would build it
    # as the default -- silently, which is the whole failure mode here.
    if len(re.findall(r"elem->id\s*==", hdr_fn)) != 1:
        raise Drift("%s: element_hdr_size() tests more than one id, so this "
                    "tree has a shape the generator does not know about"
                    % COMMON_H)

    # Which member of each struct is the length. element_datalen() says, and
    # says the byte order too.
    len_fn = _func(ch, "element_datalen", COMMON_H)
    sp_len = re.search(r"if\s*\(\s*elem->id\s*==\s*%s\s*\).*?"
                       r"(le_to_host16|be_to_host16|le_to_host32)?\s*\(?\s*"
                       r"\(\(const struct %s \*\) elem\)->(\w+)\)?"
                       % (re.escape(extlen_id), re.escape(extlen_struct)),
                       len_fn, re.S)
    df_len = re.search(r"return\s+elem->(\w+)\s*;\s*\}\s*$", len_fn)
    if not sp_len or not df_len:
        raise Drift("%s: element_datalen() no longer names the length member "
                    "of each shape" % COMMON_H)

    basic_fields = _struct(ch, basic_struct, COMMON_H)
    extlen_fields = _struct(ch, extlen_struct, COMMON_H)
    basic_offs, basic_hdr, _ = _layout(basic_fields, COMMON_H, basic_struct)
    extlen_offs, extlen_hdr, extlen_body = _layout(extlen_fields, COMMON_H,
                                                   extlen_struct)

    for member, offs, struct in ((df_len.group(1), basic_offs, basic_struct),
                                 (sp_len.group(2), extlen_offs,
                                  extlen_struct)):
        if member not in offs:
            raise Drift("%s: element_datalen() reads '%s', which struct %s "
                        "does not have" % (COMMON_H, member, struct))

    # The extension shape is not a struct: the ext id is the first octet of
    # the basic shape's BODY, consumed by the handler the parse loop dispatches
    # to. Both halves are read -- which case label, and what that handler does
    # with the first octet -- because the declared length covering the ext id
    # is exactly what makes this shape's minimum 1 rather than 0.
    parse_fn = _func(cc, "__ieee802_11_parse_elems", COMMON_C)
    ext_case = re.search(r"case\s+(\w+):\s*\n\s*if\s*\(\s*(\w*parse_extension)"
                         r"\(pos,\s*elen", parse_fn)
    if not ext_case:
        raise Drift("%s: the element parse loop no longer dispatches an "
                    "extension id to a handler taking (pos, elen)" % COMMON_C)
    ext_id_const, ext_fn_name = ext_case.group(1), ext_case.group(2)
    ext_fn = _func(cc, ext_fn_name, COMMON_C)
    ext_min = re.search(r"if\s*\(\s*elen\s*<\s*(\d+)\s*\)", ext_fn)
    ext_take = re.search(r"(\w+)\s*=\s*\*pos\+\+\s*;\s*\n\s*elen--\s*;",
                         ext_fn)
    if not ext_min or not ext_take:
        raise Drift("%s: %s() no longer takes one octet of the declared "
                    "length as the extension id" % (COMMON_C, ext_fn_name))

    # Fragmentation. Which id continues an element, what declared length makes
    # the parse loop look for one, and the length at which a fragment stops
    # being honoured.
    defrag_fn = _func(cc, "ieee802_11_defrag", COMMON_C)
    frag = re.search(r"pos\[0\]\s*==\s*(\w+)\s*&&\s*pos\[1\]", defrag_fn)
    mins = re.search(r"min_defrag_len\s*=\s*\w+\s*\?\s*(\d+)\s*:\s*(\d+)",
                     defrag_fn)
    if not frag or not mins:
        raise Drift("%s: ieee802_11_defrag() no longer walks a fragment id "
                    "with a minimum length" % COMMON_C)
    parent = re.search(r"if\s*\(elen\s*==\s*(\d+)\s*&&\s*total_len\)",
                       parse_fn)
    if not parent:
        raise Drift("%s: the parse loop no longer has a declared length at "
                    "which it collects fragments" % COMMON_C)

    sub_fn = _func(cc, "ieee802_11_defrag_mle_subelem", COMMON_C)
    sub = re.search(r"pos\[0\]\s*==\s*(\w+)\s*&&\s*pos\[1\]", sub_fn)
    sub_min = re.search(r"min_defrag_len\s*=\s*(\d+)", sub_fn)
    if not sub or not sub_min:
        raise Drift("%s: ieee802_11_defrag_mle_subelem() no longer walks a "
                    "fragment id inside an element's body" % COMMON_C)

    bl_off, bl_w, bl_le = basic_offs[df_len.group(1)]
    xl_off, xl_w, xl_le = extlen_offs[sp_len.group(2)]

    # The extension id of the extended-length shape is whatever member of its
    # struct the extended-length handler reads as the id.
    xfn = _func(cc, "ieee802_11_parse_ext_len_elem", COMMON_C)
    xid = re.search(r"=\s*\w*_to_host\d+\(elem->(\w+)\)", xfn)
    if not xid or xid.group(1) not in extlen_offs:
        raise Drift("%s: the extended-length handler no longer reads an id "
                    "member of struct %s" % (COMMON_C, extlen_struct))
    xi_off, xi_w, xi_le = extlen_offs[xid.group(1)]

    out = [
        # name, hdr, len_off, len_width, len_le, extid_off, extid_width,
        # len_covers_extid, selector constant (None = the default shape)
        dict(name="BASIC", hdr=basic_hdr, len_off=bl_off, len_width=bl_w,
             len_le=bl_le, extid_off=0, extid_width=0, extid_le=0, covers=0,
             sel=None, why="struct %s" % basic_struct),
        dict(name="EXT", hdr=basic_hdr + 1, len_off=bl_off, len_width=bl_w,
             len_le=bl_le, extid_off=basic_hdr, extid_width=1, extid_le=0,
             covers=1, sel=ext_id_const,
             why="struct %s plus the octet %s() takes" % (basic_struct,
                                                          ext_fn_name)),
        dict(name="EXTLEN", hdr=extlen_hdr, len_off=xl_off, len_width=xl_w,
             len_le=xl_le, extid_off=xi_off, extid_width=xi_w,
             extid_le=1 if xi_le else 0, covers=0, sel=extlen_id,
             why="struct %s" % extlen_struct),
    ]
    if int(ext_min.group(1)) != out[1]["covers"] * out[1]["extid_width"]:
        raise Drift("%s: %s() rejects below %s octets, but the ext id it then "
                    "takes is %d octet(s) of the declared length"
                    % (COMMON_C, ext_fn_name, ext_min.group(1),
                       out[1]["extid_width"]))

    return {
        "shapes": out,
        "frag_id": frag.group(1),
        "frag_parent_len": int(parent.group(1)),
        "defrag_min": (int(mins.group(1)), int(mins.group(2))),
        "sub_frag_id": sub.group(1),
        "sub_defrag_min": int(sub_min.group(1)),
    }


# The registries the synthesis engine needs compiled in, in the order the
# identity domain walks them. Each segment carries the shape its registry
# implies: an element id is built under whatever shape its own value selects,
# an extension id under the extension shape, an extended-length id under the
# extended-length shape.
C_TABLES = [
    ("element id", "fuzz_elem_ids", "u8"),
    ("element id extension", "fuzz_elem_ext_ids", "u8"),
    ("extended length element id", "fuzz_elem_extlen_ids", "u16"),
]

C_HEADER = """/*
 * GENERATED -- do not edit.
 *
 * The IEEE 802.11 id registries and element shapes, extracted from
 * src/common/ieee802_11_defs.h, ieee802_11_common.h and ieee802_11_common.c by
 * fuzzing/ledger/registries.py. Regenerate with:
 *
 *\tpython3 fuzzing/ledger/registries.py . --emit-c > src/common/fuzz_registries.h
 *
 * and check it with --check, which fails when a source has gained a member or
 * changed a shape this file does not have. That check is the point of
 * generating it: upstream adds members regularly, and a table that quietly
 * falls behind re-narrows the very spotlight the synthesis exists to widen --
 * silently, because a registry member that is never emitted looks exactly like
 * one that is, and an id built under the wrong shape looks exactly like one
 * built under the right one.
 *
 * Membership comes from the SECTION of the header each define sits in, not
 * from its name. Five constants in this tree are named for one registry and
 * belong to another.
 */

#ifndef FUZZ_REGISTRIES_H
#define FUZZ_REGISTRIES_H

#include "ieee802_11_defs.h"

"""


def emit_c(root, out=sys.stdout):
    data = extract(root)
    sh = shapes(root)
    out.write(C_HEADER)

    for name, symbol, ctype in C_TABLES:
        members = data.get(name, {})
        values = sorted(members)
        out.write("/* %s: %d distinct value(s) */\n" % (name, len(values)))
        out.write("static const %s %s[] = {\n" % (ctype, symbol))
        for i in range(0, len(values), 12):
            row = values[i:i + 12]
            out.write("\t" + " ".join("%d," % v for v in row) + "\n")
        out.write("};\n\n")

        # The same values, under the names the tree gives them. Parallel to
        # the table above and generated from the same lines, so a name cannot
        # drift from the id it describes -- which a second hand-written table
        # would do the first time upstream renamed one, and would do
        # invisibly, since a wrong name is still a name.
        #
        # This is what a crash record is read with: "element id 88" is a
        # number someone has to go and look up, and the lookup is in a header
        # that is not in the bug report.
        out.write("/* %s, named. Aliases are listed in the comment. */\n"
                  % name)
        out.write("static const char * const %s_names[] = {\n" % symbol)
        for v in values:
            names = members[v]
            out.write("\t\"%s\",%s\n"
                      % (names[0],
                         ("\t/* = %s */" % " = ".join(names[1:]))
                         if len(names) > 1 else ""))
        out.write("};\n\n")

    out.write("""/*
 * Element shapes. Which one an id selects is read from element_hdr_size() and
 * from the parse loop's extension dispatch, never decided here.
 *
 *\thdr\t\toctets from the id octet to the body
 *\tlen_off\t\twhere the declared length sits inside that header
 *\tlen_width\t1 or 2 -- and a 2 is a 65,536-value domain, which is
 *\t\t\twhy an element header needs the reduction tiers
 *\textid_off\twhere the sub-registry id sits, 0 when there is none
 *\tcovers\t\tthe declared length includes the sub-registry id, so a
 *\t\t\tdeclared length below extid_width leaves the id the
 *\t\t\tidentity domain just selected out of the frame
 */
""")
    out.write("enum fuzz_elem_shape {\n")
    for s in sh["shapes"]:
        out.write("\tFUZZ_SHAPE_%s,\n" % s["name"])
    out.write("\tFUZZ_NUM_SHAPES\n};\n\n")

    out.write("struct fuzz_elem_shape_info {\n"
              "\tconst char *name;\n"
              "\tu8 hdr;\n"
              "\tu8 len_off;\n"
              "\tu8 len_width;\n"
              "\tu8 len_le;\n"
              "\tu8 extid_off;\n"
              "\tu8 extid_width;\n"
              "\tu8 extid_le;\n"
              "\tu8 covers;\n"
              "};\n\n")
    out.write("static const struct fuzz_elem_shape_info fuzz_elem_shapes[] = "
              "{\n")
    for s in sh["shapes"]:
        out.write("\t/* %s: %s */\n" % (s["name"], s["why"]))
        out.write("\t{ \"%s\", %d, %d, %d, %d, %d, %d, %d, %d },\n"
                  % (s["name"], s["hdr"], s["len_off"], s["len_width"],
                     1 if s["len_le"] else 0, s["extid_off"],
                     s["extid_width"], s["extid_le"], s["covers"]))
    out.write("};\n\n")

    out.write("/* The ids that select a shape, named as the tree names "
              "them. */\n")
    for s in sh["shapes"]:
        if s["sel"]:
            out.write("#define FUZZ_EID_%s %s\n" % (s["name"], s["sel"]))
    out.write("\n")

    out.write("""/*
 * Fragmentation, read out of ieee802_11_defrag(), the parse loop and
 * ieee802_11_defrag_mle_subelem().
 *
 * A Fragment element is a CONTINUATION of the element before it, which makes
 * it the one place where inserting between two elements removes octets from a
 * third. It is also the only route to an element longer than its length field
 * can say, so the logical length domain is 0..len_max + max_body * N and not
 * 0..len_max.
 */
""")
    out.write("#define FUZZ_EID_FRAGMENT %s\n" % sh["frag_id"])
    out.write("#define FUZZ_FRAG_PARENT_LEN %d\n" % sh["frag_parent_len"])
    out.write("#define FUZZ_DEFRAG_MIN_EXT %d\n" % sh["defrag_min"][0])
    out.write("#define FUZZ_DEFRAG_MIN %d\n" % sh["defrag_min"][1])
    out.write("/* The same mechanism one nesting level down: an element whose "
              "body is\n * itself a chain, whose members are themselves "
              "fragmentable. */\n")
    out.write("#define FUZZ_SUB_EID_FRAGMENT %s\n" % sh["sub_frag_id"])
    out.write("#define FUZZ_SUB_DEFRAG_MIN %d\n\n" % sh["sub_defrag_min"])

    out.write("""/*
 * Action frame labels, read out of the frame rather than taken from the call
 * site. Two functions are the convergence point for eight protocols and over
 * a hundred call sites between them; naming the sites would be a hundred
 * hooks to carry across the rebase, and would file every case under whichever
 * caller happened to reach the convergence point rather than under the
 * protocol that will parse it.
 *
 * Most specific first: a row with an oui_type matches only that vendor, a row
 * with a code only that code, and a row with neither is the category's
 * fallback. The lookup takes the first row whose category matches and whose
 * stated fields match, so the order below IS the precedence.
 *
 * 'hdr' is how many octets the label consumed, which is the one offset in an
 * Action frame this engine is entitled to claim: what follows a category is
 * keyed by the category through a union that says nothing about which member
 * applies, so the chain walk gets the prefix the LABEL read and refuses
 * anything it cannot walk from there.
 */
""")
    out.write("struct fuzz_action_label_entry {\n"
              "\tu8 cat;\n"
              "\ts16 code;\n"
              "\ts16 oui_type;\n"
              "\tu8 hdr;\n"
              "\tconst char *label;\n"
              "};\n\n")
    rows = action_labels(root)
    out.write("/* %d label(s) */\n" % (len(rows) + 1))
    out.write("static const struct fuzz_action_label_entry "
              "fuzz_action_labels[] = {\n")
    for cat, code, oui, label in rows:
        hdr = 6 if oui is not None else (2 if code is not None else 1)
        out.write("\t{ %d, %d, %d, %d, \"%s\" },\n"
                  % (cat, -1 if code is None else code,
                     -1 if oui is None else oui, hdr, label))
    out.write("};\n\n")
    out.write("/* The category this engine could not name. It is a label like "
              "any other,\n * so a run that sends one says so rather than "
              "filing it under a\n * neighbour. */\n")
    out.write("#define FUZZ_ACTION_OTHER \"act-other\"\n")
    out.write("#define FUZZ_ACTION_VENDOR_OUI %s\n\n" % VENDOR_OUI)

    out.write("#endif /* FUZZ_REGISTRIES_H */\n")


GEN_TABLE_RE = re.compile(r"static const \w+ (\w+)\[\] = \{(.*?)\n\};", re.S)


def check_c(root):
    """Compare the generated header against a fresh extraction."""
    path = os.path.join(root, GENERATED)
    if not os.path.isfile(path):
        print("FAIL: %s does not exist; generate it with --emit-c" % path)
        return 1
    with open(path, encoding="utf-8") as f:
        text = f.read()
    tables = {m.group(1): sorted(int(v) for v in
                                 re.findall(r"(\d+),", m.group(2)))
              for m in GEN_TABLE_RE.finditer(text)}
    data = extract(root)
    bad = 0
    for name, symbol, _ in C_TABLES:
        want = sorted(data.get(name, {}))
        got = tables.get(symbol)
        if got is None:
            print("FAIL: %s missing from the generated header" % symbol)
            bad += 1
            continue
        if got != want:
            print("FAIL: %s has %d entries, the header defines %d"
                  % (symbol, len(got), len(want)))
            print("      missing: %s" % sorted(set(want) - set(got))[:12])
            print("      extra:   %s" % sorted(set(got) - set(want))[:12])
            bad += 1
        else:
            print("OK: %-22s %d value(s)" % (symbol, len(got)))

    # The shapes, and everything derived alongside them. Byte comparison
    # rather than a second parse of the generated file: the whole point is
    # that nobody edits this file, so "does it match what the sources say
    # today" is the only question worth asking about it.
    import io
    fresh = io.StringIO()
    emit_c(root, fresh)
    if fresh.getvalue() != text:
        print("FAIL: %s is not what the sources generate today" % GENERATED)
        bad += 1
    else:
        print("OK: %-22s matches the sources byte for byte"
              % "element shapes")

    if bad:
        print("\nRegenerate with: "
              "python3 fuzzing/ledger/registries.py . --emit-c > "
              "src/common/fuzz_registries.h")
    return 1 if bad else 0


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    root = os.path.abspath(args[0]) if args else os.getcwd()

    try:
        if "--emit-c" in sys.argv:
            emit_c(root)
            return 0
        if "--check" in sys.argv:
            return check_c(root)

        reg = extract(root)

        if "--name" in sys.argv:
            # The lookup a crash record needs: a number, and which family it
            # was a member of. A value is a member of several registries at
            # once and means something different in each, so all of them are
            # printed rather than the first.
            for a in args[1:] if args and os.path.isdir(args[0]) else args:
                try:
                    want = int(a, 0)
                except ValueError:
                    continue
                hits = [(n, reg[n][want]) for n, _, _ in REGISTRIES
                        if want in reg[n]]
                if not hits:
                    print("%d: not a member of any registry" % want)
                for n, names in hits:
                    print("%d  %-28s %s" % (want, n, " = ".join(names)))
            return 0

        for name, _, _ in REGISTRIES:
            print("%-28s %4d defined" % (name, len(reg[name])))
        print()
        sh = shapes(root)
        for s in sh["shapes"]:
            print("shape %-7s hdr %d  len @%d w%d%s  %s"
                  % (s["name"], s["hdr"], s["len_off"], s["len_width"],
                     " ext @%d w%d%s" % (s["extid_off"], s["extid_width"],
                                         " (inside len)" if s["covers"]
                                         else "") if s["extid_width"] else "",
                     "selected by %s" % s["sel"] if s["sel"] else "default"))
        print("fragment id %s, parent declared length %d, defrag min %s"
              % (sh["frag_id"], sh["frag_parent_len"], sh["defrag_min"]))
        print()
        for name, _, _ in REGISTRIES:
            vals = sorted(reg[name])
            print("%s: %s" % (name, " ".join(str(v) for v in vals)))
    except Drift as e:
        print("DRIFT: %s" % e, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
