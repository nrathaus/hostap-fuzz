#!/usr/bin/env python3
"""Derive the named fields of the frames this harness transmits.

A byte-offset sweep knows a frame as a run of octets. It will put all 255 other
values through the low octet of a status code and all 255 through the high one,
and never once send the pair that makes the field 300. The field is two octets
and its domain is 0..65535; an octet-wise engine reaches 511 of them. That gap
is not a tuning parameter, it is the difference between sweeping a field and
sweeping the bytes it happens to occupy.

So the fields are read out of the tree's own declarations -- `struct
ieee80211_mgmt` for management frames, `struct ieee802_1x_hdr` and `struct
wpa_eapol_key` for EAPOL-Key -- and emitted as a table the engine compiles in.
Nothing here is typed by hand. A field upstream adds, moves or widens arrives
with the next rebase, and `--check` fails until the header is regenerated.

    python3 fields.py [CHECKOUT]            list the fields
    python3 fields.py [CHECKOUT] --emit-c   the generated header
    python3 fields.py [CHECKOUT] --check    compare against the header, exit 1
"""

import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

# Widths of the typedefs these structs use. Not guessed: every one of them is
# checked against its typedef in the tree by verify_fields.py, because a wrong
# width here shifts every offset after it and the sweep would quietly be
# mutating the neighbouring field.
SCALARS = {
    "u8": 1, "s8": 1,
    "u16": 2, "le16": 2, "be16": 2, "s16": 2,
    "u32": 4, "le32": 4, "be32": 4, "s32": 4,
    "u64": 8, "le64": 8, "be64": 8,
}

# Constants that appear as array bounds in those structs, with the header that
# defines each. Resolved from the tree rather than substituted here.
CONST_HEADERS = [
    ("src/common/wpa_common.h", None),
    ("src/common/ieee802_11_defs.h", None),
    ("src/utils/common.h", None),
]

# The 802.11 header every management frame starts with, which is also where
# the engine reads the subtype from. Taken from the struct, not assumed.
MGMT_HDR_FIELDS = ("frame_control", "duration", "da", "sa", "bssid",
                   "seq_ctrl")


def strip_comments(src):
    """Blank out comments, keeping offsets and string literals."""
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
        i += 1
    return "".join(out)


def read(root, rel):
    with open(os.path.join(root, rel), encoding="utf-8",
              errors="replace") as f:
        return strip_comments(f.read())


def constants(root):
    """Integer #defines usable as an array bound."""
    out = {}
    for rel, _ in CONST_HEADERS:
        for m in re.finditer(r"(?m)^#define\s+([A-Z][A-Z0-9_]*)\s+(\d+)\s*$",
                             read(root, rel)):
            out.setdefault(m.group(1), int(m.group(2)))
    return out


def struct_body(src, name):
    """The text between the braces of 'struct <name> {' ... '}'."""
    m = re.search(r"\bstruct\s+%s\s*\{" % re.escape(name), src)
    if not m:
        return None
    i, depth = m.end(), 1
    while i < len(src) and depth:
        if src[i] == "{":
            depth += 1
        elif src[i] == "}":
            depth -= 1
        i += 1
    return src[m.end():i - 1]


def split_members(body):
    """Top-level members of a struct body: (text, inner) pairs.

    'inner' is the brace-enclosed text of a nested struct or union, so a
    caller can descend without re-finding it.
    """
    out, depth, start, i = [], 0, 0, 0
    inner_start = None
    while i < len(body):
        c = body[i]
        if c == "{":
            if depth == 0:
                inner_start = i
            depth += 1
        elif c == "}":
            depth -= 1
        elif c == ";" and depth == 0:
            text = body[start:i]
            inner = body[inner_start + 1:text.rfind("}") + start] \
                if inner_start is not None else None
            # The slice above is fragile; recompute from absolute offsets.
            if inner_start is not None:
                close = inner_start
                d = 0
                while close < i:
                    if body[close] == "{":
                        d += 1
                    elif body[close] == "}":
                        d -= 1
                        if d == 0:
                            break
                    close += 1
                inner = body[inner_start + 1:close]
            out.append((text.strip(), inner))
            start = i + 1
            inner_start = None
        i += 1
    return out


# A field whose whole content space is 65536 values or fewer is enumerated as
# a number: every bit pattern it can hold, which for one or two octets IS the
# integer domain. Anything wider is not a domain anyone finishes -- 2^256 for a
# nonce -- so it gets the pattern set instead. The threshold is the rule, not a
# judgement made field by field.
INT_MAX_WIDTH = 2


def kind_of(width):
    return "int" if width <= INT_MAX_WIDTH else "opaque"


def order_of(base, width):
    """Which way round a multi-octet field is written.

    It matters for the ladder, not for completeness: writing all 65536 bit
    patterns into two octets covers the same set either way, but "value 1"
    has to mean 1 to the code that reads the field, or the ladder's 0, 1, 2,
    max-1, max are five arbitrary values instead of the five edges.

    Taken from the declared type. An octet array has no declared order; it is
    written in reading order, which is what the tree's own comment says for
    the two that occur (key_info and key_length are "big endian"). An opaque
    field has no order at all -- it is filled, not counted.
    """
    if width < 2:
        return ""
    if base.startswith("le"):
        return "le"
    return "be"


def member_fields(body, consts):
    """Scalar and fixed-array members of a flat struct body, in order.

    Returns [(name, width, kind, order)], and a flag for whether a flexible
    array member ended the struct.
    """
    fields, flexible = [], False
    for text, inner in split_members(body):
        if inner is not None:
            # A nested struct or union. Everything before it is still at a
            # known offset; everything after it is not, so this stops rather
            # than skipping -- skipping would shift every later field and the
            # sweep would mutate the neighbour of what it named.
            break
        t = " ".join(text.split())
        m = re.match(r"^(\w+)\s+(\w+)\s*\[\s*([A-Za-z0-9_]*)\s*\]$", t)
        if m:
            base, name, bound = m.groups()
            if base not in SCALARS:
                return None, False
            if bound == "":
                flexible = True
                continue                  # the element chain; W5b's domain
            n = consts.get(bound)
            if n is None:
                try:
                    n = int(bound)
                except ValueError:
                    return None, False
            if SCALARS[base] != 1:
                return None, False        # not in these structs; not guessed
            width = n
            kind = kind_of(width)
            fields.append((name, width, kind,
                           order_of(base, width) if kind == "int" else ""))
            continue
        m = re.match(r"^(\w+)\s+(\w+)$", t)
        if m:
            base, name = m.groups()
            if base not in SCALARS:
                return None, False
            width = SCALARS[base]
            kind = kind_of(width)
            fields.append((name, width, kind,
                           order_of(base, width) if kind == "int" else ""))
            continue
        if t:
            return None, False
    return fields, flexible


def layout(fields, start=0):
    """Assign offsets. These structs are STRUCT_PACKED, so no padding."""
    out, off = [], start
    for name, width, kind, order in fields:
        out.append((name, off, width, kind, order))
        off += width
    return out, off


def mgmt_frames(root):
    """Per-subtype fixed fields of a management frame.

    The union member's own name is what names the subtype: 'auth' is
    WLAN_FC_STYPE_AUTH. A member with no matching define is dropped rather
    than mapped by hand -- if upstream adds one, the define arrives with it.
    """
    src = read(root, "src/common/ieee802_11_defs.h")
    consts = constants(root)
    body = struct_body(src, "ieee80211_mgmt")
    if body is None:
        return None, None

    members = split_members(body)
    hdr_src = [(t, i) for t, i in members if i is None]
    hdr, hdr_len = layout(member_fields(
        "".join(t + ";" for t, _ in hdr_src), consts)[0])
    hdr = [f for f in hdr if f[0] in MGMT_HDR_FIELDS]
    if [f[0] for f in hdr] != list(MGMT_HDR_FIELDS):
        return None, None

    union = [i for t, i in members if i is not None and "union" in t]
    if len(union) != 1:
        return None, None

    stypes = {}
    for m in re.finditer(
            r"(?m)^#define\s+WLAN_FC_STYPE_([A-Z0-9_]+)\s+(\d+)", src):
        # The STYPE space is reused for control and data frames; the
        # management block comes first and is the one that matters here.
        stypes.setdefault(m.group(1).lower(), int(m.group(2)))

    out = {}
    for text, inner in split_members(union[0]):
        if inner is None:
            continue
        names = text[text.rfind("}") + 1:]
        names = [n.strip() for n in names.replace("STRUCT_PACKED", "")
                 .split(",") if n.strip()]
        fields, _ = member_fields(inner, consts)
        if fields is None:
            continue                      # a nested union: Action frames
        laid, _ = layout(fields, hdr_len)
        for name in names:
            if name in stypes:
                out[name] = (stypes[name], laid)
    return hdr, out


def eapol_fields(root):
    """The EAPOL-Key frame: the 802.1X header, then the key descriptor."""
    consts = constants(root)
    hdr = member_fields(
        struct_body(read(root, "src/common/eapol_common.h"),
                    "ieee802_1x_hdr"), consts)[0]
    key = member_fields(
        struct_body(read(root, "src/common/wpa_common.h"),
                    "wpa_eapol_key"), consts)[0]
    if hdr is None or key is None:
        return None
    laid, off = layout(hdr)
    # wpa_eapol_key's own 'type' collides with the 802.1X header's; the
    # descriptor's is renamed here so the table has distinct names. The offset
    # is what the engine uses, so this is a labelling choice and nothing else.
    key = [("desc_" + n if n == "type" else n, w, k, o)
           for n, w, k, o in key]
    laid2, _ = layout(key, off)
    return laid + laid2


def build(root):
    """The whole table: (frame, selector, name, offset, width, kind, order),
    where 'selector' is the management subtype or -1.

    An Action frame contributes only its category octet. What follows it is
    keyed by category through a second union, and nothing in the struct says
    which category selects which member -- so that mapping is not invented and
    everything past the category falls back to the byte sweep.
    """
    rows = []
    hdr, frames = mgmt_frames(root)
    if hdr is None:
        return None
    for name in sorted(frames, key=lambda n: (frames[n][0], n)):
        stype, fields = frames[name]
        for fname, off, width, kind, order in fields:
            rows.append(("mgmt", stype, "%s.%s" % (name, fname),
                         off, width, kind, order))
    for fname, off, width, kind, order in eapol_fields(root) or []:
        rows.append(("eapol", -1, fname, off, width, kind, order))
    return rows


KIND_C = {"int": "FUZZ_FIELD_INT", "opaque": "FUZZ_FIELD_OPAQUE"}
FRAME_C = {"mgmt": "FUZZ_TYPE_IEEE80211_MGMT",
           "eapol": "FUZZ_TYPE_IEEE802_1X_HDR"}


def emit_c(rows):
    out = []
    out.append("/*")
    out.append(" * Named fields of the frames this harness transmits.")
    out.append(" *")
    out.append(" * GENERATED by fuzzing/ledger/fields.py from struct")
    out.append(" * ieee80211_mgmt, struct ieee802_1x_hdr and struct")
    out.append(" * wpa_eapol_key. Do not edit: regenerate with")
    out.append(" *")
    out.append(" *     python3 fuzzing/ledger/fields.py . --emit-c \\")
    out.append(" *             > src/common/fuzz_fields.h")
    out.append(" *")
    out.append(" * and check it has not gone stale with --check.")
    out.append(" *")
    out.append(" * A field is here so that its whole domain can be swept as a")
    out.append(" * unit. Sweeping the octets a two-octet field occupies")
    out.append(" * reaches 511 of its 65536 values and never the pair that")
    out.append(" * makes it 300.")
    out.append(" */")
    out.append("")
    out.append("#ifndef FUZZ_FIELDS_H")
    out.append("#define FUZZ_FIELDS_H")
    out.append("")
    out.append("enum fuzz_field_kind {")
    out.append("\tFUZZ_FIELD_INT = 0,")
    out.append("\tFUZZ_FIELD_OPAQUE = 1,")
    out.append("};")
    out.append("")
    out.append("struct fuzz_field {")
    out.append("\tconst char *name;")
    out.append("\tenum fuzz_frame_type frame;")
    out.append("\t/* Management subtype this field belongs to, or -1 for a")
    out.append("\t * frame kind that has only one layout. */")
    out.append("\tint stype;")
    out.append("\tunsigned int offset;")
    out.append("\tunsigned int width;")
    out.append("\tenum fuzz_field_kind kind;")
    out.append("\t/* 1 when the field reads most significant octet first.")
    out.append("\t * Does not change what the sweep covers; it changes what")
    out.append("\t * a given case VALUE means, and so whether the ladder's")
    out.append("\t * edges are the field's edges. */")
    out.append("\tint big_endian;")
    out.append("};")
    out.append("")
    out.append("static const struct fuzz_field fuzz_fields[] = {")
    for frame, stype, name, off, width, kind, order in rows:
        out.append('\t{ "%s", %s, %d, %d, %d, %s, %d },'
                   % (name, FRAME_C[frame], stype, off, width, KIND_C[kind],
                      1 if order == "be" else 0))
    out.append("};")
    out.append("")
    out.append("#endif /* FUZZ_FIELDS_H */")
    return "\n".join(out) + "\n"


def table_in_header(root):
    path = os.path.join(root, "src", "common", "fuzz_fields.h")
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as f:
        return f.read()


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    root = os.path.abspath(args[0]) if args else os.getcwd()
    rows = build(root)
    if rows is None:
        print("FAIL: could not read the structs; the layout has changed")
        return 1

    if "--emit-c" in sys.argv:
        sys.stdout.write(emit_c(rows))
        return 0

    if "--check" in sys.argv:
        have = table_in_header(root)
        if have is None:
            print("FAIL: src/common/fuzz_fields.h does not exist")
            return 1
        want = emit_c(rows)
        if have != want:
            print("FAIL: src/common/fuzz_fields.h does not match the tree")
            print("Regenerate with: python3 %s %s --emit-c > "
                  "src/common/fuzz_fields.h"
                  % (os.path.relpath(__file__, root), root))
            return 1
        ints = [r for r in rows if r[5] == "int"]
        print("OK: %d fields (%d integer, %d opaque), header matches the tree"
              % (len(rows), len(ints), len(rows) - len(ints)))
        return 0

    for frame, stype, name, off, width, kind, order in rows:
        print("%-6s stype=%-3s %-28s off=%-3d width=%-3d %-6s %s"
              % (frame, stype if stype >= 0 else "-", name, off, width,
                 kind, order))
    print("\n%d fields" % len(rows))
    return 0


if __name__ == "__main__":
    sys.exit(main())
