#!/usr/bin/env python3
"""Index every struct member declared in the tree's headers.

An option's domain is a property of the field it writes, not of the line that
parses it: 'unsigned int x:1' accepts two values whatever atoi() does with the
text, and a u8 accepts 256. Reading the declaration is how the domain gets
derived rather than assumed -- the alternative is a table of widths someone
typed, which is wrong the moment a field is widened upstream.

    python3 decls.py [CHECKOUT] [NAME ...]
"""

import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cparse

STRUCT = re.compile(r"\bstruct\s+(\w+)\s*\{", re.S)
ENUM = re.compile(r"\benum\s+(\w+)\s*\{(.*?)\}", re.S)

# "type name;", "type name:1;", "type name[LEN];" -- one member per statement.
MEMBER = re.compile(
    r"^[ \t]*(?P<type>(?:const\s+|unsigned\s+|signed\s+|struct\s+|enum\s+|"
    r"union\s+)*[A-Za-z_]\w*)\s+(?P<stars>\**)\s*(?P<name>[A-Za-z_]\w*)"
    r"\s*(?:\[(?P<arr>[^\]]*)\])?\s*(?::\s*(?P<bits>\d+))?\s*;",
    re.M)

# Width of the integer types hostap actually declares configuration in. A type
# absent here is simply reported as unknown rather than guessed at.
WIDTHS = {
    "u8": (0, 255), "s8": (-128, 127),
    "u16": (0, 65535), "s16": (-32768, 32767),
    "u32": (0, 4294967295), "s32": (-2147483648, 2147483647),
    "int": (-2147483648, 2147483647),
    "unsigned int": (0, 4294967295),
    "long": None, "size_t": None,
}


def struct_bodies(src):
    """[(struct name, body)] for every struct definition in the source."""
    blank = cparse.strip_comments(src)
    out = []
    for m in STRUCT.finditer(blank):
        i, depth = m.end() - 1, 0
        while i < len(blank):
            if blank[i] == "{":
                depth += 1
            elif blank[i] == "}":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        out.append((m.group(1), src[m.end():i]))
    return out


def enum_index(root, dirs=("src", "hostapd", "wpa_supplicant")):
    """{enum name: [(member, value), ...]} with C's implicit numbering applied.

    An enum is a domain that is already written down and already complete. Its
    members are what the field accepts; enumerating them is not sampling.
    """
    out = {}
    for d in dirs:
        for dirpath, _, names in os.walk(os.path.join(root, d)):
            for name in names:
                if not name.endswith((".h", ".c")):
                    continue
                path = os.path.join(dirpath, name)
                with open(path, encoding="utf-8", errors="replace") as f:
                    src = cparse.strip_comments(f.read())
                if "enum" not in src:
                    continue
                for m in ENUM.finditer(src):
                    members, nxt = [], 0
                    for item in m.group(2).split(","):
                        item = item.strip()
                        if not item:
                            continue
                        if "=" in item:
                            nm, val = item.split("=", 1)
                            nm, val = nm.strip(), val.strip()
                            try:
                                nxt = int(val, 0)
                            except ValueError:
                                members.append((nm, None))
                                nxt = None
                                continue
                        else:
                            nm = item.split()[0] if item.split() else ""
                        if not re.fullmatch(r"[A-Za-z_]\w*", nm):
                            continue
                        members.append((nm, nxt))
                        if nxt is not None:
                            nxt += 1
                    if members:
                        out.setdefault(m.group(1), members)
    return out


def index(root, dirs=("src", "hostapd", "wpa_supplicant")):
    """{member name: [{struct, type, bits, array}, ...]}"""
    out = {}
    for d in dirs:
        for dirpath, _, names in os.walk(os.path.join(root, d)):
            for name in names:
                if not name.endswith(".h"):
                    continue
                path = os.path.join(dirpath, name)
                with open(path, encoding="utf-8", errors="replace") as f:
                    src = f.read()
                if "struct" not in src:
                    continue
                for sname, body in struct_bodies(src):
                    body = cparse.strip_comments(body)
                    for mm in MEMBER.finditer(body):
                        rec = {
                            "struct": sname,
                            "type": " ".join(mm.group("type").split()),
                            "ptr": bool(mm.group("stars")),
                            "array": mm.group("arr"),
                            "bits": int(mm.group("bits")) if mm.group("bits")
                            else None,
                            "file": os.path.relpath(path, root),
                        }
                        out.setdefault(mm.group("name"), []).append(rec)
    return out


def domain_of(rec):
    """(kind, lo, hi) for a declaration, or ('opaque', None, None)."""
    if rec["ptr"]:
        return ("ptr", None, None)
    if rec["bits"] == 1:
        return ("bool", 0, 1)
    if rec["bits"]:
        return ("int", 0, (1 << rec["bits"]) - 1)
    if rec["array"] is not None:
        return ("array", None, None)
    t = rec["type"]
    if t.startswith(("struct", "union")):
        return ("opaque", None, None)
    if t.startswith("enum"):
        return ("enum", None, None)
    w = WIDTHS.get(t)
    if w:
        return ("int", w[0], w[1])
    if t in WIDTHS:
        return ("int", None, None)
    return ("opaque", None, None)


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    root = os.path.abspath(args[0]) if args else os.getcwd()
    want = args[1:]
    idx = index(root)
    enums = enum_index(root)
    if not want:
        print("%d distinct member names indexed" % len(idx))
        print("%d enums indexed" % len(enums))
        return 0
    for name in want:
        for rec in idx.get(name, []):
            kind, lo, hi = domain_of(rec)
            extra = ""
            if kind == "enum":
                mem = enums.get(rec["type"].split()[-1], [])
                extra = " {%s}" % ",".join(
                    "%s=%s" % (n, v) for n, v in mem)
            elif lo is not None:
                extra = " %d..%d" % (lo, hi)
            print("%-28s struct %-28s %-16s %s%s" % (
                name, rec["struct"], rec["type"], kind, extra))
        if name not in idx:
            print("%-28s (not found)" % name)
    return 0


if __name__ == "__main__":
    sys.exit(main())
