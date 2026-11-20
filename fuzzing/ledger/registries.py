#!/usr/bin/env python3
"""Extract the IEEE 802.11 id registries from the checkout's own header.

Every number this fuzzer treats as a member of a family comes from here, never
from a hand-written list: a literal in an operator table is a lit spot, and a
hand-written list goes stale the first time upstream adds a member. The header
is the only copy that cannot drift from the tree being fuzzed.

    python3 registries.py [CHECKOUT]
    python3 registries.py [CHECKOUT] --emit-c > src/common/fuzz_registries.h
    python3 registries.py [CHECKOUT] --check    exit 1 if the header moved
"""

import os
import re
import sys

HEADER = os.path.join("src", "common", "ieee802_11_defs.h")

# prefix -> the name the ledger reports it under. Order is the report order.
REGISTRIES = [
    ("WLAN_EID_EXT_", "element id extension"),
    ("WLAN_EID_", "element id"),
    ("WLAN_STATUS_", "status code"),
    ("WLAN_AUTH_", "authentication algorithm"),
    ("WLAN_REASON_", "reason code"),
]

DEFINE_RE = re.compile(r"^#define\s+(\w+)\s+(.+?)\s*(?:/\*.*)?$")


def _value(text):
    text = text.strip().rstrip("UuLl")
    try:
        return int(text, 0)
    except ValueError:
        return None


def extract(root):
    """{report name: {value: [constant names]}}, from the checkout's header."""
    path = os.path.join(root, HEADER)
    out = {name: {} for _, name in REGISTRIES}
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            m = DEFINE_RE.match(line.rstrip("\n"))
            if not m:
                continue
            const, raw = m.group(1), m.group(2)
            # WLAN_EID_EXT_ is a prefix of nothing else, but WLAN_EID_ is a
            # prefix of WLAN_EID_EXT_, so the longest match has to win.
            for prefix, name in REGISTRIES:
                if not const.startswith(prefix):
                    continue
                val = _value(raw)
                if val is not None and 0 <= val <= 0xFFFF:
                    out[name].setdefault(val, []).append(const)
                break
    return out


# The registries the synthesis engine needs compiled in. Element ids and the
# extension ids are what it inserts; the rest are field values and belong to the
# field model, which reads them from the same extraction.
C_TABLES = [
    ("element id", "fuzz_elem_ids", "u8"),
    ("element id extension", "fuzz_elem_ext_ids", "u8"),
]

C_HEADER = """/*
 * GENERATED -- do not edit.
 *
 * The IEEE 802.11 id registries, extracted from src/common/ieee802_11_defs.h by
 * fuzzing/ledger/registries.py. Regenerate with:
 *
 *\tpython3 fuzzing/ledger/registries.py . --emit-c > src/common/fuzz_registries.h
 *
 * and check it with --check, which fails when the header has gained a member
 * this file lacks. That check is the point of generating it: upstream adds
 * members regularly, and a table that quietly falls behind re-narrows the very
 * spotlight the synthesis exists to widen -- silently, because a registry
 * member that is never emitted looks exactly like one that is.
 */

#ifndef FUZZ_REGISTRIES_H
#define FUZZ_REGISTRIES_H

"""


def emit_c(root, out=sys.stdout):
    data = extract(root)
    out.write(C_HEADER)
    for name, symbol, ctype in C_TABLES:
        values = sorted(data.get(name, {}))
        out.write("/* %s: %d distinct value(s) */\n" % (name, len(values)))
        out.write("static const %s %s[] = {\n" % (ctype, symbol))
        for i in range(0, len(values), 12):
            row = values[i:i + 12]
            out.write("\t" + " ".join("%d," % v for v in row) + "\n")
        out.write("};\n\n")
    out.write("#endif /* FUZZ_REGISTRIES_H */\n")


GEN_TABLE_RE = re.compile(
    r"static const \w+ (\w+)\[\] = \{(.*?)\n\};", re.S)


def check_c(root):
    """Compare the generated header against a fresh extraction."""
    path = os.path.join(root, "src", "common", "fuzz_registries.h")
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
            print("OK: %-20s %d value(s)" % (symbol, len(got)))
    if bad:
        print("\nRegenerate with: "
              "python3 fuzzing/ledger/registries.py . --emit-c > "
              "src/common/fuzz_registries.h")
    return 1 if bad else 0


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    root = os.path.abspath(args[0]) if args else os.getcwd()

    if "--emit-c" in sys.argv:
        emit_c(root)
        return 0
    if "--check" in sys.argv:
        return check_c(root)

    reg = extract(root)
    for _, name in REGISTRIES:
        members = reg[name]
        print("%-24s %4d defined" % (name, len(members)))
    print()
    for _, name in REGISTRIES:
        vals = sorted(reg[name])
        print("%s: %s" % (name, " ".join(str(v) for v in vals)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
