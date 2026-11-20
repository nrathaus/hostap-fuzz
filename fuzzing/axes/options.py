#!/usr/bin/env python3
"""Every hostapd configuration option, its fields, and the domain it accepts.

Extracted from the if/else chain in hostapd_config_fill(), which is the only
place that defines what a .conf line may say. Nothing here is a list someone
typed: an option added upstream appears the next time this runs, and an option
removed upstream disappears. That property is the point -- a hand-maintained
axis list is a spotlight with paperwork.

    python3 options.py [CHECKOUT]             one line per option
    python3 options.py [CHECKOUT] --json      the same as JSON
"""

import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cparse

OPT = re.compile(r'os_strcmp\(buf,\s*"((?:[^"\\]|\\.)*)"\)\s*==\s*0')

# An assignment to a struct member: the thing a .conf line actually moves.
ASSIGN = re.compile(
    r"\b([a-z_]\w*(?:->|\.)[\w\[\]().>-]*?\w)\s*(?:=[^=]|\+=|\|=|&=)")

# Helpers that write through a pointer argument rather than returning a value,
# so the destination is an argument and not the left side of an '='.
OUT_ARG = [
    ("os_strlcpy", 0), ("os_memcpy", 0), ("hwaddr_aton", 1),
    ("hwaddr_aton2", 1), ("hexstr2bin", 1), ("hostapd_parse_intlist", 0),
    ("hostapd_parse_chanlist", 1),
]

CONTAINERS = ("conf->", "bss->", "ssid->", "wpa_", "hapd->")


def option_bodies(fill_body):
    """[(option, body)] in source order."""
    marks = [(m.start(), m.group(1)) for m in OPT.finditer(fill_body)]
    out = []
    for i, (pos, name) in enumerate(marks):
        end = marks[i + 1][0] if i + 1 < len(marks) else len(fill_body)
        brace = fill_body.find("{", pos)
        out.append((name, fill_body[brace + 1:end] if brace >= 0 else ""))
    return out


def fields_of(body):
    """The struct members this branch writes, innermost name last."""
    clean = cparse.strip_comments(body)
    found = []
    for m in ASSIGN.finditer(clean):
        found.append(m.group(1))
    for fn, argno in OUT_ARG:
        for m in re.finditer(r"\b%s\s*\(" % fn, clean):
            tail = clean[m.end():]
            depth, i, args, cur = 0, 0, [], []
            while i < len(tail):
                c = tail[i]
                if c == "(":
                    depth += 1
                elif c == ")":
                    if depth == 0:
                        break
                    depth -= 1
                if c == "," and depth == 0:
                    args.append("".join(cur))
                    cur = []
                else:
                    cur.append(c)
                i += 1
            args.append("".join(cur))
            if len(args) > argno:
                a = args[argno].strip().lstrip("&")
                if re.fullmatch(r"[a-z_]\w*(?:->|\.)[\w.>-]*\w", a):
                    found.append(a)
    # Keep only writes into configuration structures; a branch's own locals are
    # scaffolding, not an axis.
    keep = []
    for f in found:
        if not f.startswith(CONTAINERS) and "->" not in f:
            continue
        if f not in keep:
            keep.append(f)
    return keep


BOOL_RE = re.compile(r"atoi\(pos\)\s*(?:>\s*0|!=\s*0|\?)|\b!!\s*atoi\(pos\)")
NUM_RE = re.compile(r"\batoi\(pos\)|\bstrtol\(pos|\batoll\(pos")
STR_RE = re.compile(r"os_strlcpy\s*\(|os_strdup\s*\(|wpa_config_parse_string")
MAC_RE = re.compile(r"hwaddr_aton2?\s*\(")
HEX_RE = re.compile(r"hexstr2bin\s*\(")
LIST_RE = re.compile(r"\bstr_token\b|\bos_strtok\b|while\s*\(\s*\w+\s*\)\s*\{"
                     r"[^}]*atoi")

# A range the branch itself enforces: "if (x < A || x > B) return 1;" and the
# forms around it. The bound is whatever the source says, never a number chosen
# here, so a bound that moves upstream moves here too.
# The lookbehind matters more than it looks: without it the '>' of a '->' in
# the second half of the condition is read as the comparison, and the bound
# comes back as the name of the field being compared.
RANGE_RES = [
    re.compile(r"(?<![-<>=!])<\s*(-?\d+|[A-Z]\w*)\s*\|\|[^;]*?"
               r"(?<![-<>=!])>\s*(-?\d+|[A-Z]\w*)"),
    re.compile(r"(?<![-<>=!])>\s*(-?\d+|[A-Z]\w*)\s*\|\|[^;]*?"
               r"(?<![-<>=!])<\s*(-?\d+|[A-Z]\w*)"),
]
EQ_SET_RE = re.compile(r"!=\s*([A-Z][A-Z0-9_]{2,})")


def classify(body):
    clean = cparse.strip_comments(body)
    kind = "other"
    if MAC_RE.search(clean):
        kind = "mac"
    elif HEX_RE.search(clean):
        kind = "hex"
    elif BOOL_RE.search(clean) and not NUM_RE.search(
            BOOL_RE.sub("", clean)):
        kind = "bool"
    elif NUM_RE.search(clean):
        kind = "int"
    elif STR_RE.search(clean):
        kind = "str"
    if LIST_RE.search(clean) and kind in ("int", "other", "str"):
        kind = "list"

    lo = hi = None
    for r in RANGE_RES:
        m = r.search(clean)
        if m:
            a, b = m.group(1), m.group(2)
            lo, hi = (a, b) if r is RANGE_RES[0] else (b, a)
            break
    members = sorted(set(EQ_SET_RE.findall(clean)))
    if kind == "int" and not lo and len(members) >= 2:
        kind = "enum"
    return kind, lo, hi, members


def extract(root):
    path = os.path.join(root, "hostapd", "config_file.c")
    with open(path, encoding="utf-8", errors="replace") as f:
        src = f.read()
    body = cparse.function_body(src, "hostapd_config_fill")
    if body is None:
        raise SystemExit("hostapd_config_fill() not found in %s" % path)
    out = []
    for name, obody in option_bodies(body):
        kind, lo, hi, members = classify(obody)
        out.append({
            "option": name,
            "calls": sorted(cparse.calls_in(obody)),
            "fields": fields_of(obody),
            "kind": kind,
            "min": lo,
            "max": hi,
            "members": members,
        })
    return out


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    root = os.path.abspath(args[0]) if args else os.getcwd()
    opts = extract(root)
    if "--json" in sys.argv:
        json.dump(opts, sys.stdout, indent=1)
        print()
        return 0
    for o in opts:
        rng = ""
        if o["min"] or o["max"]:
            rng = " [%s..%s]" % (o["min"] or "", o["max"] or "")
        elif o["members"]:
            rng = " {%s}" % ",".join(o["members"][:4])
        print("%-34s %-6s%-24s %s" % (o["option"], o["kind"], rng,
                                      " ".join(o["fields"][:3])))
    kinds = {}
    for o in opts:
        kinds[o["kind"]] = kinds.get(o["kind"], 0) + 1
    print("\n%d options: %s" % (
        len(opts), ", ".join("%s %d" % kv for kv in sorted(kinds.items()))))
    print("%d with no field extracted" % sum(1 for o in opts if not o["fields"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
