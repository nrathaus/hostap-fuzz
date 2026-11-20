#!/usr/bin/env python3
"""Registries that a configuration option draws its values from.

Two kinds, both read out of the tree rather than listed here:

  token families -- an option whose value is a space-separated list of names
      (key managements, ciphers, ...) is parsed by a helper built from an
      os_strcmp() chain. That chain IS the set of accepted names, so extracting
      it gives the whole family and cannot drift from it.

  the group registry -- the SAE/DPP finite-field and elliptic-curve groups. The
      field on the air is a u16; the set the code will instantiate is a few
      dozen; the set it accepts by default is smaller still, and smaller for a
      reason that is a compile-time constant rather than a configuration value.
      All three are reported, because the difference between them is the part
      that has never been on the air.

    python3 families.py [CHECKOUT]
"""

import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cparse

STRCMP = re.compile(r'os_strcmp\s*\(\s*\w+\s*,\s*"((?:[^"\\]|\\.)*)"\s*\)\s*==\s*0')


def _source_of(root, func, dirs=("hostapd", "src", "wpa_supplicant")):
    for d in dirs:
        for dirpath, _, names in os.walk(os.path.join(root, d)):
            for name in names:
                if not name.endswith(".c"):
                    continue
                path = os.path.join(dirpath, name)
                with open(path, encoding="utf-8", errors="replace") as f:
                    src = f.read()
                if func not in src:
                    continue
                body = cparse.function_body(src, func)
                if body is not None:
                    return body
    return None


def token_family(root, func, depth=2):
    """Every literal a parser helper compares its token against.

    Follows delegation one or two hops -- hostapd_config_parse_cipher() is a
    three-line wrapper around wpa_parse_cipher() and the names live in the
    callee -- and stops there, because beyond that the strings being compared
    stop being this option's vocabulary.
    """
    body = _source_of(root, func)
    if body is None:
        return set(), []
    toks = set(STRCMP.findall(body))
    via = []
    if not toks and depth > 0:
        for callee in sorted(cparse.calls_in(body)):
            if not callee.startswith(("os_", "wpa_printf", "is_", "le_", "be_")):
                sub, subvia = token_family(root, callee, depth - 1)
                if sub:
                    toks |= sub
                    via.append(callee)
                    via.extend(subvia)
    return toks, via


DH_GROUP = re.compile(r"DH_GROUP\(\s*(\d+)\s*,")
CASE_GROUP = re.compile(r"case\s+(\d+)\s*:")
IFDEF = re.compile(r"^\s*#\s*(ifdef|ifndef|if|else|elif|endif)\b(.*)$", re.M)


def _gated_ints(text, pattern):
    """[(value, [gate, ...])] -- each match with the #ifdefs enclosing it."""
    out, stack = [], []
    pos = 0
    for d in IFDEF.finditer(text):
        for m in pattern.finditer(text, pos, d.start()):
            out.append((int(m.group(1)), list(stack)))
        kind, rest = d.group(1), d.group(2).strip()
        if kind in ("ifdef", "ifndef", "if"):
            stack.append(("!" if kind == "ifndef" else "") + rest.split()[0]
                         if rest else kind)
        elif kind == "else":
            if stack:
                stack[-1] = "!" + stack[-1]
        elif kind == "endif":
            if stack:
                stack.pop()
        pos = d.end()
    for m in pattern.finditer(text, pos):
        out.append((int(m.group(1)), list(stack)))
    return out


def group_registry(root):
    """What the build will accept as a group id, and what gates each tier."""
    out = {"ffc": [], "ecc": [], "production": [], "gates": {}}

    path = os.path.join(root, "src", "crypto", "dh_groups.c")
    if os.path.isfile(path):
        with open(path, encoding="utf-8", errors="replace") as f:
            src = cparse.strip_comments(f.read())
        start = src.find("dh_groups[] = {")
        if start >= 0:
            end = src.find("\n};", start)
            out["ffc"] = _gated_ints(src[start:end], DH_GROUP)

    path = os.path.join(root, "src", "crypto", "crypto_openssl.c")
    if os.path.isfile(path):
        with open(path, encoding="utf-8", errors="replace") as f:
            body = cparse.function_body(f.read(), "crypto_ec_group_2_nid")
        if body:
            out["ecc"] = _gated_ints(cparse.strip_comments(body), CASE_GROUP)

    body = _source_of(root, "dragonfly_suitable_group")
    if body:
        out["production"] = sorted(
            {int(m) for m in re.findall(r"group\s*==\s*(\d+)",
                                        cparse.strip_comments(body))})

    # The gate that decides whether the production filter runs at all.
    body = _source_of(root, "sae_set_group")
    if body:
        m = re.search(r"#ifdef\s+(\w+)[^#]*?#else", body, re.S)
        if m and "dragonfly_suitable_group" in body:
            out["gates"]["sae_set_group"] = m.group(1)
    return out


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    root = os.path.abspath(args[0]) if args else os.getcwd()

    for fn in ("hostapd_config_parse_key_mgmt", "hostapd_config_parse_cipher"):
        toks, via = token_family(root, fn)
        print("%s: %d token(s)%s" % (
            fn, len(toks), " via %s" % " -> ".join(via) if via else ""))
        print("    %s" % " ".join(sorted(toks)))

    g = group_registry(root)
    print("\ngroup registry")
    for tier in ("ffc", "ecc"):
        plain = sorted({v for v, gates in g[tier] if not gates})
        gated = sorted({v for v, gates in g[tier] if gates})
        print("    %-4s unconditional %-26s gated %s" % (
            tier, " ".join(map(str, plain)) or "-",
            " ".join(map(str, gated)) or "-"))
        for v, gates in g[tier]:
            if gates:
                print("         %3d  needs %s" % (v, " && ".join(gates)))
    print("    production filter accepts: %s" %
          " ".join(map(str, g["production"])))
    for k, v in g["gates"].items():
        print("    %s() skips that filter under %s" % (k, v))
    return 0


if __name__ == "__main__":
    sys.exit(main())
