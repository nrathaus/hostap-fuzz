#!/usr/bin/env python3
"""The axis list: every configuration option that changes what goes on the air,
with the domain it accepts and the values a sweep should take it through.

Nothing in this file is a list of interesting options. The options come from
hostapd_config_fill(), the domains come from the struct declarations and the
registries the parsers consult, and the filter that drops the rest is the
mechanical reachability test in reach.py. An option that stops reaching frame
construction leaves on its own; one that starts, arrives on its own.

Why axes at all: the mutation engine can only change octets of a frame that the
running configuration caused hostapd to build. A frame no configuration in the
run ever constructs is not under-fuzzed, it is absent. Moving an axis is how a
frame that was absent becomes present, and a family of frames is covered when
every member of the family has been present in some run.

A domain is enumerated, never sampled. Where it is too large to enumerate over
the air in one run, the reduction is declared as a tier and the tier says what
the run leaves for the next one:

    FULL    every value in the domain
    LADDER  the boundaries and the values adjacent to them, plus the default --
            the shape of a domain, for fields where the interior is linear
    STRIDE  a prime stride with a per-run offset, so the union over runs is the
            whole domain. Deferral, not sampling.

    python3 axes.py [CHECKOUT]              the axis list
    python3 axes.py [CHECKOUT] --all        including the unreachable ones
    python3 axes.py [CHECKOUT] --json       machine readable, for run_profiles
    python3 axes.py [CHECKOUT] --stats      counts only
"""

import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import cparse
import decls
import families
import options as options_mod
import reach

# Above this many values a domain is reduced rather than enumerated, because a
# run has to finish. The number is a throughput budget, not a claim about which
# values matter.
FULL_MAX = 64
STRIDE_PRIME = 251

# Helpers whose presence in a branch tells us what the value really is, beyond
# what the assignment alone shows.
TOKEN_PARSERS = {
    "hostapd_config_parse_key_mgmt": "key-mgmt",
    "hostapd_config_parse_cipher": "cipher",
    "wpa_parse_cipher": "cipher",
}
# An option parsed as a list of integers has no width of its own: the domain is
# whatever the consumer of the list will accept. For the group lists that is the
# group registry, which is a few dozen members of a u16 -- and most of those
# members are behind a compile-time gate rather than a configuration value, so
# the registry reports the gate too.
INTLIST = "hostapd_parse_intlist"
GROUP_OPTION = re.compile(r"(^|_)groups?$")


def containers(root):
    """{local name: struct} for hostapd_config_fill()'s parameters."""
    path = os.path.join(root, "hostapd", "config_file.c")
    with open(path, encoding="utf-8", errors="replace") as f:
        src = cparse.strip_comments(f.read())
    m = re.search(r"hostapd_config_fill\s*\(([^)]*)\)\s*\n?\{", src)
    out = {}
    if m:
        for arg in m.group(1).split(","):
            am = re.search(r"struct\s+(\w+)\s*\*\s*(\w+)", arg)
            if am:
                out[am.group(2)] = am.group(1)
    return out


def by_struct(idx):
    out = {}
    for name, recs in idx.items():
        for rec in recs:
            out[(rec["struct"], name)] = rec
    return out


def resolve(path, conts, bystruct, idx):
    """Follow a field path such as bss->radius->auth_server to its declaration."""
    parts = re.split(r"->|\.", path)
    parts = [re.sub(r"\[.*", "", p) for p in parts if p]
    if not parts:
        return None
    struct = conts.get(parts[0])
    if struct is None:
        recs = idx.get(parts[-1], [])
        return recs[0] if len(recs) == 1 else None
    for p in parts[1:]:
        rec = bystruct.get((struct, p))
        if rec is None:
            return None
        if p == parts[-1]:
            return rec
        t = rec["type"].split()
        struct = t[-1] if t[0] == "struct" else None
        if struct is None:
            return None
    return None


DEFAULT_ASSIGN = re.compile(
    r"\b(?:bss|conf)->([a-z_]\w*)\s*=\s*(-?\w+)\s*;")


def defaults(root):
    """{field: literal} from the two functions that set configuration defaults.

    The default anchors a LADDER: a sweep that never includes it cannot tell a
    value that broke something from a build that was broken already.
    """
    path = os.path.join(root, "src", "ap", "ap_config.c")
    out = {}
    if not os.path.isfile(path):
        return out
    with open(path, encoding="utf-8", errors="replace") as f:
        src = f.read()
    for fn in ("hostapd_config_defaults_bss", "hostapd_config_defaults"):
        body = cparse.function_body(src, fn)
        if not body:
            continue
        for m in DEFAULT_ASSIGN.finditer(cparse.strip_comments(body)):
            out.setdefault(m.group(1), m.group(2))
    return out


def as_int(tok):
    try:
        return int(tok, 0)
    except (TypeError, ValueError):
        return None


# A configuration integer is almost always wider than the field it ends up in:
# hostapd parses into an int and the element carries a u8 or a u16. So the
# values worth taking an over-wide domain through are the boundaries of the
# widths it could be narrowed to on the way out, which is a property of binary
# representation and not of any protocol. Derived, so that widening a field
# upstream changes this on its own.
WIDTH_EDGES = sorted({v
                      for bits in (8, 16, 32)
                      for v in (2 ** bits - 1, 2 ** bits, 2 ** (bits - 1) - 1,
                                2 ** (bits - 1))})


def ladder(lo, hi, default):
    """The edges of the domain, the edges inside it, and the default.

    One step past the top is deliberate: a field is a contract between the
    parser and everything that later reads it, and the only way to find out
    whether the readers believe the parser is to hand them a value the parser
    was supposed to reject.
    """
    vals = {lo, lo + 1, hi - 1, hi, hi + 1, 0, 1}
    if lo < 0:
        vals.add(-1)
    for edge in WIDTH_EDGES:
        vals |= {edge - 1, edge, edge + 1}
    if default is not None:
        vals |= {default - 1, default, default + 1}
    return sorted(v for v in vals if lo - 1 <= v <= hi + 1)


def stride(lo, hi, offset=0):
    return list(range(lo + (offset % STRIDE_PRIME), hi + 1, STRIDE_PRIME))


def plan_domain(opt, rec, enums, defs, fam):
    """(tier, values, note, shape).

    'shape' says how a value is written into a configuration file: "value" for
    a number or a name that goes in literally, "length" for a field whose
    domain is how long the text is rather than what it says. The distinction
    matters because a length domain written literally would set the option to
    the number 3 instead of to three characters -- a sweep that looks like it
    covered the field and did not.
    """
    body_kind = opt["kind"]

    if fam is not None:
        kind, toks = fam
        return ("FULL", sorted(toks), "%s registry, one per run" % kind,
                "value")

    if rec is None:
        return "NONE", [], "no declaration resolved", "value"

    kind, lo, hi = decls.domain_of(rec)

    if kind == "enum":
        ename = rec["type"].split()[-1]
        mem = enums.get(ename, [])
        vals = [v for _, v in mem if v is not None]
        return ("FULL", sorted(set(vals)),
                "enum %s, %d member(s)" % (ename, len(mem)), "value")

    if kind == "bool":
        return "FULL", [0, 1], "single bit", "value"

    if kind in ("array", "ptr", "opaque"):
        n = as_int(rec["array"]) if rec["array"] else None
        if n is not None:
            # The domain is the length, not the content: content is the
            # mutation engine's job, length is this one's.
            vals = list(range(0, n + 2)) if n + 2 <= FULL_MAX else \
                ladder(0, n + 1, None)
            tier = "FULL" if n + 2 <= FULL_MAX else "LADDER"
            return (tier, vals,
                    "length 0..%s, one past the declared bound" % n,
                    "hex-length" if "hexstr2bin" in opt.get("calls", ())
                    else "length")
        return "NONE", [], "%s, no numeric domain" % kind, "value"

    # An integer. The declaration gives the width; a range the branch enforces
    # itself narrows it, because a value the parser rejects never reaches a
    # frame and sweeping it only costs a run.
    slo, shi = as_int(opt["min"]), as_int(opt["max"])
    if slo is not None and (lo is None or slo > lo):
        lo = slo
    if shi is not None and (hi is None or shi < hi):
        hi = shi
    if lo is None or hi is None:
        return "NONE", [], "unbounded", "value"

    default = None
    for f in opt["fields"]:
        default = as_int(defs.get(re.split(r"->|\.", f)[-1]))
        if default is not None:
            break
    size = hi - lo + 1
    if size <= FULL_MAX:
        return ("FULL", list(range(lo, hi + 1)), "%d value(s)" % size, "value")
    if body_kind == "int" and opt["members"]:
        return ("FULL", sorted(opt["members"]),
                "compared against named values", "value")
    note = "%d values; STRIDE %d covers the rest across runs" % (
        size, STRIDE_PRIME)
    if default is not None and not lo <= default <= hi:
        # The configuration's resting value is one no .conf line can express:
        # a sentinel meaning "leave it to the driver". Worth saying, because a
        # sweep of this axis never visits the state the AP is normally in.
        note += "; default %d is outside what the parser accepts" % default
    return "LADDER", ladder(lo, hi, default), note, "value"


def build(root):
    opts = options_mod.extract(root)
    idx = decls.index(root)
    enums = decls.enum_index(root)
    conts = containers(root)
    bystruct = by_struct(idx)
    defs = defaults(root)
    _, _, reads, _ = reach.build(root)
    groups = families.group_registry(root)
    group_values = sorted({v for tier in ("ffc", "ecc")
                           for v, _ in groups[tier]})
    group_gated = sorted({v for tier in ("ffc", "ecc")
                          for v, g in groups[tier] if g})

    tokcache = {}
    out = []
    for opt in opts:
        body_fams = None
        fields = opt["fields"]
        rec = None
        for f in fields:
            rec = resolve(f, conts, bystruct, idx)
            if rec is not None:
                break

        # Does the branch hand the value to a registry parser?
        tier_fam = None
        for fn, label in TOKEN_PARSERS.items():
            if fn in opt.get("calls", ()):
                if fn not in tokcache:
                    tokcache[fn] = families.token_family(root, fn)[0]
                tier_fam = (label, tokcache[fn])
                break
        if tier_fam is None and INTLIST in opt.get("calls", ()) and \
                GROUP_OPTION.search(opt["option"]):
            tier_fam = ("group", group_values)

        tier, vals, note, shape = plan_domain(opt, rec, enums, defs, tier_fam)

        dist, nsites = None, 0
        for f in fields:
            best, sites = reads.get(re.split(r"->|\.", f)[-1], (None, []))
            nsites += len(sites)
            if best is not None and (dist is None or best < dist):
                dist = best

        if tier_fam is not None and tier_fam[0] == "group":
            note += "; %d of them need a build flag (%s)" % (
                len(group_gated), " ".join(map(str, group_gated)))

        out.append({
            "option": opt["option"],
            "field": fields[0] if fields else None,
            "struct": rec["struct"] if rec else None,
            "type": rec["type"] if rec else None,
            "tier": tier,
            "shape": shape,
            "values": vals,
            "note": note,
            "distance": dist,
            "sites": nsites,
        })
    # Nearest the frame builders first: an axis read inside one changes the air
    # directly, and a run that has to stop early should have done those.
    out.sort(key=lambda a: (a["distance"] if a["distance"] is not None else 99,
                            -a["sites"], a["option"]))
    return out


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    root = os.path.abspath(args[0]) if args else os.getcwd()
    show_all = "--all" in sys.argv
    axes = build(root)
    live = [a for a in axes
            if a["distance"] is not None and a["tier"] != "NONE"]

    if "--json" in sys.argv:
        json.dump(axes if show_all else live, sys.stdout, indent=1)
        print()
        return 0

    if "--stats" not in sys.argv:
        for a in (axes if show_all else live):
            vals = a["values"]
            shown = " ".join(str(v) for v in vals[:6])
            if len(vals) > 6:
                shown += " ... (%d)" % len(vals)
            print("%-30s %-7s %-4s %-36s %s" % (
                a["option"], a["tier"],
                "-" if a["distance"] is None else "d%d" % a["distance"],
                shown, a["note"][:40]))
        print()

    tiers, dists = {}, {}
    for a in live:
        tiers[a["tier"]] = tiers.get(a["tier"], 0) + 1
        dists[a["distance"]] = dists.get(a["distance"], 0) + 1
    print("%d options parsed; %d have a domain and are read somewhere"
          % (len(axes), len(live)))
    print("tiers: %s" % ", ".join("%s %d" % kv for kv in sorted(tiers.items())))
    print("by distance from a frame writer: %s" % ", ".join(
        "d%s:%d" % kv for kv in sorted(dists.items())))
    print("%d axis settings in all" % sum(len(a["values"]) for a in live))
    no_domain = [a for a in axes if a["tier"] == "NONE"]
    print("%d option(s) have no domain this can derive -- listed with --all, "
          "not dropped" % len(no_domain))
    return 0


if __name__ == "__main__":
    sys.exit(main())
