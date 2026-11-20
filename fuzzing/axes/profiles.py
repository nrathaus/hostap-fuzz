#!/usr/bin/env python3
"""Turn the axis list into runnable configurations, and read the results back.

The mutation engine can only change octets of a frame the running configuration
caused hostapd to build. So the unit of coverage here is not a case, it is a
RUN: one configuration, one value on one axis, everything else held. A family is
covered when every member of it has been the setting of some run.

    profiles.py gen  [CHECKOUT] --out DIR     write one .conf per axis setting
    profiles.py plan [CHECKOUT]               what gen would write, as a list
    profiles.py report DIR                    union the runs, check the inventory

'gen' never decides which axes matter. It takes the order axes.py produced
(nearest the frame builders first) and whatever filters were asked for, and the
filters are recorded in the manifest so a report can say what was not run rather
than quietly leaving it out.
"""

import argparse
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "ledger"))
import axes as axes_mod

BASE_CONF = os.path.join("hostapd", "hostapd-wpa3.conf")

# Options that decide which machine the run happens on rather than what goes on
# the air. Overriding one does not widen coverage, it breaks the run, and a
# broken run is indistinguishable from an axis that reached nothing.
PLATFORM = {
    "interface", "driver", "bridge", "vlan_bridge", "wds_bridge",
    "ctrl_interface", "ctrl_interface_group", "logger_stdout",
    "logger_stdout_level", "logger_syslog", "logger_syslog_level",
    "driver_params", "accept_mac_file", "deny_mac_file", "eap_user_file",
    "dump_file", "debug",
}


def set_option(conf_text, option, value):
    """Base configuration with this option set, replacing it if present."""
    pat = re.compile(r"^[ \t]*%s[ \t]*=.*$" % re.escape(option), re.M)
    line = "%s=%s" % (option, value)
    if pat.search(conf_text):
        return pat.sub(line, conf_text, count=1)
    return conf_text.rstrip("\n") + "\n\n# axis under test\n" + line + "\n"


def select(axes, tier=None, max_distance=None, pattern=None, limit=None):
    out = []
    rx = re.compile(pattern) if pattern else None
    for a in axes:
        if a["option"] in PLATFORM or a["tier"] == "NONE":
            continue
        if a["distance"] is None:
            continue
        if tier and a["tier"] not in tier:
            continue
        if max_distance is not None and a["distance"] > max_distance:
            continue
        if rx and not rx.search(a["option"]):
            continue
        out.append(a)
        if limit and len(out) >= limit:
            break
    return out


def render(shape, value):
    """The text a .conf line carries for this value.

    A length domain is written as text OF that length. The content is filler
    on purpose: what the octets say is the mutation engine's job, and how many
    there are is this one's. Mixing the two would mean neither is enumerated.
    """
    if shape == "length":
        return "a" * int(value)
    if shape == "hex-length":
        return "61" * int(value)
    return str(value)


def profile_id(option, value):
    return "%s__%s" % (option, re.sub(r"[^A-Za-z0-9_.-]", "_", str(value)))


def gen(root, outdir, picked):
    base = open(os.path.join(root, BASE_CONF), encoding="utf-8").read()
    os.makedirs(outdir, exist_ok=True)
    manifest = []
    for a in picked:
        for value in a["values"]:
            text = render(a.get("shape", "value"), value)
            pid = profile_id(a["option"], value)
            path = os.path.join(outdir, pid + ".conf")
            with open(path, "w", encoding="utf-8") as f:
                f.write(set_option(base, a["option"], text))
            manifest.append({
                "id": pid, "conf": os.path.basename(path),
                "option": a["option"], "value": value, "text": text,
                "shape": a.get("shape", "value"),
                "tier": a["tier"], "distance": a["distance"],
                "note": a["note"],
            })
    return manifest


def report(outdir):
    """Union every run's ledger and say what the inventory still has left.

    A run that produced no ledger is reported as such and not counted as a run
    that reached nothing: a configuration hostapd refused is a fact about the
    configuration, and silently folding it into the coverage total would turn a
    broken profile into apparent evidence of an unreachable target.
    """
    mpath = os.path.join(outdir, "manifest.json")
    if not os.path.isfile(mpath):
        raise SystemExit("no manifest.json in %s -- run 'gen' first" % outdir)
    doc = json.load(open(mpath, encoding="utf-8"))
    manifest = doc["profiles"] if isinstance(doc, dict) else doc
    filters = doc.get("filters") if isinstance(doc, dict) else None

    inventory, reached, by_label = set(), set(), {}
    ran = failed = empty = 0
    for entry in manifest:
        rpath = os.path.join(outdir, entry["id"] + ".json")
        if not os.path.isfile(rpath):
            continue
        try:
            res = json.load(open(rpath, encoding="utf-8"))
        except ValueError:
            failed += 1
            continue
        # No inventory means hostapd never reached the first mutation: the
        # inventory is emitted ahead of every case. Same fact as an explicit
        # startup_failed, arrived at from the other side.
        if res.get("startup_failed") or res.get("inventory") is None:
            failed += 1
            continue
        ran += 1
        inventory |= set(res.get("inventory", []))
        hit = set(res.get("targets", []))
        if not hit:
            empty += 1
        reached |= hit
        for label in hit:
            by_label.setdefault(label, []).append(
                "%s=%s" % (entry["option"], entry["value"]))

    print("%d profile(s) in the manifest" % len(manifest))
    if filters:
        print("selected with: %s" % json.dumps(filters))
    print("%d ran, %d were refused at startup, %d ran and reached no target"
          % (ran, failed, empty))
    if not inventory:
        print("\nno inventory seen -- no run produced a ledger")
        return 1

    print("\n%d of %d target labels reached" % (len(reached & inventory),
                                                len(inventory)))
    for label in sorted(inventory):
        hits = by_label.get(label, [])
        if hits:
            print("  %-30s %s%s" % (label, hits[0],
                                    " (+%d more)" % (len(hits) - 1)
                                    if len(hits) > 1 else ""))
        else:
            print("  %-30s NOT REACHED by any profile run" % label)
    missing = sorted(inventory - reached)
    if missing:
        print("\n%d label(s) were not reached. Each is either out of reach in "
              "this topology -- no peer in the run plays the role that makes "
              "hostapd build the frame -- or waiting on an axis this selection "
              "filtered out. The manifest records the filter." % len(missing))
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("action", choices=["gen", "plan", "report"])
    ap.add_argument("path", nargs="?", default=".")
    ap.add_argument("--out", default="fuzz-profiles")
    ap.add_argument("--tier", action="append",
                    help="FULL or LADDER; repeatable. Default: FULL only, "
                         "which is every domain small enough to enumerate "
                         "whole.")
    ap.add_argument("--distance", type=int, default=1,
                    help="how far from a frame writer an axis may be read "
                         "(default 1); raise it to include the rest")
    ap.add_argument("--option", help="regex over option names")
    ap.add_argument("--limit", type=int)
    args = ap.parse_args()

    if args.action == "report":
        return report(args.path if args.path != "." else args.out)

    root = os.path.abspath(args.path)
    picked = select(axes_mod.build(root), tier=args.tier or ["FULL"],
                    max_distance=args.distance, pattern=args.option,
                    limit=args.limit)
    total = sum(len(a["values"]) for a in picked)

    if args.action == "plan":
        for a in picked:
            print("%-30s %-7s d%-2d %3d value(s)  %s" % (
                a["option"], a["tier"], a["distance"], len(a["values"]),
                a["note"][:46]))
        print("\n%d axes, %d runs" % (len(picked), total))
        return 0

    outdir = os.path.abspath(args.out)
    manifest = gen(root, outdir, picked)
    with open(os.path.join(outdir, "manifest.json"), "w",
              encoding="utf-8") as f:
        json.dump({"filters": {"tier": args.tier or ["FULL"],
                               "distance": args.distance,
                               "option": args.option, "limit": args.limit},
                   "profiles": manifest}, f, indent=1)
    print("%d profile(s) written to %s" % (len(manifest), outdir))
    print("the filters used are recorded beside them, so a report can say "
          "what was left out rather than omitting it")
    return 0


if __name__ == "__main__":
    sys.exit(main())
