#!/usr/bin/env python3
"""Checks on the axis list -- that it is derived, and that a run can attribute
its coverage to exactly one axis.

The value of this list is entirely in its being mechanical. A list someone
curated would look the same and be worth much less, because the options it
omits would be omitted silently and forever. So what is checked here is not
"are these good axes" -- that is not a question a test can answer -- but the
properties that make the list trustworthy without anyone vouching for it:

  it matches the parser               nothing invented, nothing dropped
  the domains come from the tree      enums, registries and widths as declared
  one axis per configuration          so coverage attributes to one setting
  the one hand-written list is small, justified, and still accurate

    python3 verify_axes.py [CHECKOUT]
"""

import json
import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import axes as axes_mod
import cparse
import decls
import families
import options as options_mod
import profiles


class Check:
    def __init__(self):
        self.passed = self.failed = 0

    def ok(self, cond, what, detail=""):
        if cond:
            self.passed += 1
            print("  ok    %s" % what)
        else:
            self.failed += 1
            print("  FAIL  %s" % what)
            if detail:
                print("        %s" % detail)


def check_parser_match(root, check):
    """The options are the parser's, all of them and only them."""
    print("\nThe list is the parser's")
    path = os.path.join(root, "hostapd", "config_file.c")
    src = cparse.strip_comments(open(path, encoding="utf-8").read())
    body = cparse.function_body(src, "hostapd_config_fill")
    literal = set(re.findall(r'os_strcmp\(buf,\s*"([^"]*)"\)\s*==\s*0', body))
    extracted = {o["option"] for o in options_mod.extract(root)}

    check.ok(extracted == literal,
             "every parsed option is extracted, and no others (%d)"
             % len(literal),
             "missing=%s extra=%s" % (sorted(literal - extracted)[:5],
                                      sorted(extracted - literal)[:5]))
    check.ok(len(extracted) > 400,
             "the chain was walked, not truncated (%d options)"
             % len(extracted))


def check_domains(root, check):
    """Every domain traces to a declaration or a registry in the tree."""
    print("\nThe domains come from the tree")
    axes = axes_mod.build(root)
    enums = decls.enum_index(root)
    byopt = {a["option"]: a for a in axes}

    bad = []
    for a in axes:
        if not a["note"].startswith("enum "):
            continue
        ename = a["note"].split()[1].rstrip(",")
        declared = sorted({v for _, v in enums.get(ename, [])
                           if v is not None})
        if sorted(a["values"]) != declared:
            bad.append((a["option"], ename, a["values"], declared))
    check.ok(not bad, "every enum axis sweeps exactly its declared members",
             "; ".join("%s/%s got %s want %s" % b for b in bad[:3]))

    toks, _ = families.token_family(root, "hostapd_config_parse_key_mgmt")
    km = byopt.get("wpa_key_mgmt")
    check.ok(km and set(km["values"]) == toks,
             "the key-management axis sweeps every name the parser accepts "
             "(%d)" % len(toks),
             "" if not km else "axis=%d parser=%d" % (len(km["values"]),
                                                      len(toks)))

    groups = families.group_registry(root)
    known = {v for tier in ("ffc", "ecc") for v, _ in groups[tier]}
    sg = byopt.get("sae_groups")
    check.ok(sg and set(sg["values"]) == known,
             "the group axis sweeps every group the tree can instantiate "
             "(%d)" % len(known))
    check.ok(sg and len(sg["values"]) > len(groups["production"]),
             "and more than the production filter accepts (%d), which is "
             "the point of sweeping it" % len(groups["production"]))

    # A ladder that does not contain the default cannot tell a value that
    # broke something from a build that was broken already.
    defs = axes_mod.defaults(root)
    missing, sentinel = [], []
    for a in axes:
        if a["tier"] != "LADDER" or not a["field"]:
            continue
        d = axes_mod.as_int(defs.get(re.split(r"->|\.", a["field"])[-1]))
        if d is None or d in a["values"]:
            continue
        # A default the parser itself would reject is a sentinel -- "leave it
        # to the driver" -- not a value a sweep failed to include.
        if "is outside what the parser accepts" in a["note"]:
            sentinel.append(a["option"])
        else:
            missing.append(a["option"])
    check.ok(not missing,
             "every ladder includes the field's own default, except where "
             "the default is a sentinel the parser rejects (%d of those)"
             % len(sentinel),
             "without it: %s" % missing[:5])


def check_one_axis_per_conf(root, check):
    """A generated configuration differs from the base in one line."""
    print("\nOne axis per configuration")
    base_path = os.path.join(root, profiles.BASE_CONF)
    base = open(base_path, encoding="utf-8").read().splitlines()
    picked = profiles.select(axes_mod.build(root), tier=["FULL"],
                             max_distance=1)
    check.ok(picked, "there is something to run (%d axes)" % len(picked))

    with tempfile.TemporaryDirectory() as tmp:
        manifest = profiles.gen(root, tmp, picked)
        multi, platform, lengths, missing = [], [], [], []
        for entry in manifest:
            text = open(os.path.join(tmp, entry["conf"]),
                        encoding="utf-8").read().splitlines()
            changed = [l for l in text
                       if l not in base and l.strip()
                       and not l.startswith("#")]
            line = "%s=%s" % (entry["option"], entry["text"])
            # Zero lines changed is correct when the base already carries this
            # exact setting -- the axis still runs, it just happens to start at
            # the value the base uses. What must never happen is the setting
            # not being in the file at all.
            if line not in text:
                missing.append(entry["id"])
            if len(changed) > 1:
                multi.append((entry["id"], changed))
            if entry["option"] in profiles.PLATFORM:
                platform.append(entry["id"])
            if entry["shape"] == "length" and \
                    len(entry["text"]) != int(entry["value"]):
                lengths.append(entry["id"])

        check.ok(not multi,
                 "no configuration changes more than one line from the base, "
                 "so coverage attributes to one axis (%d checked)"
                 % len(manifest),
                 "; ".join("%s -> %s" % (i, c) for i, c in multi[:3]))
        check.ok(not missing,
                 "and every configuration actually carries its axis setting",
                 str(missing[:5]))
        check.ok(not platform,
                 "no configuration overrides an option that decides which "
                 "machine the run happens on", str(platform[:5]))
        check.ok(not lengths,
                 "a length domain is written as text of that length, not as "
                 "the number", str(lengths[:5]))
        ids = [e["id"] for e in manifest]
        check.ok(len(ids) == len(set(ids)),
                 "profile names are unique, so one run cannot overwrite "
                 "another's ledger")


def check_hand_written_list(root, check):
    """The one list in here that a person typed, kept honest."""
    print("\nThe one hand-written list")
    parsed = {o["option"] for o in options_mod.extract(root)}
    unknown = sorted(profiles.PLATFORM - parsed)
    check.ok(not unknown,
             "every excluded option still exists in the parser (%d excluded)"
             % len(profiles.PLATFORM),
             "no longer options: %s" % unknown)
    check.ok(len(profiles.PLATFORM) < 0.1 * len(parsed),
             "the exclusion list is a small fraction of the options "
             "(%d of %d)" % (len(profiles.PLATFORM), len(parsed)))


def check_report_is_honest(root, check):
    """A refused configuration must not read as a target that cannot be hit."""
    print("\nA refused run is not a measurement")
    with tempfile.TemporaryDirectory() as tmp:
        picked = profiles.select(axes_mod.build(root), tier=["FULL"],
                                 max_distance=1, limit=1)
        manifest = profiles.gen(root, tmp, picked)
        with open(os.path.join(tmp, "manifest.json"), "w") as f:
            json.dump({"filters": {}, "profiles": manifest}, f)
        inv = ["alpha", "beta"]
        for i, entry in enumerate(manifest):
            res = ({"startup_failed": True, "returncode": 1} if i == 0 else
                   {"inventory": inv, "targets": ["alpha"]})
            with open(os.path.join(tmp, entry["id"] + ".json"), "w") as f:
                json.dump(res, f)
        out = subprocess.run(
            [sys.executable, os.path.join(HERE, "profiles.py"),
             "report", tmp], capture_output=True, text=True).stdout
    check.ok("1 were refused at startup" in out or
             "1 were refused" in out,
             "a configuration hostapd refused is counted as refused")
    check.ok("beta" in out and "NOT REACHED" in out,
             "a target no run reached is named, not left out")
    check.ok("alpha " in out and "NOT REACHED by any profile run" not in
             out.split("alpha")[1].split("\n")[0],
             "a target some run reached is shown with the setting that "
             "reached it")


def main():
    root = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else ".")
    check = Check()
    for fn in (check_parser_match, check_domains, check_one_axis_per_conf,
               check_hand_written_list, check_report_is_honest):
        fn(root, check)
    print("\n%d of %d checks pass" % (check.passed,
                                      check.passed + check.failed))
    return 1 if check.failed else 0


if __name__ == "__main__":
    sys.exit(main())
