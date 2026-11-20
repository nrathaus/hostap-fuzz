#!/usr/bin/env python3
"""Extract the set of stages this tree can re-issue, and check the table.

A stage label is the first argument of fuzz_stage_repeat(). The extraction and
the drift check mirror fuzzing/ledger/targets.py, and for the same reason: a stage
added at a call site without being added to fuzz_known_stages[] would honour
its FUZZ_REPEAT_* while never announcing that it exists, so a consumer reading
the inventory would be told the stage is not there.

    python3 stages.py [CHECKOUT]            list the stages
    python3 stages.py [CHECKOUT] --check    compare against fuzz.c, exit 1 on drift
    python3 stages.py [CHECKOUT] --emit     regenerate the table
"""

import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "ledger"))
import targets as targets_mod

SCAN_DIRS = ["src", "hostapd", "wpa_supplicant"]

TABLE_RE = re.compile(
    r"static const char \* const fuzz_known_stages\[\] = \{(.*?)\n\};",
    re.S)


def extract(root):
    """{stage: {file, ...}} over every fuzz_stage_repeat() call site."""
    found = {}
    for d in SCAN_DIRS:
        for dirpath, _, names in os.walk(os.path.join(root, d)):
            for name in names:
                if not name.endswith(".c"):
                    continue
                path = os.path.join(dirpath, name)
                with open(path, encoding="utf-8", errors="replace") as f:
                    src = targets_mod.strip_comments(f.read())
                if "fuzz_stage_repeat" not in src:
                    continue
                for args in targets_mod.call_args(src, "fuzz_stage_repeat"):
                    if not args:
                        continue
                    lit = targets_mod.literal(args[0])
                    if lit is not None:
                        found.setdefault(lit, set()).add(
                            os.path.relpath(path, root))
    return found


def table_in_fuzz_c(root):
    path = os.path.join(root, "src", "common", "fuzz.c")
    with open(path, encoding="utf-8") as f:
        m = TABLE_RE.search(f.read())
    if not m:
        return None
    return set(re.findall(r'"((?:[^"\\]|\\.)*)"', m.group(1)))


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    root = os.path.abspath(args[0]) if args else os.getcwd()
    found = extract(root)

    if "--emit" in sys.argv:
        print("static const char * const fuzz_known_stages[] = {")
        for name in sorted(found):
            print('\t"%s",' % name)
        print("};")
        return 0

    if "--check" not in sys.argv:
        for name in sorted(found):
            print("%-20s %s" % (name, " ".join(sorted(found[name]))))
        print("\n%d stage(s)" % len(found))
        return 0

    table = table_in_fuzz_c(root)
    if table is None:
        print("FAIL: no fuzz_known_stages[] table found in src/common/fuzz.c")
        return 1

    # fuzz_report_repeat() writes these into JSON unescaped and
    # fuzz_env_name() folds them into FUZZ_REPEAT_<STAGE>, so the charset is
    # checked rather than assumed -- the same contract the target labels have.
    bad = sorted(n for n in found if not re.fullmatch(r"[A-Za-z0-9_-]+", n))
    for name in bad:
        print("FAIL: stage is not [A-Za-z0-9_-]: %r" % name)
    if bad:
        return 1

    missing = sorted(set(found) - table)
    extra = sorted(table - set(found))
    for name in missing:
        print("FAIL: guarded in the tree but absent from fuzz_known_stages[]: "
              "%s" % name)
    for name in extra:
        print("FAIL: in fuzz_known_stages[] but no call site guards it: %s"
              % name)
    if missing or extra:
        print("\n%d stage(s) differ. Regenerate with: python3 %s %s --emit"
              % (len(missing) + len(extra), os.path.basename(__file__), root))
        return 1
    print("OK: %d stages, table matches the tree" % len(table))
    return 0


if __name__ == "__main__":
    sys.exit(main())
