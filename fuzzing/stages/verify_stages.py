#!/usr/bin/env python3
"""Behavioural checks for fuzz_stage_repeat(): the budget, its scope, and the
guarantee that a build with it compiled in behaves as it did until asked.

    python3 verify_stages.py /path/to/checkout

Needs no radio, no interface and no root: it compiles a small harness against
the checkout's own fuzz.o and drives the primitive directly. Build the checkout
with CONFIG_FUZZ=y first.

What is worth checking here is not "does it repeat" -- one run shows that --
but the properties a long campaign depends on and that a quick look would miss:
that the budget terminates a loop, that one peer's budget is not another's, and
that a reconnecting station gets its budget back. A primitive that leaked
budget across sessions would repeat a stage in the first session of a run and
in no other, which looks exactly like a stage that does not repeat at all.
"""

import json
import os
import re
import subprocess
import sys
import tempfile

PREFIX = "[fuzz] "

OBJECTS = [
    "src/common/fuzz.o",
    "src/utils/json.o",
    "src/utils/wpabuf.o",
    "src/utils/common.o",
    "src/utils/os_unix.o",
    "src/utils/base64.o",
    "src/utils/wpa_debug.o",
]

# A tiny interpreter, so one compiled harness covers every ordering of calls a
# check wants to make. "rep <stage> <peer>" and "reset <peer>"; a peer of "-"
# is the NULL pointer, which is the not-per-peer case.
HARNESS = """
#include "utils/includes.h"
#include "utils/common.h"
#include "common/fuzz.h"

static int parse_peer(const char *s, u8 *out)
{
\tif (os_strcmp(s, "-") == 0)
\t\treturn 0;
\tif (hexstr2bin(s, out, ETH_ALEN) < 0)
\t\treturn -1;
\treturn 1;
}

int main(int argc, char *argv[])
{
\tint i = 1;

\twhile (i < argc) {
\t\tu8 peer[ETH_ALEN];
\t\tint have;

\t\tif (os_strcmp(argv[i], "rep") == 0 && i + 2 < argc) {
\t\t\thave = parse_peer(argv[i + 2], peer);
\t\t\tif (have < 0)
\t\t\t\treturn 2;
\t\t\tprintf("rep %s %s %d\\n", argv[i + 1], argv[i + 2],
\t\t\t       fuzz_stage_repeat(argv[i + 1],
\t\t\t\t\t\t have ? peer : NULL));
\t\t\ti += 3;
\t\t} else if (os_strcmp(argv[i], "reset") == 0 && i + 1 < argc) {
\t\t\thave = parse_peer(argv[i + 1], peer);
\t\t\tif (have < 0)
\t\t\t\treturn 2;
\t\t\tfuzz_peer_reset(have ? peer : NULL);
\t\t\tprintf("reset %s\\n", argv[i + 1]);
\t\t\ti += 2;
\t\t} else {
\t\t\treturn 2;
\t\t}
\t}

\treturn 0;
}
"""

PEER_A = "020000000001"
PEER_B = "020000000002"


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


def build(root, workdir):
    objdir = os.path.join(root, "build", "hostapd")
    missing = [o for o in OBJECTS
               if not os.path.exists(os.path.join(objdir, o))]
    if missing:
        print("cannot find %s under %s" % (missing[0], objdir))
        print("Build the checkout with CONFIG_FUZZ=y first:")
        print("    cd hostapd && make")
        return None

    path = os.path.join(workdir, "stages.c")
    binary = os.path.join(workdir, "stages")
    with open(path, "w", encoding="utf-8") as f:
        f.write(HARNESS)

    command = [
        os.environ.get("CC", "cc"), "-o", binary, path,
        "-I%s" % os.path.join(root, "src"),
        "-I%s" % os.path.join(root, "src", "utils"),
        "-DCONFIG_FUZZ",
    ] + [os.path.join(objdir, o) for o in OBJECTS]

    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode != 0:
        print("the harness did not compile:")
        print(result.stderr.strip()[:2000])
        return None
    return binary


def run(binary, ops, env=None):
    """(results, messages): the 'rep' outcomes and the [fuzz] lines."""
    e = dict(os.environ)
    for k in list(e):
        if k.startswith("FUZZ_"):
            del e[k]
    e.update(env or {})
    out = subprocess.run([binary] + ops, capture_output=True, text=True,
                         env=e).stdout

    results, messages = [], []
    for line in out.splitlines():
        if line.startswith(PREFIX):
            try:
                messages.append(json.loads(line[len(PREFIX):]))
            except ValueError:
                messages.append({"msg": "unparsable", "line": line})
        elif line.startswith("rep "):
            parts = line.split()
            results.append((parts[1], parts[2], int(parts[3])))
    return results, messages


def rep(stage, peer, n=1):
    return ["rep", stage, peer] * n


def check_default(binary, check):
    print("\nA budget nobody set is no budget")
    results, messages = run(binary, rep("eapol-m1", PEER_A, 5))
    check.ok(all(r[2] == 0 for r in results),
             "with no FUZZ_REPEAT_* set, the stage never repeats",
             str(results))
    check.ok(not messages,
             "and nothing is emitted, so a run that is not using this looks "
             "exactly as it did", str(messages[:2]))


def check_budget(binary, check):
    print("\nThe budget is spent, and then it is gone")
    results, _ = run(binary, rep("eapol-m1", PEER_A, 6),
                     {"FUZZ_REPEAT_EAPOL_M1": "3"})
    got = [r[2] for r in results]
    check.ok(got == [1, 1, 1, 0, 0, 0],
             "FUZZ_REPEAT_EAPOL_M1=3 returns true exactly three times",
             str(got))
    check.ok(got[3:] == [0, 0, 0],
             "so a 'while (fuzz_stage_repeat(...))' loop terminates")

    for value in ("0", "-1", "", "nonsense"):
        results, _ = run(binary, rep("eapol-m1", PEER_A, 3),
                         {"FUZZ_REPEAT_EAPOL_M1": value})
        check.ok(all(r[2] == 0 for r in results),
                 "a budget of %r is no budget" % value,
                 str([r[2] for r in results]))

    results, _ = run(binary, rep("eapol-m1", PEER_A, 40),
                     {"FUZZ_REPEAT_EAPOL_M1": "1000"})
    n = sum(r[2] for r in results)
    check.ok(0 < n <= 32,
             "an absurd budget is clamped (%d repeats, cap 32), so one stage "
             "cannot starve the ones behind it" % n)


def check_scope(binary, check):
    print("\nWhose budget it is")
    ops = rep("eapol-m1", PEER_A, 2) + rep("eapol-m1", PEER_B, 2)
    results, _ = run(binary, ops, {"FUZZ_REPEAT_EAPOL_M1": "2"})
    check.ok([r[2] for r in results] == [1, 1, 1, 1],
             "each peer gets its own budget",
             str([r[2] for r in results]))

    ops = rep("eapol-m1", PEER_A, 2) + rep("eapol-m3", PEER_A, 2)
    results, _ = run(binary, ops, {"FUZZ_REPEAT_EAPOL_M1": "1",
                                   "FUZZ_REPEAT_EAPOL_M3": "1"})
    check.ok([r[2] for r in results] == [1, 0, 1, 0],
             "each stage gets its own budget",
             str([r[2] for r in results]))

    ops = rep("eapol-m1", PEER_A, 2) + rep("eapol-m3", PEER_A, 2)
    results, _ = run(binary, ops, {"FUZZ_REPEAT_EAPOL_M1": "1"})
    check.ok([r[2] for r in results] == [1, 0, 0, 0],
             "and a stage with no budget stays at one occurrence while "
             "another repeats", str([r[2] for r in results]))


def check_reset(binary, check):
    print("\nA new session is a new budget")
    ops = (rep("eapol-m1", PEER_A, 2) + ["reset", PEER_A] +
           rep("eapol-m1", PEER_A, 2))
    results, _ = run(binary, ops, {"FUZZ_REPEAT_EAPOL_M1": "1"})
    check.ok([r[2] for r in results] == [1, 0, 1, 0],
             "a peer's budget comes back when its session is torn down",
             str([r[2] for r in results]))

    ops = (rep("eapol-m1", PEER_A, 1) + rep("eapol-m1", PEER_B, 1) +
           ["reset", PEER_A] +
           rep("eapol-m1", PEER_A, 1) + rep("eapol-m1", PEER_B, 1))
    results, _ = run(binary, ops, {"FUZZ_REPEAT_EAPOL_M1": "1"})
    check.ok([r[2] for r in results] == [1, 1, 1, 0],
             "and resetting one peer leaves the other's budget alone",
             str([r[2] for r in results]))


def check_disable(binary, check):
    print("\nFUZZ_DISABLE still means disabled")
    results, messages = run(binary, rep("eapol-m1", PEER_A, 3),
                            {"FUZZ_REPEAT_EAPOL_M1": "3", "FUZZ_DISABLE": "1"})
    check.ok(all(r[2] == 0 for r in results),
             "a budget is ignored under FUZZ_DISABLE=1, so the control run "
             "is a control run", str([r[2] for r in results]))
    check.ok(not messages, "and nothing is emitted")


def check_message(binary, check):
    print("\nThe repeat message")
    _, messages = run(binary, rep("eapol-m1", PEER_A, 2),
                      {"FUZZ_REPEAT_EAPOL_M1": "2"})
    check.ok(len(messages) == 2,
             "one message per extra occurrence (%d)" % len(messages))
    if len(messages) != 2:
        return
    first, second = messages
    check.ok(all(m.get("msg") == "repeat" for m in messages),
             "every line is a JSON object with a 'msg', as the contract says")
    check.ok(first.get("stage") == "eapol-m1" and first.get("of") == 2,
             "it names the stage and the budget", json.dumps(first))
    check.ok((first.get("n"), second.get("n")) == (1, 2),
             "and counts the occurrences, so a consumer can tell the second "
             "from the fourth", str((first.get("n"), second.get("n"))))
    check.ok(re.fullmatch(r"02:00:00:00:00:01", first.get("peer") or ""),
             "and names the peer", str(first.get("peer")))

    _, messages = run(binary, rep("eapol-m1", "-", 1),
                      {"FUZZ_REPEAT_EAPOL_M1": "1"})
    check.ok(messages and "peer" not in messages[0],
             "a stage with no peer omits the field rather than inventing one",
             json.dumps(messages[0]) if messages else "no message")


def check_inventory(root, check):
    print("\nThe inventory announces them")
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import stages as stages_mod
    table = stages_mod.table_in_fuzz_c(root)
    found = set(stages_mod.extract(root))
    check.ok(table is not None and table == found,
             "fuzz_known_stages[] lists every stage the tree guards (%d)"
             % len(found),
             "table=%s tree=%s" % (sorted(table or []), sorted(found)))
    src = open(os.path.join(root, "src", "common", "fuzz.c"),
               encoding="utf-8").read()
    check.ok('json_start_array(json, "stages")' in src,
             "and the inventory message carries them, so a stage that was "
             "never repeated is still known to exist")


def main():
    root = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else ".")
    check = Check()
    with tempfile.TemporaryDirectory() as tmp:
        binary = build(root, tmp)
        if not binary:
            return 2
        for fn in (check_default, check_budget, check_scope, check_reset,
                   check_disable, check_message):
            fn(binary, check)
        check_inventory(root, check)
    print("\n%d of %d checks pass" % (check.passed,
                                      check.passed + check.failed))
    return 1 if check.failed else 0


if __name__ == "__main__":
    sys.exit(main())
