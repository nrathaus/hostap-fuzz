#!/usr/bin/env python3
"""Behavioural checks for the mutation hook: the sweep, FUZZ_HOLD and the
`[fuzz] ` output contract.

    python3 fuzz_verify.py /path/to/checkout

Needs no radio, no interface and no root: it compiles two small harnesses
against the checkout's own `fuzz.o` and drives the mutation hook directly. The
checkout must have been built with CONFIG_FUZZ=y first, since the harnesses
link the objects the build produces:

    cd hostapd && cp defconfig-fuzz .config && make

This is a companion to the two acceptance scripts beside it, which check that
their own asks landed. It covers what those do not: that the sweep is
unchanged, that a held target behaves, and that the states and the abandonment
ordering are right. Run all three after touching src/common/fuzz.c.
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile

PREFIX = "[fuzz] "

# 0x41 is not one of the interesting values and no mutation can produce it from
# itself, so every applied mutation is visible against a frame filled with it.
FILL = 0x41

#  Drives the hook one frame at a time, reporting the frame it was left with so
#  the caller can see when nothing was mutated -- which is the whole question
#  for a held target.
HARNESS = """
#include "utils/includes.h"
#include "utils/common.h"
#include "common/fuzz.h"

int main(int argc, char *argv[])
{
\tconst char *target = argv[1];
\tsize_t len;
\tint iterations, defer, i;
\tenum fuzz_frame_type type;
\tu8 *frame;
\tchar *hex;

\tif (argc < 5)
\t\treturn 2;

\tlen = (size_t) atoi(argv[2]);
\titerations = atoi(argv[3]);
\ttype = os_strcmp(argv[4], "eapol") == 0 ? FUZZ_TYPE_IEEE802_1X_HDR :
\t\tFUZZ_TYPE_IEEE80211_MGMT;
\tdefer = argc > 5 && os_strcmp(argv[5], "defer") == 0;

\tframe = os_malloc(len ? len : 1);
\thex = os_malloc(2 * len + 2);
\tif (!frame || !hex)
\t\treturn 2;

\tfor (i = 0; i < iterations; i++) {
\t\tos_memset(frame, 0x%02X, len);
\t\tif (defer)
\t\t\tapply_mutation_defer_log(target, type, frame, len,
\t\t\t\t\t\t len);
\t\telse
\t\t\tapply_mutation(target, type, frame, len);
\t\twpa_snprintf_hex(hex, 2 * len + 2, frame, len);
\t\tprintf("[harness] %%s\\n", hex);
\t\tif (defer)
\t\t\tfuzz_log_sent_frame(frame, len);
\t}

\tos_free(frame);
\tos_free(hex);

\treturn 0;
}
""" % FILL

#  Three deferred mutations with one flush at the end: the first two frames are
#  abandoned, which is what an error path between mutation and transmission
#  does.
ABANDON = """
#include "utils/includes.h"
#include "utils/common.h"
#include "common/fuzz.h"

int main(void)
{
\tu8 frame[64];
\tint i;

\tos_memset(frame, 0x%02X, sizeof(frame));
\tfor (i = 0; i < 3; i++)
\t\tapply_mutation_defer_log("eapol", FUZZ_TYPE_IEEE802_1X_HDR,
\t\t\t\t\t frame, sizeof(frame),
\t\t\t\t\t sizeof(frame));
\tfuzz_log_sent_frame(frame, sizeof(frame));

\treturn 0;
}
""" % FILL

OBJECTS = [
    "src/common/fuzz.o",
    "src/utils/json.o",
    "src/utils/wpabuf.o",
    "src/utils/common.o",
    "src/utils/os_unix.o",
    "src/utils/base64.o",
    "src/utils/wpa_debug.o",
]

#  Every target name reachable from the call sites, so the FUZZ_HOLD_ spelling
#  is checked against the rule rather than against one example.
TARGETS = [
    "probe_resp", "assoc_resp", "deauth", "eapol", "auth-sae",
    "sae-send-commit", "sae-send-confirm", "handle-auth", "auth-ft-finish",
    "auth-fils-finish", "sae-commit-override", "auth-sae-reflection-attack",
]

#  A 34-byte management frame leaves 10 fuzzable bytes after the 24-byte
#  header, so the whole sweep is small enough to run exhaustively.
FRAME_LEN = 34
FUZZABLE = 10
CASES_PER_OFFSET = 255
CASES = FUZZABLE * CASES_PER_OFFSET
WARMUP = 9


class Checker:
    """Collects check results so one failure does not hide the rest."""

    def __init__(self):
        self.passes = 0
        self.failures = []

    def ok(self, condition, label, detail=""):
        if condition:
            self.passes += 1
            print(f"  ok    {label}")
        else:
            self.failures.append(label)
            print(f"  FAIL  {label}" + (f": {detail}" if detail else ""))


def build(root, workdir, name, source):
    """Compile one harness against the checkout's built objects."""
    objdir = os.path.join(root, "build", "hostapd")
    missing = [o for o in OBJECTS if not os.path.exists(os.path.join(objdir, o))]
    if missing:
        print(f"cannot find {missing[0]} under {objdir}")
        print("Build the checkout with CONFIG_FUZZ=y first:")
        print("    cd hostapd && cp defconfig-fuzz .config && make")
        return None

    path = os.path.join(workdir, name + ".c")
    binary = os.path.join(workdir, name)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(source)

    command = [
        os.environ.get("CC", "cc"), "-o", binary, path,
        f"-I{os.path.join(root, 'src')}",
        f"-I{os.path.join(root, 'src', 'utils')}",
        "-DCONFIG_FUZZ",
    ] + [os.path.join(objdir, o) for o in OBJECTS]

    result = subprocess.run(command, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        print(f"the {name} harness did not compile:")
        print(result.stderr.strip()[:2000])
        return None

    return binary


def run(binary, argv, **env):
    """Drive a harness and split its output into messages and frames.

    Returns (messages, frames, unparsed): every '[fuzz] ' line that is a JSON
    object with a 'msg', every frame the harness was left holding, and any
    '[fuzz] ' line that is neither.
    """
    environment = dict(os.environ)
    #  A stale FUZZ_* in the caller's environment would silently change every
    #  number below.
    for name in list(environment):
        if name.startswith("FUZZ_"):
            del environment[name]
    environment.update({k: str(v) for k, v in env.items()})

    result = subprocess.run([binary] + [str(a) for a in argv],
                            capture_output=True, env=environment, check=False)
    text = (result.stdout + result.stderr).decode("utf-8", "replace")

    messages, frames, unparsed = [], [], []
    for line in text.splitlines():
        if line.startswith(PREFIX):
            try:
                obj = json.loads(line[len(PREFIX):])
            except ValueError:
                unparsed.append(line)
                continue
            if isinstance(obj, dict) and "msg" in obj:
                messages.append(obj)
            else:
                unparsed.append(line)
        elif line.startswith("[harness] "):
            frames.append(line.split(" ", 1)[1])

    return messages, frames, unparsed


def intact(frame):
    """Whether the harness's fill survived untouched.

    Compares the whole dump: a byte mutated to 0x14 hexdumps as characters that
    are individually present in '41', so a per-character test would miss it.
    """
    return frame == f"{FILL:02x}" * (len(frame) // 2)


def check_sweep(harness, check):
    """The sweep must be exactly what it was before FUZZ_HOLD existed."""
    print(f"the sweep, over a {FRAME_LEN}-byte management frame")
    messages, frames, unparsed = run(
        harness, ["auth-sae", FRAME_LEN, CASES + WARMUP + 3, "mgmt"],
        FUZZ_START_CASE=0)
    progress = [m for m in messages if m["msg"] == "progress"]
    mutations = [m for m in messages if m["msg"] == "fuzz"]

    check.ok(all(p["case_max"] == CASES for p in progress),
             f"case_max is {CASES} for every progress message",
             str({p["case_max"] for p in progress}))
    check.ok(len(mutations) == CASES, f"exactly {CASES} mutations applied",
             f"got {len(mutations)}")

    signatures = {(m["idx"], m["mask"]) for m in mutations}
    check.ok(len(signatures) == CASES, "no duplicate (offset, mask)",
             f"{len(signatures)} distinct")

    per_offset = {}
    for m in mutations:
        per_offset.setdefault(m["idx"], []).append(m)
    check.ok(sorted(per_offset) == list(range(FUZZABLE)),
             f"all {FUZZABLE} offsets swept", str(sorted(per_offset)))
    check.ok(all(len(v) == CASES_PER_OFFSET for v in per_offset.values()),
             f"{CASES_PER_OFFSET} cases per offset",
             str({len(v) for v in per_offset.values()}))
    check.ok({m["type"] for m in mutations} == {"MUT_BYTE_XOR"},
             "one kind, MUT_BYTE_XOR", str({m["type"] for m in mutations}))
    check.ok(all({m["mask"] for m in cases} == set(range(1, 256))
                 for cases in per_offset.values()),
             "every offset gets each of the XOR masks 1..255 exactly once")

    #  The point of the 268 -> 255 change: an offset's cases are 255 distinct
    #  values, which is every value the byte can hold other than the one it
    #  came with, and none of them repeats.
    check.ok(all({m["after"] for m in cases} == set(range(256)) - {FILL}
                 for cases in per_offset.values()),
             "an offset produces all 255 other byte values, none twice")
    check.ok(all(m["before"] == FILL and m["after"] != FILL
                 for m in mutations),
             "no case leaves the byte unchanged")

    #  What the dropped MUT_SET_INTERESTING and MUT_BIT_FLIP kinds really
    #  supplied was the head of the order, and that is kept: a run bounded well
    #  short of an offset's 255 cases still gets those first. Breadth-first,
    #  these are passes over the whole frame.
    interesting = [0x00, 0x01, 0x7F, 0x80, 0xFF]
    check.ok(all([m["after"] for m in cases[:len(interesting)]] == interesting
                 for cases in per_offset.values()),
             "the interesting values lead every offset", str(interesting))
    bit_flips = {1 << b for b in range(8)}
    check.ok(all(bit_flips <= {m["mask"] for m in cases[:13]}
                 for cases in per_offset.values()),
             "all 8 single-bit flips land within the first 13 cases")

    lowest = min((i // 2 for frame in frames
                  for i in range(0, len(frame), 2)
                  if frame[i:i + 2] != f"{FILL:02x}"), default=None)
    check.ok(lowest == 24, "the whole 24-byte 802.11 header is skipped",
             f"lowest mutated byte is {lowest}")
    check.ok(sum(1 for f in frames if intact(f)) == WARMUP + 3,
             f"{WARMUP} warm-up frames and 3 past case_max are untouched",
             str(sum(1 for f in frames if intact(f))))
    check.ok(not unparsed, "every [fuzz] line is JSON with a msg",
             str(unparsed[:2]))

    states = {}
    for message in progress:
        states.setdefault(message["state"], []).append(message["case_id"])
    check.ok(set(states) == {"warmup", "mutating", "done"},
             "progress reports warmup, mutating and done", str(set(states)))
    check.ok(all(c < 0 for c in states.get("warmup", [])),
             "warmup is exactly the range below zero")
    check.ok(len(states.get("warmup", [])) == WARMUP,
             f"the warm-up is {WARMUP} frames",
             str(len(states.get("warmup", []))))
    check.ok(all(0 <= c < CASES for c in states.get("mutating", [])),
             "mutating is exactly 0..case_max-1")
    check.ok(all(c == CASES for c in states.get("done", [])),
             "done is the case_max lock")


def check_hold(harness, check):
    """A held target answers correctly, announces itself, and burns no cases."""
    print("FUZZ_HOLD_<TARGET>")
    held_frames = 50
    messages, frames, unparsed = run(harness, ["probe_resp", 200, held_frames,
                                               "mgmt"], FUZZ_HOLD_PROBE_RESP=1)
    progress = [m for m in messages if m["msg"] == "progress"]

    check.ok(all(intact(f) for f in frames),
             "every held frame is transmitted exactly as built")
    check.ok(len(progress) == held_frames,
             "a held target announces itself on every frame",
             f"{len(progress)} of {held_frames}")
    check.ok(not any(m["msg"] == "fuzz" for m in messages),
             "a held target emits no 'fuzz' message",
             str({m["msg"] for m in messages}))
    check.ok(all(p["state"] == "held" for p in progress),
             "its state is 'held', so it cannot be mistaken for a missing one",
             str({p["state"] for p in progress}))
    check.ok({p["case_id"] for p in progress} == {-9},
             "a held target consumes no cases",
             str(sorted({p["case_id"] for p in progress})))
    check.ok(all(p["case_max"] == (200 - 24) * CASES_PER_OFFSET
                 for p in progress), "case_max is still reported while held")
    check.ok(not unparsed, "every [fuzz] line is JSON with a msg",
             str(unparsed[:2]))

    messages, _, _ = run(harness, ["probe_resp", 200, 12, "mgmt"],
                         FUZZ_HOLD_PROBE_RESP=0)
    check.ok(any(m["msg"] == "fuzz" for m in messages),
             "FUZZ_HOLD_...=0 is not a hold")

    messages, frames, _ = run(harness, ["probe_resp", 200, 12, "mgmt"])
    check.ok(any(m["msg"] == "fuzz" for m in messages),
             "with no FUZZ_HOLD set, the target sweeps as before")
    check.ok(sum(1 for f in frames if not intact(f)) == 12 - WARMUP,
             f"{12 - WARMUP} of 12 frames mutated past the warm-up",
             str(sum(1 for f in frames if not intact(f))))

    messages, _, _ = run(harness, ["sae-send-commit", 200, 12, "mgmt"],
                         FUZZ_HOLD_PROBE_RESP=1)
    check.ok(any(m["msg"] == "fuzz" for m in messages),
             "a hold is per target: holding one leaves another sweeping")

    messages, frames, _ = run(harness, ["eapol", 200, 5, "eapol"],
                              FUZZ_HOLD_EAPOL=1, FUZZ_START_EAPOL=500)
    progress = [m for m in messages if m["msg"] == "progress"]
    check.ok({p["case_id"] for p in progress} == {500},
             "a held target parks at its resume point, not at the warm-up",
             str({p["case_id"] for p in progress}))
    check.ok(all(intact(f) for f in frames),
             "and is still unmutated there")
    check.ok(any(m["msg"] == "resume" for m in messages),
             "and still reports the resume")

    agree = 0
    for target in TARGETS:
        name = "FUZZ_HOLD_" + "".join(
            c.upper() if c.isascii() and c.isalnum() else "_" for c in target)
        messages, frames, _ = run(harness, [target, 64, 12, "mgmt"],
                                  **{name: 1})
        # Per the output contract, assert only over the messages this check is
        # about; an unrecognised 'msg' is ignorable by construction.
        progress = [m for m in messages if m["msg"] == "progress"]
        if (progress and all(p["state"] == "held" for p in progress)
                and not any(m["msg"] == "fuzz" for m in messages)
                and all(intact(f) for f in frames)):
            agree += 1
    check.ok(agree == len(TARGETS),
             f"all {len(TARGETS)} target names fold as the documented rule says",
             f"{agree} of {len(TARGETS)}")


def check_abandoned(abandon, harness, check):
    """An abandoned frame names the case it lost, in order."""
    print("abandoned frames")
    messages, _, unparsed = run(abandon, [], FUZZ_START_EAPOL=100)
    # 'inventory' is emitted once, ahead of everything; check_inventory() owns
    # that ordering. What this check is about is the per-case sequence.
    sequence = [(m["msg"], m.get("case_id")) for m in messages
                if m["msg"] != "inventory"]
    expected = [("resume", 100), ("progress", 100), ("abandoned", 100),
                ("progress", 101), ("abandoned", 101), ("progress", 102),
                ("fuzz", None)]
    check.ok(sequence == expected,
             "two abandonments then a delivery, each naming its own case",
             str(sequence))
    check.ok(all(m.get("target") == "eapol" for m in messages
                 if m["msg"] == "abandoned"),
             "the abandoned message names the target it belongs to")
    check.ok(not unparsed, "every [fuzz] line is JSON with a msg",
             str(unparsed[:2]))

    messages, _, _ = run(harness, ["eapol", 64, 4, "eapol", "defer"],
                         FUZZ_START_EAPOL=100)
    check.ok(not any(m["msg"] == "abandoned" for m in messages),
             "a frame that is flushed is never reported abandoned")


def check_inventory(root, harness, check):
    """The target table is announced once, before anything else, in full.

    The dict in fuzz.c fills lazily, so a target the configuration never causes
    hostapd to build is absent from the output and is indistinguishable from a
    target that does not exist. The inventory message is what separates them,
    which only works if it arrives before the first case and lists every label
    the tree can emit.
    """
    print("inventory")
    messages, _, _ = run(harness, ["probe_resp", 64, 12, "mgmt"])
    inventory = [m for m in messages if m["msg"] == "inventory"]

    check.ok(len(inventory) == 1,
             "the inventory is announced exactly once",
             f"{len(inventory)} times")
    if not inventory:
        return

    check.ok(messages[0]["msg"] == "inventory",
             "it arrives before any other message",
             messages[0]["msg"])

    targets = inventory[0].get("targets")
    check.ok(isinstance(targets, list) and all(isinstance(t, str)
                                               for t in targets),
             "'targets' is a list of strings",
             repr(targets)[:120])
    if not isinstance(targets, list):
        return

    # The table is only useful if it is the whole truth, so compare it against
    # the call sites rather than against a copy of itself.
    sys.path.insert(0, os.path.join(root, "fuzzing", "ledger"))
    try:
        import targets as target_extract
    except ImportError:
        check.ok(False, "fuzzing/ledger/targets.py is importable")
        return

    emitted = set(target_extract.extract(root))

    # 'targets' is what THIS binary contains, not what the tree has: each
    # entry in the generated table is wrapped in its call site's build
    # condition, so a harness built without CONFIG_SAE announces no SAE
    # target. The whole-tree claim moved to 'roster', and both halves are
    # still asserted -- nothing announced that no call site emits, and
    # nothing emitted that the roster forgets.
    check.ok(set(targets) <= emitted,
             f"every announced label is one the tree emits ({len(targets)})",
             f"announced-not-emitted={sorted(set(targets) - emitted)}")
    check.ok(len(targets) == len(set(targets)),
             "with no duplicates")

    roster = inventory[0].get("roster")
    check.ok(isinstance(roster, list) and roster,
             "the inventory carries a roster of every label in the tree",
             repr(roster)[:120])
    if isinstance(roster, list):
        names = [e.get("name") for e in roster if isinstance(e, dict)]
        check.ok(set(names) == emitted,
                 f"and the roster is exactly the tree's labels ({len(emitted)})",
                 f"roster-not-emitted={sorted(set(names) - emitted)} "
                 f"emitted-not-rostered={sorted(emitted - set(names))}")
        check.ok(set(targets) <= set(names),
                 "and what this binary announces is a subset of it")
        # A label absent from this build must say why, or the ledger cannot
        # tell "excluded here" from "never reached".
        absent = [e for e in roster
                  if isinstance(e, dict) and e.get("name") not in set(targets)]
        check.ok(all(e.get("guard") for e in absent),
                 "and every label this build lacks carries its build condition",
                 f"no guard: {sorted(e.get('name') for e in absent if not e.get('guard'))}")

    daemon = inventory[0].get("daemon")
    check.ok(isinstance(daemon, str) and daemon,
             "the inventory names the daemon that announced it",
             repr(daemon))


def check_disable(harness, check):
    """FUZZ_DISABLE=1 must leave nothing behind at all."""
    print("FUZZ_DISABLE")
    messages, frames, unparsed = run(harness, ["probe_resp", 200, 50, "mgmt"],
                                     FUZZ_DISABLE=1)
    check.ok(not messages and not unparsed,
             "FUZZ_DISABLE=1 emits no [fuzz] lines at all",
             f"{len(messages) + len(unparsed)} lines")
    check.ok(all(intact(f) for f in frames),
             "and leaves every frame untouched")

    messages, frames, _ = run(harness, ["probe_resp", 200, 50, "mgmt"],
                              FUZZ_DISABLE="notanumber")
    bad_env = [m for m in messages if m["msg"] == "bad_env"]
    check.ok(len(bad_env) == 1 and bad_env[0].get("name") == "FUZZ_DISABLE",
             "a malformed value is reported as bad_env and then ignored",
             str(bad_env))
    check.ok(any(m["msg"] == "fuzz" for m in messages),
             "a malformed FUZZ_DISABLE does not silently disable fuzzing")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", default=".",
                        help="path to the checkout (default: the current directory)")
    arguments = parser.parse_args()

    root = os.path.abspath(arguments.root)
    if not os.path.exists(os.path.join(root, "src", "common", "fuzz.c")):
        print(f"{root} does not look like the checkout: no src/common/fuzz.c")
        return 2

    workdir = tempfile.mkdtemp(prefix="fuzz-verify-")
    try:
        harness = build(root, workdir, "harness", HARNESS)
        if harness is None:
            return 2
        abandon = build(root, workdir, "abandon", ABANDON)
        if abandon is None:
            return 2

        check = Checker()
        check_sweep(harness, check)
        check_hold(harness, check)
        check_abandoned(abandon, harness, check)
        check_inventory(root, harness, check)
        check_disable(harness, check)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    total = check.passes + len(check.failures)
    print()
    print(f"{check.passes} of {total} checks pass")
    if check.failures:
        for failure in check.failures:
            print(f"  FAILED: {failure}")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
