#!/usr/bin/env python3
"""Put the control and held runs side by side, as a table to paste into
FUZZING.md.

    python3 compare.py logs/

The point of the pair is that neither log means much alone: the control shows
what the starvation looks like on this station, and the held run shows what
changes when the earlier stage is answered correctly. Reporting them together
is what makes the second one evidence rather than an assertion.
"""

import json
import os
import re
import sys

PREFIX = "[fuzz] "
HANDSHAKE = re.compile(r"EAPOL-4WAY-HS-COMPLETED")
ASSOC = re.compile(r"AP-STA-CONNECTED")
DISCONNECT = re.compile(r"AP-STA-DISCONNECTED")


def read(path):
    """Per-target reach and the station-side counts, from one phase log."""
    targets = {}
    counts = {"handshakes": 0, "associations": 0, "disconnections": 0}
    seconds = None

    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            lines = handle.read().splitlines()
    except OSError:
        return None

    for line in lines:
        if HANDSHAKE.search(line):
            counts["handshakes"] += 1
        if ASSOC.search(line):
            counts["associations"] += 1
        if DISCONNECT.search(line):
            counts["disconnections"] += 1
        if not line.startswith(PREFIX):
            continue
        try:
            message = json.loads(line[len(PREFIX):])
        except ValueError:
            continue
        if message.get("msg") != "progress":
            continue
        target = message.get("target")
        entry = targets.setdefault(target, {"high": None, "max": None,
                                            "states": set(), "frames": 0})
        case_id = message.get("case_id")
        if isinstance(case_id, int):
            entry["high"] = (case_id if entry["high"] is None
                             else max(entry["high"], case_id))
        entry["max"] = message.get("case_max", entry["max"])
        entry["states"].add(message.get("state"))
        entry["frames"] += 1

    return {"targets": targets, "counts": counts, "seconds": seconds}


def cell(entry):
    """One target's reach, as it should read in the table."""
    if entry is None:
        return "never announced"
    high, top = entry["high"], entry["max"]
    if "held" in entry["states"]:
        return f"held ({entry['frames']} frames)"
    if isinstance(high, int) and high < 0:
        return "warm-up only"
    if isinstance(high, int) and isinstance(top, int) and top:
        return f"{high:,} of {top:,} ({100.0 * high / top:.1f}%)"
    return str(high)


def main():
    directory = sys.argv[1] if len(sys.argv) > 1 else "logs"
    control = read(os.path.join(directory, "control.log"))
    held = read(os.path.join(directory, "held.log"))

    if control is None or held is None:
        print(f"need both control.log and held.log under {directory}")
        return 2

    names = sorted(set(control["targets"]) | set(held["targets"]),
                   key=lambda n: (n is None, n))

    print("| target | control (nothing held) | held (FUZZ_HOLD_PROBE_RESP=1) |")
    print("| --- | --- | --- |")
    for name in names:
        print(f"| `{name}` | {cell(control['targets'].get(name))} "
              f"| {cell(held['targets'].get(name))} |")

    print()
    print("| | control | held |")
    print("| --- | --- | --- |")
    for key, label in (("handshakes", "four-way handshakes"),
                       ("associations", "associations"),
                       ("disconnections", "disconnections")):
        print(f"| {label} | {control['counts'][key]} | {held['counts'][key]} |")

    #  The acceptance from fuzzing/phasing/README.md, stated as a
    #  verdict rather than left for the reader to work out.
    print()
    verdicts = []
    probe = held["targets"].get("probe_resp")
    commit = held["targets"].get("sae-send-commit")
    verdicts.append((probe is not None and "held" in probe["states"],
                     "probe_resp announced itself while held"))
    verdicts.append((held["counts"]["handshakes"] > 0,
                     "the station completed the four-way handshake"))
    verdicts.append((commit is not None and isinstance(commit["high"], int)
                     and commit["high"] >= 100,
                     "sae-send-commit advanced past 100 cases"))
    verdicts.append((control["targets"].get("probe_resp") is not None,
                     "the control exercised probe_resp, so the pair is comparable"))
    for good, label in verdicts:
        print(f"  {'PASS' if good else 'FAIL'}  {label}")

    return 0 if all(good for good, _ in verdicts) else 1


if __name__ == "__main__":
    sys.exit(main())
