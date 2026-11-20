#!/usr/bin/env python3
"""Read one phase's log and report what the run actually did.

    python3 summarise.py logs/held.log

Per target: how far the sweep got, and in what state. Plus the station-side
counts that say whether the exchange was progressing at all, and any
'[fuzz] ' line that broke the output contract -- which is the one check no
offline harness can make, because it needs real traffic.
"""

import json
import re
import sys
from collections import Counter

PREFIX = "[fuzz] "

#  The station-side events that say how far the exchange got. Counted from
#  hostapd's own output, so they need no access to the station.
#  One pattern per event, not an alternation: hostapd logs both
#  "associated (aid N)" and "AP-STA-CONNECTED" for a single association, and
#  both "AP-STA-DISCONNECTED" and "deauthenticated due to" for a single
#  disconnect, so an alternation doubles every count.
EVENTS = {
    "associations": r"AP-STA-CONNECTED",
    "four-way handshakes": r"EAPOL-4WAY-HS-COMPLETED",
    "disconnections": r"AP-STA-DISCONNECTED",
}


def main():
    if len(sys.argv) != 2:
        print(__doc__)
        return 2

    try:
        with open(sys.argv[1], encoding="utf-8", errors="replace") as handle:
            lines = handle.read().splitlines()
    except OSError as exception:
        print(f"   cannot read the log: {exception}")
        return 2

    targets = {}
    warnings = []
    abandoned = Counter()
    other = Counter()
    violations = []
    events = Counter()

    for line in lines:
        for name, pattern in EVENTS.items():
            if re.search(pattern, line):
                events[name] += 1

        #  Only at the start of a line: the monitor's own stderr warning
        #  about an unparsable line quotes the prefix, and counting that as a
        #  contract violation would double-report every real one.
        if not line.startswith(PREFIX):
            if line.startswith("warning: "):
                warnings.append(line)
            continue
        payload = line[len(PREFIX):].strip()
        try:
            message = json.loads(payload)
        except ValueError:
            violations.append(payload)
            continue
        if not isinstance(message, dict) or "msg" not in message:
            violations.append(payload)
            continue

        kind = message["msg"]
        target = message.get("target")
        if kind == "progress":
            entry = targets.setdefault(
                target, {"seen": 0, "high": None, "max": None,
                         "states": Counter()})
            entry["seen"] += 1
            case_id = message.get("case_id")
            if isinstance(case_id, int):
                entry["high"] = (case_id if entry["high"] is None
                                 else max(entry["high"], case_id))
            entry["max"] = message.get("case_max", entry["max"])
            entry["states"][message.get("state", "-")] += 1
        elif kind == "abandoned":
            abandoned[target] += 1
        else:
            other[kind] += 1

    print()
    if not targets:
        print("   no target announced itself -- hostapd never transmitted a "
              "frame through a hook.")
    else:
        width = max(len(t or "?") for t in targets)
        print(f"   {'target'.ljust(width)}  {'reached':>9}  {'of':>9}   frames  states")
        for target, entry in sorted(targets.items()):
            high = entry["high"]
            top = entry["max"]
            share = f"{100.0 * high / top:.1f}%" if (
                isinstance(high, int) and isinstance(top, int) and top
                and high > 0) else ""
            states = ",".join(f"{k}:{v}" for k, v in entry["states"].most_common())
            print(f"   {(target or '?').ljust(width)}  {high!s:>9}  {top!s:>9}   "
                  f"{entry['seen']:>6}  {states} {share}")

    mutations = other.pop("fuzz", 0)

    print()
    print(f"   {'mutations logged':22s} {mutations}")
    #  Counted from the parsed messages rather than from hostapd's SAE debug
    #  lines, which the config's log level suppresses.
    sae = sum(entry["seen"] for name, entry in targets.items()
              if name and name.startswith("sae-"))
    print(f"   {'SAE frames sent':22s} {sae}")
    for name in EVENTS:
        print(f"   {name:22s} {events[name]}")

    if abandoned:
        print()
        for target, count in abandoned.most_common():
            print(f"   abandoned: {target} lost {count} announced case(s)")

    if other:
        print()
        print("   other messages: " +
              ", ".join(f"{k}={v}" for k, v in other.most_common()))

    if warnings:
        print()
        print(f"   the monitor raised {len(warnings)} warning(s):")
        for warning in warnings[:3]:
            print(f"      {warning[:100]}")

    print()
    if violations:
        print(f"   !! {len(violations)} '[fuzz] ' line(s) BROKE the contract:")
        for bad in violations[:5]:
            print(f"      {bad[:100]}")
    else:
        fuzz_lines = sum(1 for line in lines if line.startswith(PREFIX))
        print(f"   contract: all {fuzz_lines} '[fuzz] ' lines parsed as JSON "
              "with a msg")

    return 0


if __name__ == "__main__":
    sys.exit(main())
