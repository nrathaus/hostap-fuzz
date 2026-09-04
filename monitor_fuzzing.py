#!/usr/bin/env python3
"""Run hostapd under the fuzzing hooks and report how it died.

Decodes the [fuzz] JSON lines hostapd emits, shows each mutated frame via
scapy, and on an abnormal exit records the case that was in flight so it can
be replayed. You need to install scapy to get this code to work.
"""

import argparse
import json
import os
import signal
import subprocess
import sys
from datetime import datetime, timezone

try:
    import scapy.layers.eap
    import scapy.layers.dot11
    HAVE_SCAPY = True
except ImportError:
    # Dissection is a convenience; crash detection is the point. Run without
    # scapy and frames are reported as raw hex instead.
    HAVE_SCAPY = False

PREFIX = "[fuzz] "


def env_name(target):
    """Mirror fuzz_start_case() in src/common/fuzz.c so the replay hint is
    actually the variable hostapd will read."""
    name = "FUZZ_START_" + target
    return "".join(c.upper() if c.isascii() and c.isalnum() else "_"
                   for c in name)


def decode(target, data_hex):
    """Render a frame hexdump as a scapy packet, or None if it will not parse.

    A mutated frame is malformed by construction, so dissection failing is a
    normal outcome here, not an error worth stopping for.
    """
    if not HAVE_SCAPY:
        return None
    try:
        raw = bytes.fromhex(data_hex)
    except ValueError:
        return None
    try:
        if target == "eapol":
            return scapy.layers.eap.EAPOL(raw)
        return scapy.layers.dot11.Dot11(raw)
    except Exception:
        return None


def describe_exit(returncode):
    if returncode == 0:
        return "exited normally (status 0)"
    if returncode < 0:
        try:
            name = signal.Signals(-returncode).name
        except ValueError:
            name = "unknown"
        return f"killed by signal {-returncode} ({name})"
    return f"exited with status {returncode}"


def write_repro(repro_dir, last, returncode):
    """Record the in-flight case so the crash can be replayed."""
    if last is None:
        return None

    target = last.get("target", "unknown")
    case_id = last.get("case_id", last.get("idx", "unknown"))
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    os.makedirs(repro_dir, exist_ok=True)
    base = f"{stamp}-{target}-{case_id}"
    path = os.path.join(repro_dir, base + ".json")
    # Two runs crashing on the same case in the same second must not silently
    # overwrite each other's record.
    n = 1
    while os.path.exists(path):
        path = os.path.join(repro_dir, f"{base}-{n}.json")
        n += 1

    with open(path, "w") as f:
        json.dump({
            "exit": describe_exit(returncode),
            "returncode": returncode,
            "replay_env": {env_name(target): case_id},
            "case": last,
        }, f, indent=2)

    return path


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--hostapd", default="./hostapd/hostapd",
                    help="hostapd binary (default: %(default)s)")
    ap.add_argument("--config", default="hostapd/hostapd-wpa3.conf",
                    help="hostapd config file (default: %(default)s)")
    ap.add_argument("--repro-dir", default="fuzz-repro",
                    help="where to record a crashing case "
                         "(default: %(default)s)")
    ap.add_argument("--quiet", action="store_true",
                    help="only show fuzzing activity, not all hostapd output")
    ap.add_argument("extra", nargs="*",
                    help="extra arguments passed through to hostapd")
    args = ap.parse_args()

    for path in (args.hostapd, args.config):
        if not os.path.exists(path):
            print(f"error: {path} does not exist", file=sys.stderr)
            return 2

    if not HAVE_SCAPY:
        print("note: scapy is not installed, frames will be shown as raw hex",
              file=sys.stderr)

    cmd = [args.hostapd, args.config] + args.extra
    print(f"Starting {' '.join(cmd)}")

    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    if process.stdout is None:
        print("error: failed to capture hostapd output", file=sys.stderr)
        process.kill()
        return 2

    # Most recent mutation per target, plus the very last one overall -- that
    # is the case in flight if hostapd dies.
    per_target = {}
    last = None
    progress = {}

    try:
        for line in process.stdout:
            if not args.quiet or line.startswith(PREFIX):
                print(line, end="")

            if not line.startswith(PREFIX):
                continue

            payload = line[len(PREFIX):].strip()
            if not payload.startswith("{"):
                continue  # human-readable [fuzz] note, not a record

            try:
                obj = json.loads(payload)
            except json.JSONDecodeError as e:
                print(f"warning: unparsable [fuzz] line ({e})",
                      file=sys.stderr)
                continue

            msg = obj.get("msg")
            target = obj.get("target")

            if msg == "progress":
                if target:
                    progress[target] = obj
                    if target in per_target:
                        per_target[target]["case_id"] = obj.get("case_id")
            elif msg == "fuzz":
                # Carry the case_id from this target's progress line, which
                # is emitted immediately before the mutation.
                if target in progress:
                    obj["case_id"] = progress[target].get("case_id")
                per_target[target] = obj
                last = obj

                packet = decode(target, obj.get("data", ""))
                if packet is None:
                    why = "raw" if not HAVE_SCAPY else "undissectable"
                    print(f"packet=<{why}> {obj.get('data', '')}")
                else:
                    print(f"{packet=}")
    except KeyboardInterrupt:
        print("\nInterrupted, stopping hostapd")
        process.terminate()
        process.wait()
        return 130

    returncode = process.wait()
    verdict = describe_exit(returncode)

    print()
    print(f"hostapd {verdict}")
    if progress:
        print("Last case per target:")
        for target, obj in sorted(progress.items()):
            print(f"  {target}: case {obj.get('case_id')} "
                  f"of {obj.get('case_max')}")

    if returncode == 0:
        return 0

    path = write_repro(args.repro_dir, last, returncode)
    if last is not None:
        target = last.get("target", "unknown")
        print(f"In flight: target={target} case={last.get('case_id')} "
              f"idx={last.get('idx')} type={last.get('type')}")
        print(f"Replay with: {env_name(target)}={last.get('case_id')} "
              f"{' '.join(sys.argv)}")
    if path:
        print(f"Recorded: {path}")

    return 1


if __name__ == "__main__":
    sys.exit(main())
