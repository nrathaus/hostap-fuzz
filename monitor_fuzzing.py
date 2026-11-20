#!/usr/bin/env python3
"""Run a fuzzing build and report how something died.

Decodes the [fuzz] JSON lines the subject emits, shows each mutated frame via
scapy, and on an abnormal exit records the case that was in flight so it can
be replayed. You need to install scapy to get this code to work.

The subject is whichever binary carries the hooks. With hostapd that is also
the process whose death is interesting, because a mutated frame it sends can
only crash it on the way out. Point the hooks the other way -- a fuzzing
wpa_supplicant against a stock hostapd -- and the two separate: the subject is
the station and the victim is the AP. --victim launches that second process and
watches it, which is the whole detection this harness has and all it wants. A
process that died is not a judgement call.
"""

import argparse
import collections
import json
import os
import shlex
import signal
import subprocess
import sys
import threading
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

# The coverage ledger lives at one place in the tree and is looked for there
# and nowhere else. A search would find a stale copy left somewhere in the
# checkout and report coverage from the wrong parser, which is worse than
# reporting none: the output would look right. One path means a missing ledger
# is a missing ledger, and a moved one is caught by the next run rather than
# silently satisfied by whatever else answers to the name.
#
# Not finding it is still not an error -- the run reports no coverage, which is
# a reporting loss rather than a fuzzing one -- but it says so instead of
# looking elsewhere.
_HERE = os.path.dirname(os.path.abspath(__file__))
LEDGER_DIR = os.path.join(_HERE, "fuzzing", "ledger")
Ledger = None
if os.path.isfile(os.path.join(LEDGER_DIR, "ledger.py")):
    sys.path.insert(0, LEDGER_DIR)
    try:
        from ledger import Ledger
    except ImportError as _exc:
        print(f"warning: {LEDGER_DIR}/ledger.py is present but did not import "
              f"({_exc}); running without coverage reporting",
              file=sys.stderr)
else:
    print(f"warning: no coverage ledger at {LEDGER_DIR}/ledger.py; "
          f"running without coverage reporting", file=sys.stderr)


def env_name(target, prefix="FUZZ_START_"):
    """Mirror fuzz_env_name() in src/common/fuzz.c so the replay hint is
    actually the variable hostapd will read."""
    return "".join(c.upper() if c.isascii() and c.isalnum() else "_"
                   for c in prefix + target)


def decode(frame, data_hex):
    """Render a frame hexdump as a scapy packet, or None if it will not parse.

    'frame' is the kind the engine reported -- not the target's name. A target
    is a label someone chose for a call site; guessing the layout from it is
    wrong the first time a site is named something sensible, and silently so,
    because a mutated frame failing to dissect is a normal outcome here rather
    than an error worth stopping for.
    """
    if not HAVE_SCAPY:
        return None
    try:
        raw = bytes.fromhex(data_hex)
    except ValueError:
        return None
    try:
        if frame == "eapol":
            return scapy.layers.eap.EAPOL(raw)
        if frame == "mgmt":
            return scapy.layers.dot11.Dot11(raw)
        # "body": a frame body with no header of its own, because the driver
        # builds one. There is nothing for scapy to start from.
        return None
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


def write_repro(repro_dir, last, returncode, who="subject"):
    """Record the in-flight case so the crash can be replayed.

    'who' is the process that died. It is recorded rather than inferred,
    because in the inverted direction the process that sent the frame and the
    process that died are not the same one and a record that does not say
    which is a record of nothing.
    """
    if last is None:
        return None

    target = last.get("target", "unknown")
    case_id = last.get("case_id", last.get("idx", "unknown"))
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    os.makedirs(repro_dir, exist_ok=True)
    base = f"{stamp}-{who}-{target}-{case_id}"
    path = os.path.join(repro_dir, base + ".json")
    # Two runs crashing on the same case in the same second must not silently
    # overwrite each other's record.
    n = 1
    while os.path.exists(path):
        path = os.path.join(repro_dir, f"{base}-{n}.json")
        n += 1

    #  The sweep orders renumber every case, so a case_id replayed under the
    #  wrong one reproduces a different frame and looks non-reproducible.
    replay_env = {env_name(target): case_id}
    if last.get("order") == "depth":
        replay_env["FUZZ_SWEEP_DEPTH_FIRST"] = 1

    with open(path, "w") as f:
        json.dump({
            "who": who,
            "exit": describe_exit(returncode),
            "returncode": returncode,
            # The case space this case_id indexes. Tier, stride offset and
            # the set of domains all renumber every case, so a case_id is
            # meaningless without it -- it would replay without complaint and
            # reproduce a different frame.
            "opset": last.get("opset"),
            "replay_env": replay_env,
            "case": last,
        }, f, indent=2)

    return path


def report_ledger(ledger, args, returncode, verdict):
    """Print the coverage ledger, and write it as JSON if asked.

    Called on every way out, including an interrupted run: a run that was
    stopped still sent frames, and a campaign that throws those away
    under-reports its own coverage.
    """
    if not ledger:
        return
    print()
    ledger.report(_HERE)
    if not args.ledger_json:
        return
    summary = ledger.summary()
    summary["returncode"] = returncode
    summary["verdict"] = verdict
    try:
        with open(args.ledger_json, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=1)
    except OSError as exc:
        print(f"warning: could not write {args.ledger_json}: {exc}",
              file=sys.stderr)


class Victim:
    """A second process, launched alongside the subject and watched.

    It carries no hooks and sends nothing: it is only here to die. Its exit is
    the one signal this harness trusts, which is why it is watched on a thread
    rather than polled -- a subject that stalls would otherwise keep a dead
    victim unnoticed for as long as it stayed quiet.
    """

    def __init__(self, cmd, log_path):
        self.cmd = cmd
        self.log_path = log_path
        self.returncode = None
        self.log = open(log_path, "w")
        self.proc = subprocess.Popen(cmd, stdout=self.log,
                                     stderr=subprocess.STDOUT, text=True)
        self.died = threading.Event()
        self.thread = threading.Thread(target=self._wait, daemon=True)

    def watch(self, on_death):
        self._on_death = on_death
        self.thread.start()

    def _wait(self):
        self.returncode = self.proc.wait()
        self.died.set()
        self._on_death()

    def stop(self):
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
        self.returncode = self.proc.returncode
        self.log.close()

    def tail(self, n=40):
        try:
            with open(self.log_path, encoding="utf-8",
                      errors="replace") as f:
                return f.read().splitlines()[-n:]
        except OSError:
            return []


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--hostapd", default="./hostapd/hostapd",
                    help="the binary carrying the fuzzing hooks -- hostapd, "
                         "or a fuzzing wpa_supplicant for the inverted "
                         "direction (default: %(default)s)")
    ap.add_argument("--config", default="hostapd/hostapd-wpa3.conf",
                    help="config file for that binary (default: %(default)s)")
    ap.add_argument("--subject", metavar="CMD",
                    help="the whole subject command line, in place of "
                         "--hostapd/--config. wpa_supplicant does not take "
                         "its config as a bare argument, so a station run "
                         "needs this rather than a config path.")
    ap.add_argument("--replay", metavar="RECORD",
                    help="a repro record written by an earlier run. Its "
                         "replay_env is applied, and the run stops if the "
                         "binary reports a different case space from the one "
                         "the record was written under -- a case_id indexes "
                         "an enumeration, and under a different one it "
                         "reproduces a different frame without complaining.")
    ap.add_argument("--victim", metavar="CMD", action="append", default=[],
                    help="a process to launch and watch, for the topologies "
                         "where the thing that might crash is not the thing "
                         "doing the sending. Its abnormal exit is reported "
                         "exactly as the subject's is. Repeatable: a run with "
                         "several peers has several processes that might die, "
                         "and watching only the first would miss the others.")
    ap.add_argument("--victim-log", default="fuzz-victim.log",
                    help="where a victim's own output goes. With more than "
                         "one victim the index is appended, so they do not "
                         "overwrite each other (default: %(default)s)")
    ap.add_argument("--repro-dir", default="fuzz-repro",
                    help="where to record a crashing case "
                         "(default: %(default)s)")
    ap.add_argument("--quiet", action="store_true",
                    help="only show fuzzing activity, not all of the subject's output")
    ap.add_argument("--no-ledger", action="store_true",
                    help="skip the end-of-run coverage ledger")
    ap.add_argument("--ledger-json", metavar="PATH",
                    help="also write the ledger as JSON, for a campaign that "
                         "unions many runs. Written even when the subject exits "
                         "badly, because a run that died still sent frames "
                         "and a campaign that drops them under-reports.")
    ap.add_argument("extra", nargs="*",
                    help="extra arguments appended to the subject command")
    args = ap.parse_args()

    if args.subject:
        cmd = shlex.split(args.subject) + args.extra
    else:
        cmd = [args.hostapd, args.config] + args.extra
        for path in (args.hostapd, args.config):
            if not os.path.exists(path):
                print(f"error: {path} does not exist", file=sys.stderr)
                return 2
    if not os.path.exists(cmd[0]):
        print(f"error: {cmd[0]} does not exist", file=sys.stderr)
        return 2

    if not HAVE_SCAPY:
        print("note: scapy is not installed, frames will be shown as raw hex",
              file=sys.stderr)

    want_opset, child_env = None, None
    if args.replay:
        try:
            with open(args.replay, encoding="utf-8") as f:
                record = json.load(f)
        except (OSError, ValueError) as exc:
            print(f"error: cannot read {args.replay}: {exc}", file=sys.stderr)
            return 2
        want_opset = record.get("opset")
        child_env = dict(os.environ)
        env = record.get("replay_env") or {}
        for k, v in env.items():
            child_env[str(k)] = str(v)
        print("Replaying %s: %s"
              % (args.replay,
                 " ".join("%s=%s" % kv for kv in sorted(env.items()))))
        if want_opset is None:
            print("note: this record has no opset, so whether it replays "
                  "under the current case space cannot be checked",
                  file=sys.stderr)

    # A timed run is stopped with SIGTERM, which would otherwise kill this
    # process outright and take the run's ledger with it. Routing it through
    # the same path as Ctrl-C keeps what the run actually covered.
    def on_sigterm(signum, frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, on_sigterm)

    victims = []
    for i, spec in enumerate(args.victim):
        vcmd = shlex.split(spec)
        if not os.path.exists(vcmd[0]):
            print(f"error: {vcmd[0]} does not exist", file=sys.stderr)
            for v in victims:
                v.stop()
            return 2
        log = args.victim_log
        if len(args.victim) > 1:
            base, ext = os.path.splitext(log)
            log = f"{base}{i}{ext}"
        print(f"Victim {i}: {' '.join(vcmd)}  (output -> {log})")
        try:
            victims.append(Victim(vcmd, log))
        except OSError as exc:
            print(f"error: could not start a victim: {exc}", file=sys.stderr)
            for v in victims:
                v.stop()
            return 2

    print(f"Starting {' '.join(cmd)}")

    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        env=child_env,
    )
    if process.stdout is None:
        print("error: failed to capture the subject's output", file=sys.stderr)
        process.kill()
        for v in victims:
            v.stop()
        return 2

    for v in victims:
        # Ending the subject's stdout is what gets the main loop out; without
        # it a victim that dies early would be noticed only when the subject
        # happened to print again.
        v.watch(lambda: process.terminate())

    # Most recent mutation per target, plus the very last one overall -- that
    # is the case in flight if hostapd dies.
    per_target = {}
    last = None
    progress = {}
    # Cases hostapd announced but never put on the air, per target.
    abandoned = {}
    ledger = Ledger() if (Ledger and not args.no_ledger) else None

    # --quiet shows only fuzzing activity, which is right while a run is
    # working and wrong when it never starts: a config hostapd rejects then
    # produces an empty ledger and no reason anywhere. Keep the last lines so
    # a subject that dies without ever fuzzing can be explained rather than
    # reported as zero coverage.
    tail = collections.deque(maxlen=20)
    saw_fuzz_line = False

    try:
        for line in process.stdout:
            if not args.quiet or line.startswith(PREFIX):
                print(line, end="")
            tail.append(line.rstrip("\n"))

            if not line.startswith(PREFIX):
                continue
            saw_fuzz_line = True

            # Every [fuzz] line is a JSON object with a "msg" key: the prefix
            # means "this line is for the consumer", so one that does not parse
            # is a real problem rather than a note meant for a human.
            payload = line[len(PREFIX):].strip()
            try:
                obj = json.loads(payload)
            except json.JSONDecodeError as e:
                print(f"warning: unparsable [fuzz] line ({e})",
                      file=sys.stderr)
                continue

            if not isinstance(obj, dict) or "msg" not in obj:
                print(f"warning: [fuzz] line carries no msg: {payload}",
                      file=sys.stderr)
                continue

            if want_opset and obj.get("opset") and \
                    obj["opset"] != want_opset:
                print(f"error: this build's case space is {obj['opset']}, "
                      f"but the record was written under {want_opset}.",
                      file=sys.stderr)
                print("       The same case_id indexes a different frame "
                      "under each, so replaying it here would reproduce "
                      "something else and look like a flaky crash.",
                      file=sys.stderr)
                process.terminate()
                process.wait()
                for v in victims:
                    v.stop()
                return 2

            if ledger:
                ledger.feed(obj)

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

                frame = obj.get("frame")
                packet = decode(frame, obj.get("data", ""))
                if packet is None:
                    if not HAVE_SCAPY:
                        why = "raw"
                    elif frame == "body":
                        why = "body, no header"
                    else:
                        why = "undissectable"
                    print(f"packet=<{why}> {obj.get('data', '')}")
                else:
                    print(f"{packet=}")
            elif msg == "abandoned":
                # The case was announced through 'progress' but its frame was
                # dropped on an error path before transmission, so it was never
                # delivered. Count it rather than claiming the coverage.
                abandoned[target] = abandoned.get(target, 0) + 1
            elif msg == "bad_env":
                print(f"warning: hostapd ignored {obj.get('name')}="
                      f"{obj.get('value')!r}, it is not an integer",
                      file=sys.stderr)
            # Any other msg belongs to someone else. The contract is that an
            # unknown one is safe to ignore, so a new message breaks nobody.
    except KeyboardInterrupt:
        print("\nInterrupted, stopping")
        process.terminate()
        rc = process.wait()
        for v in victims:
            v.stop()
        report_ledger(ledger, args, rc, "interrupted")
        return 130

    returncode = process.wait()
    verdict = describe_exit(returncode)

    #  A subject that never emitted a single [fuzz] line did not fuzz, and the
    #  ledger about to be printed will say zero of everything. Zero coverage
    #  and "your config was rejected" look identical in that report, so say
    #  which one it was. The lines are kept even under --quiet, because that
    #  is exactly when they were not printed as they went by.
    if not saw_fuzz_line:
        print(file=sys.stderr)
        print("warning: the subject produced no [fuzz] lines at all, so this "
              "run fuzzed nothing.", file=sys.stderr)
        print("  Either it is not a CONFIG_FUZZ build (check -v), or it never "
              "got far enough", file=sys.stderr)
        print("  to transmit. Its last output follows.", file=sys.stderr)
        print(file=sys.stderr)
        for line in tail:
            print("  | %s" % line, file=sys.stderr)
        print(file=sys.stderr)

    dead = []
    for v in victims:
        v.stop()
        if v.returncode not in (0, -signal.SIGTERM):
            dead.append(v)

    report_ledger(ledger, args, returncode, verdict)

    print()
    print(f"subject {verdict}")
    for i, v in enumerate(victims):
        print(f"victim {i} {describe_exit(v.returncode)}")
    if progress:
        print("Last case per target:")
        for target, obj in sorted(progress.items()):
            # 'mutating' is the ordinary state and says nothing; the other
            # three explain a target that is not advancing.
            state = obj.get("state")
            note = f" [{state}]" if state and state != "mutating" else ""
            lost = abandoned.get(target)
            if lost:
                note += f" ({lost} announced but never sent)"
            print(f"  {target}: case {obj.get('case_id')} "
                  f"of {obj.get('case_max')}{note}")

    # A subject terminated because its victim died exited abnormally itself,
    # and reporting that as the finding would name the wrong process. The
    # victim is checked first for that reason.
    if dead:
        # More than one can die at once -- a frame delivered to several peers,
        # or one peer's death taking a shared resource with it. All of them
        # are named; the record is written against the first, because there
        # is one case in flight and it is the same case for all of them.
        for i, v in enumerate(dead):
            print(f"  victim {i} died:")
            for line in v.tail():
                print(f"    | {line}")
        path = write_repro(args.repro_dir, last, dead[0].returncode,
                           who="victim" if len(dead) == 1
                           else f"{len(dead)} victims")
    elif returncode != 0:
        path = write_repro(args.repro_dir, last, returncode, who="subject")
    else:
        return 0

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
