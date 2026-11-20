#!/usr/bin/env python3
"""
Acceptance for FUZZ_HOLD_<TARGET>: hold a fuzzing target unmutated so the
stages behind it stay reachable. See README.md for the measurement that
motivates it.

    python3 phase_starvation.py                     static, no root, no radio
    sudo python3 phase_starvation.py --live PATH    drives the build under test

The static mode reports whether the build under test knows the variable at all
and exits non-zero until it does. It reads the binary's own strings rather than
running it, so it needs neither root nor an interface.

The live mode needs no radio and no second machine either: it brings up two
mac80211_hwsim interfaces, runs the build on one as a WPA3-SAE AP and
wpa_supplicant on the other as an SAE station, and reports which targets
advanced. That is the only way to show the starvation itself, because it is a
property of the exchange rather than of the binary.

It is deliberately possible to run --live against a build WITHOUT the change:
that is the control, and it is what produces the table in README.md.
"""

import argparse
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time

#  The five targets the build declares. Held in one place because the naming
#  rule - uppercase, '-' as '_' - is the thing a caller has to get right.
TARGETS = [
    "probe_resp",
    "assoc_resp",
    "eapol",
    "sae-send-commit",
    "sae-send-confirm",
]

#  How long the live run drives the exchange for. Every case is delivered as a
#  reply to a station action, so this is measured in station retries rather
#  than in cases: a station reattempts every two to three seconds, and three
#  minutes is enough for the difference between reachable and starved to be
#  unambiguous rather than marginal.
LIVE_SECONDS = 180

#  What "advanced" means for the acceptance check. Low enough that a slow
#  station still passes, high enough that the warm-up range alone cannot.
ADVANCE_THRESHOLD = 100

SSID = "fuzz-phasing-test"
PASSPHRASE = "phasing-test-passphrase"


def env_name(target: str) -> str:
    """The environment variable spelling for a target, per FUZZ_START_<T>."""
    return target.upper().replace("-", "_")


def binary_knows_hold(path: str) -> bool:
    """
    Whether the build under test has any FUZZ_HOLD support compiled in.

    Reads the binary rather than running it: running needs root and an
    interface, and the question here is only whether the symbol exists.
    """
    try:
        with open(path, "rb") as handle:
            blob = handle.read()
    except OSError as exception:
        print(f"cannot read {path}: {exception}")
        sys.exit(2)

    return b"FUZZ_HOLD" in blob


def static_check(path: str) -> int:
    """Report whether the ask has landed. Exits non-zero until it has."""
    print(f"build under test: {path}")

    version = subprocess.run([path, "-v"], capture_output=True, text=True, check=False)
    banner = (version.stdout + version.stderr).strip().splitlines()
    print(f"  version: {banner[0] if banner else '(no output)'}")

    if b"-fuzz" not in (banner[0].encode() if banner else b""):
        print("  the fuzzing hooks are NOT compiled in, so nothing here applies.")
        print("  Build with CONFIG_FUZZ=y.")
        return 2

    if binary_knows_hold(path):
        print("  FUZZ_HOLD: present")
        print()
        print("The ask has landed. Run --live to check it behaves.")
        return 0

    print("  FUZZ_HOLD: ABSENT")
    print()
    print("Without it, an early-stage target starves every later one and there")
    print("is no way to answer it honestly. FUZZ_START_<TARGET> does not")
    print("substitute: it removes the frame rather than sending it correctly,")
    print("and a held target then stops announcing itself. See README.md.")
    print()
    print("Expected, one per target:")
    for target in TARGETS:
        print(f"  FUZZ_HOLD_{env_name(target)}=1")

    return 1


def write_configs(directory: str, ap_iface: str, sta_iface: str):
    """The AP and station configurations, as files hostapd/wpa_supplicant read."""
    ap_config = os.path.join(directory, "hostapd.conf")
    with open(ap_config, "w", encoding="utf-8") as handle:
        handle.write(
            f"interface={ap_iface}\n"
            "driver=nl80211\n"
            f"ssid={SSID}\n"
            "hw_mode=g\n"
            "channel=1\n"
            "wpa=2\n"
            "wpa_key_mgmt=SAE\n"
            "rsn_pairwise=CCMP\n"
            f"sae_password={PASSPHRASE}\n"
            #  No trailing comments on these: hostapd only treats '#' as a
            #  comment at the start of a line, so a trailing one becomes part
            #  of the value and survives only because atoi() stops at the
            #  first non-digit.
            "ieee80211w=2\n"
            "sae_require_mfp=1\n"
            "sae_pwe=2\n"
        )

    sta_config = os.path.join(directory, "wpa_supplicant.conf")
    with open(sta_config, "w", encoding="utf-8") as handle:
        handle.write(
            "ctrl_interface=/var/run/wpa_supplicant_phasing\n"
            "network={\n"
            f'    ssid="{SSID}"\n'
            "    key_mgmt=SAE\n"
            f'    sae_password="{PASSPHRASE}"\n'
            "    ieee80211w=2\n"
            "}\n"
        )

    return ap_config, sta_config


def hwsim_interfaces():
    """
    Two mac80211_hwsim interfaces, or None with the reason.

    Loaded with radios=2 rather than reusing whatever is already there, so the
    test cannot silently run against a real adapter.
    """
    if shutil.which("iw") is None:
        return None, "'iw' is not installed"

    subprocess.run(
        ["modprobe", "mac80211_hwsim", "radios=2"],
        capture_output=True,
        check=False,
    )

    listing = subprocess.run(
        ["iw", "dev"], capture_output=True, text=True, check=False
    ).stdout
    names = re.findall(r"Interface (wlan\d+)", listing)

    simulated = []
    for name in names:
        driver = os.path.realpath(f"/sys/class/net/{name}/device/driver")
        if driver.endswith("mac80211_hwsim"):
            simulated.append(name)

    if len(simulated) < 2:
        return None, "fewer than two mac80211_hwsim interfaces are present"

    return simulated[:2], None


def read_progress(text: str) -> dict:
    """The highest case reached per target, from the build's own output."""
    highest = {}
    for line in text.splitlines():
        if not line.startswith("[fuzz] "):
            continue
        match = re.search(r"\{.*\}", line)
        if match is None:
            #  Prose under the same prefix. README.md asks for this to be
            #  wrapped; until it is, skipping it is all a consumer can do.
            continue
        try:
            message = json.loads(match.group())
        except json.JSONDecodeError:
            continue
        if message.get("msg") != "progress":
            continue
        target = message.get("target")
        case_id = int(message.get("case_id", 0))
        highest[target] = max(highest.get(target, case_id), case_id)

    return highest


def live_check(path: str, hold: bool) -> int:
    """Drive a real exchange and report which targets advanced."""
    if os.geteuid() != 0:
        print("--live needs root: it loads a module and configures interfaces.")
        return 2

    if shutil.which("wpa_supplicant") is None:
        print("wpa_supplicant is not installed, so there is no station to pair.")
        return 2

    interfaces, reason = hwsim_interfaces()
    if interfaces is None:
        print(f"cannot get simulated radios: {reason}")
        return 2

    ap_iface, sta_iface = interfaces
    print(f"AP on {ap_iface}, station on {sta_iface}, {LIVE_SECONDS}s")

    environment = dict(os.environ)
    if hold:
        environment[f"FUZZ_HOLD_{env_name('probe_resp')}"] = "1"
        print("  holding probe_resp unmutated")
    else:
        print("  holding nothing - this is the control")

    with tempfile.TemporaryDirectory() as directory:
        ap_config, sta_config = write_configs(directory, ap_iface, sta_iface)

        ap = subprocess.Popen(
            [path, ap_config],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            env=environment,
        )
        time.sleep(2)
        sta = subprocess.Popen(
            ["wpa_supplicant", "-i", sta_iface, "-c", sta_config],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        try:
            time.sleep(LIVE_SECONDS)
        finally:
            for process in (sta, ap):
                if process.poll() is None:
                    process.send_signal(signal.SIGTERM)
            try:
                output = ap.communicate(timeout=10)[0] or ""
            except subprocess.TimeoutExpired:
                ap.kill()
                output = ap.communicate()[0] or ""
            sta.wait(timeout=10)

    highest = read_progress(output)
    handshakes = output.count("EAPOL-4WAY-HS-COMPLETED")

    print()
    print(f"  four-way handshakes completed: {handshakes}")
    for target in TARGETS:
        reached = highest.get(target)
        shown = "never announced" if reached is None else f"{reached:,}"
        print(f"  {target:20s} {shown}")

    if not hold:
        print()
        print("Control run. The table above is the starvation itself: the")
        print("targets behind probe_resp cannot advance while it is mutated.")
        return 0

    failures = []
    if handshakes == 0:
        failures.append("the station never completed a four-way handshake")
    if highest.get("probe_resp") is None:
        failures.append("probe_resp did not announce itself while held")
    commit = highest.get("sae-send-commit")
    if commit is None or commit < ADVANCE_THRESHOLD:
        failures.append(
            f"sae-send-commit reached {commit}, wanted {ADVANCE_THRESHOLD}+"
        )

    print()
    if failures:
        for failure in failures:
            print(f"  FAIL: {failure}")
        return 1

    print("  PASS: holding probe_resp made the stages behind it reachable.")
    return 0


def main() -> int:
    """main"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", nargs="?", help="the hostapd build under test")
    parser.add_argument("--live", action="store_true", help="drive a real exchange")
    parser.add_argument(
        "--control",
        action="store_true",
        help="with --live, hold nothing: reproduces the starvation",
    )
    arguments = parser.parse_args()

    path = arguments.binary or shutil.which("hostapd")
    if path is None:
        print("name the build to test, or put one on PATH")
        return 2

    if arguments.live:
        return live_check(path, hold=not arguments.control)

    return static_check(path)


if __name__ == "__main__":
    sys.exit(main())
