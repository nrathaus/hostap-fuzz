#!/usr/bin/env python3
"""Create mac80211_hwsim radios in the current network namespace.

The radios belong to whatever namespace creates them and disappear with it, so
a run that is killed leaves nothing behind -- there is no teardown step to
forget. Creating them needs CAP_NET_ADMIN over that namespace and nothing
else, which `unshare -r -n` grants without root: the only privileged step in
the whole topology is the once-per-boot `modprobe mac80211_hwsim`.

The netlink plumbing is hostap's own, in tests/hwsim/. Importing it rather
than reimplementing it means a kernel-side change is picked up with the
checkout.

    python3 radios.py N        create N radios, print their interface names
"""

import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(ROOT, "tests", "hwsim"))

import hwsim                                            # noqa: E402


def interfaces():
    out = subprocess.run(["iw", "dev"], capture_output=True, text=True).stdout
    return [l.split()[1] for l in out.splitlines()
            if l.strip().startswith("Interface ")]


def main():
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 2
    before = set(interfaces())
    ctrl = hwsim.HWSimController()
    for _ in range(n):
        ctrl.create_radio(n_channels=1)

    # The netlink call returns before udev has renamed the interface, so the
    # name is read back rather than assumed. A script that assumed wlan0 would
    # be right until the first time it was not, and would then point hostapd
    # at an interface that is someone else's.
    deadline = time.time() + 10
    while time.time() < deadline:
        names = sorted(set(interfaces()) - before)
        if len(names) >= n:
            print(" ".join(names[:n]))
            return 0
        time.sleep(0.1)

    print("error: only %d of %d radios appeared" %
          (len(set(interfaces()) - before), n), file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
