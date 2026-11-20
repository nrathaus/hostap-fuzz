#!/usr/bin/env python3
"""Acceptance check for the `[fuzz] ` output contract.

Compiles a small harness against the checkout's own `fuzz.o` and drives the
mutation hook directly, so this needs no radio, no interface and no root. It
exits non-zero until the change described in README.md lands.

    python3 fuzz_output_contract.py /path/to/checkout

The checkout must have been built with CONFIG_FUZZ=y first, since the harness
links the object the build produces:

    cd hostapd && cp defconfig-fuzz .config && make
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile

# Two deferred mutations with no flush between them. That is what an error path
# between mutation and transmission does, and the second call is where the
# first frame's abandonment is noticed.
HARNESS = """
#include "utils/includes.h"
#include "utils/common.h"
#include "common/fuzz.h"

int main(void)
{
\tu8 frame[64];

\tos_memset(frame, 0x41, sizeof(frame));

\tapply_mutation_defer_log("eapol", FUZZ_TYPE_IEEE802_1X_HDR,
\t\t\t\t frame, sizeof(frame));
\tapply_mutation_defer_log("eapol", FUZZ_TYPE_IEEE802_1X_HDR,
\t\t\t\t frame, sizeof(frame));
\treturn 0;
}
"""

# Objects the harness needs beside fuzz.o. json/base64 are what fuzz.c reports
# through, which is why CONFIG_FUZZ declares NEED_JSON and NEED_BASE64.
OBJECTS = [
    "src/common/fuzz.o",
    "src/utils/json.o",
    "src/utils/wpabuf.o",
    "src/utils/common.o",
    "src/utils/os_unix.o",
    "src/utils/base64.o",
    "src/utils/wpa_debug.o",
]

PREFIX = "[fuzz] "


def build(root, workdir):
    """Compile the harness against the checkout's built objects."""
    objdir = os.path.join(root, "build", "hostapd")
    missing = [o for o in OBJECTS if not os.path.exists(os.path.join(objdir, o))]
    if missing:
        print(f"cannot find {missing[0]} under {objdir}")
        print("Build the checkout with CONFIG_FUZZ=y first:")
        print("    cd hostapd && cp defconfig-fuzz .config && make")
        return None

    source = os.path.join(workdir, "harness.c")
    binary = os.path.join(workdir, "harness")
    with open(source, "w", encoding="utf-8") as handle:
        handle.write(HARNESS)

    command = [
        os.environ.get("CC", "cc"),
        "-o",
        binary,
        source,
        f"-I{os.path.join(root, 'src')}",
        f"-I{os.path.join(root, 'src', 'utils')}",
        "-DCONFIG_FUZZ",
    ] + [os.path.join(objdir, o) for o in OBJECTS]

    result = subprocess.run(command, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        print("the harness did not compile:")
        print(result.stderr.strip()[:2000])
        return None

    return binary


def run(binary):
    """Drive the harness past its warm-up, so a frame is really mutated.

    Below case 0 the hook returns before it can defer anything, so the
    abandoned path is unreachable without resuming - which is also what makes
    the malformed-environment and resume lines appear in one run.
    """
    environment = dict(os.environ)
    environment["FUZZ_START_EAPOL"] = "100"
    environment["FUZZ_DISABLE"] = "notanumber"

    result = subprocess.run(
        [binary], capture_output=True, text=True, check=False, env=environment
    )
    return [
        line[len(PREFIX) :]
        for line in (result.stdout + result.stderr).splitlines()
        if line.startswith(PREFIX)
    ]


def check(payloads):
    """Return (passes, failures) over the four acceptance checks."""
    passes, failures = [], []

    unparsed = []
    parsed = []
    for payload in payloads:
        try:
            obj = json.loads(payload)
        except ValueError:
            unparsed.append(payload)
            continue
        if isinstance(obj, dict) and "msg" in obj:
            parsed.append(obj)
        else:
            unparsed.append(payload)

    if unparsed:
        failures.append(
            f"{len(unparsed)} of {len(payloads)} '{PREFIX}' line(s) are not a "
            f"JSON object with a 'msg': " + "; ".join(repr(u) for u in unparsed)
        )
    else:
        passes.append(
            f"all {len(payloads)} '{PREFIX}' line(s) parse as JSON with a 'msg'"
        )

    abandoned = [o for o in parsed if o.get("msg") == "abandoned"]
    if not abandoned:
        failures.append(
            'the abandoned frame produced no {"msg":"abandoned"} message, '
            "so a consumer cannot correct a case counted through 'progress' "
            "but never transmitted"
        )
    else:
        passes.append("the abandoned frame is reported as msg 'abandoned'")

        note = abandoned[0]
        if "target" not in note or "case_id" not in note:
            failures.append(
                f"the abandoned message is missing target and/or case_id: {note}"
            )
        else:
            # The lost case is the one the preceding progress announced.
            progress = [o for o in parsed if o.get("msg") == "progress"]
            expected = progress[0].get("case_id") if progress else None
            if expected is not None and note["case_id"] != expected:
                failures.append(
                    f"the abandoned case_id is {note['case_id']}, but the case "
                    f"announced before it was {expected}"
                )
            else:
                passes.append(
                    f"it names the target and the lost case_id ({note['case_id']})"
                )

    # Additive, not a rename: an existing consumer reads these two.
    kinds = {o.get("msg") for o in parsed}
    if "progress" in kinds:
        passes.append("'progress' is still emitted under its own name")
    else:
        failures.append(
            "no 'progress' message - the contract was unified by renaming a "
            "message consumers already read, which is a breaking change"
        )

    return passes, failures


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "root",
        nargs="?",
        default=".",
        help="path to the checkout (default: the current directory)",
    )
    args = parser.parse_args()

    root = os.path.abspath(args.root)
    if not os.path.exists(os.path.join(root, "src", "common", "fuzz.c")):
        print(f"{root} does not look like the checkout: no src/common/fuzz.c")
        return 2

    workdir = tempfile.mkdtemp(prefix="fuzz-contract-")
    try:
        binary = build(root, workdir)
        if binary is None:
            return 2
        payloads = run(binary)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    if not payloads:
        print(f"the harness emitted no '{PREFIX}' lines at all - it did not run")
        return 2

    passes, failures = check(payloads)

    for line in passes:
        print(f"  ok    {line}")
    for line in failures:
        print(f"  FAIL  {line}")

    print()
    print(f"{len(passes)} of {len(passes) + len(failures)} checks pass")
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
