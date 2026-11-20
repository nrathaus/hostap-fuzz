#!/usr/bin/env python3
"""Find the transmit branches that happen once per peer and then never again.

The sweep delivers one case per occurrence of a stage. A stage the state
machine produces exactly once per peer therefore gets exactly one case per
session, and the number of occurrences -- which is itself a domain, 0..N -- is
pinned at the constant 1. Nothing in the engine can unpin it, because the engine
mutates frames and this is about how many frames there are.

So the sites have to be found. Choosing a few by hand would make the primitive a
fix for the sites someone happened to think of; what is wanted is the shape, so
the shape is what gets searched for:

    a branch whose condition READS a per-peer field, whose body (or the
    function around it) TRANSMITS, and which WRITES that same field

That last part is the latch. A field tested before sending and set after it is
the code saying "only once per peer" in the only way C has of saying it. The
search is syntactic and makes no judgement about what the field means.

There is a second shape, and missing it would have cost the whole EAPOL
exchange. A state machine written with SM_STATE() sends from inside a state and
then moves on; the state is entered once per session, so the stage occurs once,
and there is no latch field to find because the latch IS the state variable.
Those are enumerated separately -- every SM_STATE() whose body transmits -- and
they need no evidence beyond that, since a transmitting state in a state machine
is one-shot by construction.

    python3 oneshot.py [CHECKOUT]            the sites, strongest evidence first
    python3 oneshot.py [CHECKOUT] --json
    python3 oneshot.py [CHECKOUT] --file src/ap/ieee802_11.c
"""

import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "axes"))
import cparse
import reach

# Sending a frame, as this tree spells it. Distinct from reach.py's "writes
# octets into a frame": a branch matters here only if the frame leaves.
TX_CALLS = re.compile(
    r"\b(hostapd_drv_send_mlme|hostapd_drv_sta_deauth|hostapd_drv_sta_disassoc"
    r"|ieee802_11_send_\w+|wpa_send_eapol|hostapd_send_eapol"
    r"|hostapd_eapol_send|send_auth_reply|wpa_auth_send_eapol"
    r"|hostapd_notif_\w*send\w*|ap_sta_disconnect)\s*\(")

# A per-peer field: something reached through a pointer. The pointer's name is
# kept so that a condition on one object and a write to another is not mistaken
# for a latch.
FIELD = re.compile(r"\b([a-z_]\w*)\s*->\s*([a-z_]\w*)\b")

# A write to one: assignment, or the bit-set form hostap uses for sta->flags.
WRITE = re.compile(
    r"\b([a-z_]\w*)\s*->\s*([a-z_]\w*)\s*(?:=[^=]|\|=|\+=|\^=|&=|\+\+|--)")

IF = re.compile(r"\bif\s*\(")


def blocks(body):
    """[(condition, body, offset)] for every if statement in a function."""
    out = []
    clean = cparse.strip_comments(body)
    for m in IF.finditer(clean):
        depth, i = 1, m.end()
        while i < len(clean) and depth:
            if clean[i] == "(":
                depth += 1
            elif clean[i] == ")":
                depth -= 1
            i += 1
        cond = clean[m.end():i - 1]
        rest = clean[i:]
        bm = re.match(r"\s*\{", rest)
        if bm:
            depth, j = 1, bm.end()
            while j < len(rest) and depth:
                if rest[j] == "{":
                    depth += 1
                elif rest[j] == "}":
                    depth -= 1
                j += 1
            blk = rest[bm.end():j - 1]
        else:
            end = rest.find(";")
            blk = rest[:end + 1] if end >= 0 else rest[:200]
        out.append((cond, blk, m.start()))
    return out


def line_of(src, body_start, offset):
    return src.count("\n", 0, body_start + offset) + 1


SM_STATE = re.compile(r"^SM_STATE\(\s*(\w+)\s*,\s*(\w+)\s*\)", re.M)


def scan_state_machines(root, only=None):
    """Every SM_STATE() whose body sends a frame."""
    out = []
    for dirpath, _, names in os.walk(root):
        rel = os.path.relpath(dirpath, root)
        if not rel.startswith(("src", "wpa_supplicant", "hostapd")):
            continue
        for name in names:
            if not name.endswith(".c"):
                continue
            path = os.path.join(dirpath, name)
            fil = os.path.relpath(path, root)
            if only and fil != only:
                continue
            with open(path, encoding="utf-8", errors="replace") as f:
                src = f.read()
            if "SM_STATE(" not in src:
                continue
            clean = cparse.strip_comments(src)
            for m in SM_STATE.finditer(clean):
                end = clean.find("\n}", m.end())
                body = clean[m.end():end if end > 0 else len(clean)]
                tx = sorted({t.group(1) for t in TX_CALLS.finditer(body)})
                if not tx:
                    continue
                out.append({
                    "file": fil,
                    "function": "SM_STATE(%s, %s)" % (m.group(1), m.group(2)),
                    "line": clean.count("\n", 0, m.start()) + 1,
                    "distance": 0,
                    "fields": ["state machine %s" % m.group(1)],
                    "condition": "entered once per session",
                    "tx_in_branch": True,
                    "shape": "state",
                    "sends": tx,
                })
    out.sort(key=lambda s: (s["file"], s["line"]))
    return out


def scan(root, only=None):
    funcs = reach.load(root)
    writers, dist = reach.distances(funcs)
    sources = {}
    found = []

    for fil, name, body in funcs:
        if only and fil != only:
            continue
        d = dist.get(name)
        if d is None or d > 2:
            continue
        clean = cparse.strip_comments(body)
        if not TX_CALLS.search(clean) and not (
                cparse.calls_in(body) & writers):
            continue

        if fil not in sources:
            with open(os.path.join(root, fil), encoding="utf-8",
                      errors="replace") as f:
                sources[fil] = f.read()
        src = sources[fil]
        body_start = src.find(body)

        writes = {(m.group(1), m.group(2)) for m in WRITE.finditer(clean)}
        if not writes:
            continue

        for cond, blk, off in blocks(body):
            reads = {(m.group(1), m.group(2)) for m in FIELD.finditer(cond)}
            latched = sorted(reads & writes)
            if not latched:
                continue
            # The frame has to actually leave, either from the branch or from
            # the function the branch is the guard for.
            in_branch = bool(TX_CALLS.search(blk))
            if not in_branch and not TX_CALLS.search(clean):
                continue
            found.append({
                "shape": "latch",
                "file": fil,
                "function": name,
                "line": line_of(src, body_start, off) if body_start >= 0 else 0,
                "distance": d,
                "fields": ["%s->%s" % f for f in latched],
                "condition": " ".join(cond.split())[:90],
                "tx_in_branch": in_branch,
            })

    # A latch tested and set inside the branch that sends is the clearest case;
    # after that, nearer the frame builders first.
    found.sort(key=lambda s: (not s["tx_in_branch"], s["distance"],
                              s["file"], s["line"]))
    return scan_state_machines(root, only) + found


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    root = os.path.abspath(args[0]) if args else os.getcwd()
    only = None
    if "--file" in sys.argv:
        only = sys.argv[sys.argv.index("--file") + 1]

    sites = scan(root, only)
    if "--json" in sys.argv:
        json.dump(sites, sys.stdout, indent=1)
        print()
        return 0

    for s in sites:
        print("%s:%d  %s  d%d%s" % (s["file"], s["line"], s["function"],
                                    s["distance"],
                                    "  tx-in-branch" if s["tx_in_branch"]
                                    else ""))
        if s["shape"] == "state":
            print("        sends: %s" % " ".join(s["sends"]))
        else:
            print("        latch: %s" % " ".join(s["fields"]))
            print("        if (%s)" % s["condition"])
    states = [s for s in sites if s["shape"] == "state"]
    latches = [s for s in sites if s["shape"] == "latch"]
    inbranch = sum(1 for s in latches if s["tx_in_branch"])
    print("\n%d one-shot transmit site(s): %d transmitting state-machine "
          "states, %d latched branches (%d sending from inside the branch)"
          % (len(sites), len(states), len(latches), inbranch))
    files = {}
    for s in sites:
        files[s["file"]] = files.get(s["file"], 0) + 1
    for f, n in sorted(files.items(), key=lambda kv: -kv[1])[:8]:
        print("    %-40s %d" % (f, n))
    return 0


if __name__ == "__main__":
    sys.exit(main())
