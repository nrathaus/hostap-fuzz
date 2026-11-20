#!/usr/bin/env python3
"""How close a configuration field sits to the code that builds a frame.

An axis is worth sweeping if moving it changes what goes on the air. The
tempting way to decide that is a filter that drops the rest -- but a filter is a
list of things someone decided not to look at, which is the spotlight this whole
effort exists to widen. A wrong exclusion is permanent and silent: the frame
family it drops is never swept by any run, and nothing in the output says so.
A wrong inclusion costs one run.

So nothing is excluded for being far away. Distance is measured and reported,
and the sweep order follows it:

  0  the field is read inside a function that writes octets into a frame
  1  it is read one call away from one -- a predicate that decides whether the
     frame is built at all, or an accessor the builder consults
  2+ further out, the value still reaches the air but through more code

Distance is measured on the UNDIRECTED call graph, because both directions
matter and for different reasons. Downwards is a builder consulting a helper.
Upwards is the decision to build the frame at all -- which is the stronger case
of the two, since a field read there can make a frame exist rather than merely
change its contents, and a frame that is never built is exactly what this is
about.

A function "writes a frame" if its body contains one of the ways this tree puts
octets into one -- wpabuf_put*, a walking pos/eid pointer, WPA_PUT_* -- or if
its name follows the tree's own convention for an element emitter. Syntax, not
a judgement about the function.

A field read nowhere outside the parser is the one thing reported as out of
reach, and that is a fact about the tree rather than a decision about the field.

    python3 reach.py [CHECKOUT] [FIELD ...]
"""

import collections
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cparse

SCAN_DIRS = ["src", "wpa_supplicant", "hostapd"]
MAX_DIST = 4

FRAME_MARKERS = [
    re.compile(r"\bwpabuf_put"),
    re.compile(r"\*\s*(?:pos|eid|p|buf|start)\+\+\s*="),
    re.compile(r"\bWPA_PUT_(?:LE|BE)\d*\s*\(\s*(?:pos|eid|p|buf)"),
    re.compile(r"\bos_memcpy\s*\(\s*(?:pos|eid|p)\s*,"),
]
FRAME_NAMES = re.compile(
    r"^(hostapd_eid_|wpa_write_|wpas_\w+_ie|.*_build_.*|.*_add_\w*ie$|"
    r".*_own_ie|.*_write_\w*ie)", re.I)

# A read, not a write: "->field =" is the parser storing the value, which is
# true of every field and so distinguishes nothing.
READ = re.compile(r"(?:->|\.)\s*([a-z_]\w*)\b(?!\s*(?:=[^=]|\+\+|--))")


def is_frame_writer(name, body):
    if FRAME_NAMES.match(name):
        return True
    clean = cparse.strip_comments(body)
    return any(r.search(clean) for r in FRAME_MARKERS)


def load(root):
    """[(file, name, body)] for every function in the scanned directories."""
    out = []
    for d in SCAN_DIRS:
        base = os.path.join(root, d)
        if not os.path.isdir(base):
            continue
        for dirpath, _, names in os.walk(base):
            for name in names:
                if not name.endswith(".c"):
                    continue
                path = os.path.join(dirpath, name)
                with open(path, encoding="utf-8", errors="replace") as f:
                    src = f.read()
                rel = os.path.relpath(path, root)
                for fname, body in cparse.split_functions(src):
                    out.append((rel, fname, body))
    return out


def distances(funcs):
    """{function: hops to the nearest frame writer} on the undirected graph."""
    defined = {name for _, name, _ in funcs}
    writers = {name for _, name, body in funcs if is_frame_writer(name, body)}

    down = collections.defaultdict(set)
    up = collections.defaultdict(set)
    for _, name, body in funcs:
        for callee in cparse.calls_in(body) & defined:
            down[name].add(callee)
            up[callee].add(name)

    dist = {w: 0 for w in writers}
    queue = collections.deque(writers)
    while queue:
        cur = queue.popleft()
        d = dist[cur]
        if d >= MAX_DIST:
            continue
        for nxt in down[cur] | up[cur]:
            if nxt not in dist:
                dist[nxt] = d + 1
                queue.append(nxt)
    return writers, dist


def read_sites(funcs, dist):
    """{field: (best distance, [site, ...])} over every read in the tree.

    A field read only beyond MAX_DIST, or not read at all, gets distance None.
    """
    out = {}
    for fil, name, body in funcs:
        d = dist.get(name)
        for m in READ.finditer(cparse.strip_comments(body)):
            field = m.group(1)
            site = "%s:%s" % (fil, name)
            best, sites = out.setdefault(field, (None, []))
            if d is not None and (best is None or d < best):
                best = d
            if len(sites) < 64:
                sites.append((d, site))
            out[field] = (best, sites)
    return out


def build(root):
    funcs = load(root)
    writers, dist = distances(funcs)
    return writers, dist, read_sites(funcs, dist), len(funcs)


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    root = os.path.abspath(args[0]) if args else os.getcwd()
    want = args[1:]
    writers, dist, reads, total = build(root)
    hist = collections.Counter(dist.values())
    print("%d functions scanned, %d write frames" % (total, len(writers)))
    print("by distance: %s" % ", ".join(
        "%d:%d" % (d, hist[d]) for d in sorted(hist)))
    print("%d distinct field names read somewhere" % len(reads))
    for name in want:
        best, sites = reads.get(name, (None, []))
        near = sorted((d, s) for d, s in sites if d is not None)
        print("\n%s: distance %s, %d site(s)" % (
            name, "unreached" if best is None else best, len(sites)))
        for d, s in near[:6]:
            print("    %d  %s" % (d, s))
    return 0


if __name__ == "__main__":
    sys.exit(main())
