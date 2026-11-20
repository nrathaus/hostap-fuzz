#!/usr/bin/env python3
"""Coverage ledger: report what a run SENT, never whether anything broke.

This is not an oracle. It answers one question -- how much of each family did
this run actually put on the air -- because without it "the sweep covers a
family rather than a member" is an unfalsifiable claim.

    python3 ledger.py [CHECKOUT] < run.log
    python3 ledger.py [CHECKOUT] run.log [run2.log ...]

Input is anything carrying the '[fuzz] ' lines: a saved hostapd log, or
monitor_fuzzing.py's output.

Two tallies are kept per registry and they mean different things:

  as built   the frame with the run's single-byte mutation undone, which is
             what the running configuration causes hostapd to emit. This is
             the number that says how wide the spotlight is.
  on air     the frame as transmitted. Wider, because rewriting an id octet in
             place does select a different parse helper -- but the length and
             body still belong to the element that was there, so most helpers
             reject on the first guard. Depth is not reach.

The gap between the two columns is the argument for synthesis.
"""

import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import registries as registries_mod   # noqa: E402
import targets as targets_mod         # noqa: E402

PREFIX = "[fuzz] "

# Which registry a named field draws its values from. Keyed on the field's
# own name as struct ieee80211_mgmt spells it, so a field upstream renames
# stops matching rather than silently counting into the wrong registry.
FIELD_REGISTRY = {
    "status_code": "status code",
    "reason_code": "reason code",
    "auth_alg": "authentication algorithm",
}

MGMT_AUTH, MGMT_ASSOC_RESP, MGMT_PROBE_RESP = 11, 1, 5
MGMT_DEAUTH, MGMT_DISASSOC = 12, 10

# Subtype -> (octets of fixed fields after the 24-octet header, element chain?)
FIXED = {
    MGMT_ASSOC_RESP: 6,
    MGMT_PROBE_RESP: 12,
    MGMT_DEAUTH: 2,
    MGMT_DISASSOC: 2,
}


class Tally:
    def __init__(self):
        self.values = {}

    def add(self, value, where):
        self.values.setdefault(value, set()).add(where)


def walk_elements(body):
    """Walk an element chain. Returns (ids, ext_ids) or None if it does not
    consume the region exactly.

    Refusing a partial walk is deliberate. An authentication frame's variable
    part is only an element chain for some (algorithm, transaction, status)
    combinations; for the rest it starts with fixed fields whose octets would
    parse as plausible elements and invent members that were never sent. A
    tally that over-reports is worse than one that reports less.
    """
    ids, ext_ids, i = [], [], 0
    while i < len(body):
        if i + 2 > len(body):
            return None
        eid, elen = body[i], body[i + 1]
        if i + 2 + elen > len(body):
            return None
        ids.append(eid)
        if eid == 255 and elen >= 1:          # WLAN_EID_EXTENSION
            ext_ids.append(body[i + 2])
        i += 2 + elen
    return ids, ext_ids


def frame_kind(message):
    """What the mutated buffer is, as the engine reported it.

    Older logs predate the "frame" key. For those the target name is the only
    thing there is, and the rule below is exactly what the engine did at the
    time -- every target but "eapol" was an 802.11 management frame -- so the
    fallback is not a guess about those logs, it is their history. It is
    wrong only for frame kinds that did not exist when they were written,
    which is to say for none of them.
    """
    kind = message.get("frame")
    if kind:
        return kind
    return "eapol" if message.get("target") == "eapol" else "mgmt"


def parse_frame(kind, data):
    """Best effort. Returns a dict of registry name -> list of values seen.

    'kind' is the frame kind, not the target's name. A body with no 802.11
    header of its own is not parsed here at all: its first octet is an element
    id or a category, and reading it as a frame control field yields a subtype
    and a fixed-field length that are arithmetic on unrelated bytes. The chain
    may then walk cleanly and the tally gains members that were never sent.
    Over-reporting is worse than reporting less, so these frames are counted
    through the engine's own MUT_ELEM messages instead.
    """
    out = {}
    if kind != "mgmt" or len(data) < 24:
        return out                            # not an 802.11 management frame

    fc0 = data[0]
    if (fc0 >> 2) & 0x3 != 0:                 # not type management
        return out
    subtype = (fc0 >> 4) & 0xF
    body = data[24:]

    if subtype == MGMT_AUTH:
        if len(body) < 6:
            return out
        out["authentication algorithm"] = [body[0] | (body[1] << 8)]
        out["status code"] = [body[4] | (body[5] << 8)]
        walked = walk_elements(body[6:])
    elif subtype in (MGMT_DEAUTH, MGMT_DISASSOC):
        if len(body) < 2:
            return out
        out["reason code"] = [body[0] | (body[1] << 8)]
        walked = None
    elif subtype in FIXED:
        fixed = FIXED[subtype]
        if subtype == MGMT_ASSOC_RESP and len(body) >= 4:
            out["status code"] = [body[2] | (body[3] << 8)]
        walked = walk_elements(body[fixed:]) if len(body) >= fixed else None
    else:
        walked = None

    if walked:
        ids, ext_ids = walked
        out["element id"] = ids
        out["element id extension"] = ext_ids
    return out


def as_built(message, data, legacy_hdr=False):
    """The frame with this case's mutation undone, or None.

    For a length case there is nothing to undo when the frame was grown -- the
    octets hostapd built are still the first 'was' of them -- and nothing to
    recover when it was truncated, since the rest was never sent and is not in
    the log. The caller is told which by the return value and counts the two
    separately; folding a truncated case into "could not reconstruct" would
    make a working sweep look like a broken one.
    """
    if message.get("type") == "MUT_LEN":
        was = message.get("was")
        if was is None or was > len(data):
            return None
        return bytes(data[:was])

    if message.get("type") == "MUT_ELEM":
        # Cut the inserted octets back out. The engine says where they went
        # and how many there were, so this is exact rather than inferred.
        was, now, at = (message.get("was"), message.get("len"),
                        message.get("at"))
        if None in (was, now, at) or now < was or at > was or now > len(data):
            return None
        return bytes(data[:at]) + bytes(data[at + (now - was):now])

    if message.get("type") == "MUT_CHAIN":
        # Deleting an element loses octets that are not in the log, and the
        # other two are reversible only by redoing the walk. Not recovered,
        # and counted as its own thing rather than as a broken message.
        return None

    if message.get("type") == "MUT_FIELD":
        # A field case has an exact as-built form too: the engine reported
        # what was there before it wrote, and where. Treating it as
        # unrecoverable would under-report the as-built column by every field
        # case in the run, which is most of them.
        at, width = message.get("at"), message.get("width")
        before = message.get("before")
        if at is None or width is None or before is None or \
                at + width > len(data):
            return None
        out = bytearray(data)
        for i in range(width):
            k = width - 1 - i if message.get("frame") == "eapol" else i
            out[at + k] = (before >> (8 * i)) & 0xff
        return bytes(out)

    try:
        idx, mask = message["idx"], message["mask"]
    except KeyError:
        return None
    hdr = message.get("hdr")
    if hdr is None:
        if not legacy_hdr:
            return None                       # pre-'hdr' log: cannot be exact
        # The engine's own rule, applied to a log written before it was
        # recorded. Correct for every target in the tree today, and stated in
        # the report so it is never mistaken for something the log carried.
        hdr = 0 if frame_kind(message) != "mgmt" else 24
    pos = hdr + idx
    if pos >= len(data):
        return None
    out = bytearray(data)
    out[pos] ^= mask
    return bytes(out)


class Ledger:
    """Incremental collector, so a long run is tallied as it goes rather than
    buffered. monitor_fuzzing.py feeds it one decoded message at a time."""

    def __init__(self, legacy_hdr=False):
        self.legacy_hdr = legacy_hdr
        self.inventory = None
        self.stages = None
        self.repeats = {}
        self.seen = set()
        self.built, self.air = {}, {}
        self.frames = self.unparsed = self.no_hdr = 0
        # Per named field: how many cases it got, and under which tier. The
        # tier is what turns "this field was swept" into a statement with a
        # denominator.
        self.fields = {}
        self.widths = {}
        self.patterns = {}
        self.tiers = {}
        self.opsets = set()
        # Cases per (peer, target). Several peers share a target's case
        # counter, so each receives a different case -- a multi-peer run is N
        # times the stimulus, not N copies of it -- and this is the record
        # that says so rather than leaving it to be assumed.
        self.peers = {}
        self.lengths = {}
        self.truncated = 0
        self.synth = 0
        self.chain_ops = {}

    def feed(self, msg):
        kind = msg.get("msg")
        if kind == "inventory":
            self.inventory = list(msg.get("targets") or [])
            self.stages = list(msg.get("stages") or [])
            return
        if kind == "repeat":
            # How many extra occurrences of a stage this run actually
            # delivered. A budget that was set and never spent means the
            # branch was never taken, which is a different fact from a stage
            # nobody asked to repeat.
            stage = msg.get("stage")
            self.repeats[stage] = self.repeats.get(stage, 0) + 1
            return
        if kind == "progress":
            self.seen.add(msg.get("target"))
            return
        if msg.get("opset"):
            self.opsets.add(msg["opset"])

        if kind != "fuzz":
            return

        if msg.get("peer"):
            key = (msg["peer"], msg.get("target", "?"))
            self.peers[key] = self.peers.get(key, 0) + 1

        self.seen.add(msg.get("target"))
        try:
            data = bytes.fromhex(msg.get("data", ""))
        except ValueError:
            self.unparsed += 1
            return
        self.frames += 1
        target = msg.get("target", "?")
        kind = frame_kind(msg)
        for name, values in parse_frame(kind, data).items():
            for v in values:
                self.air.setdefault(name, Tally()).add(v, target)
        if msg.get("type") == "MUT_ELEM":
            # The id the engine says it synthesised, not one re-derived by
            # parsing. A management frame's variable part is only an element
            # chain for some frames, so a parser that refuses a partial walk --
            # as it must -- would miss exactly the ids that were appended to a
            # frame it could not walk. The engine knows; it is asked.
            for key in ("eid", "element id"), ("ext_id",
                                               "element id extension"):
                if msg.get(key[0]) is not None:
                    self.air.setdefault(key[1], Tally()).add(
                        msg[key[0]], target)
            self.synth = getattr(self, "synth", 0) + 1

        if msg.get("type") == "MUT_FIELD":
            # The value the engine says it wrote, under the field's own name,
            # rather than one re-derived by parsing. Same reason as the
            # element ids: parse_frame() refuses a frame it cannot walk, and
            # would miss exactly the cases that made it unwalkable.
            reg = FIELD_REGISTRY.get(msg.get("field", "").split(".")[-1])
            if reg and msg.get("after") is not None:
                self.air.setdefault(reg, Tally()).add(msg["after"], target)
            self.fields[msg.get("field")] = \
                self.fields.get(msg.get("field"), 0) + 1
            if msg.get("width"):
                self.widths[msg.get("field")] = msg["width"]
            if msg.get("tier"):
                self.tiers.setdefault(msg["tier"], set()).add(
                    msg.get("field"))

        if msg.get("type") == "MUT_PATTERN":
            self.patterns[msg.get("field")] = \
                self.patterns.get(msg.get("field"), 0) + 1

        if msg.get("type") == "MUT_CHAIN":
            self.chain_ops[msg.get("op")] = \
                self.chain_ops.get(msg.get("op"), 0) + 1

        if msg.get("type") == "MUT_LEN":
            # The length domain, tallied like any other: what was sent, not
            # whether it was any good.
            was, now = msg.get("was"), msg.get("len")
            if now is not None:
                self.lengths[now] = self.lengths.get(now, 0) + 1
            if was is not None and now is not None and now < was:
                self.truncated += 1

        original = as_built(msg, data, self.legacy_hdr)
        if original is None:
            # A truncated frame has no as-built form to recover: the octets
            # past the new length were never sent and are not in the log. That
            # is the case working as intended, not a message missing a field,
            # so it is not counted as one.
            # A pattern case overwrote the octets outright, so there is
            # nothing to undo: like a truncation, that is the case working
            # as intended rather than a message missing a field.
            if msg.get("type") not in ("MUT_LEN", "MUT_CHAIN",
                                       "MUT_PATTERN", "MUT_ELEM"):
                self.no_hdr += 1
            return
        for name, values in parse_frame(kind, original).items():
            for v in values:
                self.built.setdefault(name, Tally()).add(v, target)

    def feed_line(self, line):
        at = line.find(PREFIX)
        if at < 0:
            return
        try:
            msg = json.loads(line[at + len(PREFIX):])
        except ValueError:
            self.unparsed += 1
            return
        if isinstance(msg, dict):
            self.feed(msg)

    def summary(self, root=None):
        """The run's coverage as data, for a campaign that unions many runs.

        Separate from report() on purpose: report() is written to be read by a
        person at the end of one run, and a format that has to stay readable is
        the wrong thing for another program to parse.
        """
        out = {
            "inventory": self.inventory,
            "lengths": dict(sorted(self.lengths.items())),
            "truncated": self.truncated,
            "synthesised": self.synth,
            "chain_ops": dict(sorted(self.chain_ops.items())),
            "stages": self.stages,
            "repeats": dict(sorted(self.repeats.items())),
            "targets": sorted(t for t in self.seen if t),
            "frames": self.frames,
            "unparsed": self.unparsed,
            "no_hdr": self.no_hdr,
            "fields": dict(sorted(self.fields.items())),
            "patterns": dict(sorted(self.patterns.items())),
            "tiers": {k: sorted(v) for k, v in sorted(self.tiers.items())},
            # Every case space this run's messages came from. More than one
            # means the run's case_ids are not comparable with each other,
            # which a campaign unioning runs has to know.
            "opsets": sorted(self.opsets),
            "peers": {"%s %s" % k: v
                      for k, v in sorted(self.peers.items())},
            "built": {}, "air": {},
        }
        for key, src in (("built", self.built), ("air", self.air)):
            for name, tally in src.items():
                out[key][name] = sorted(tally.values)
        return out

    def report(self, root, out=None):
        out = out or sys.stdout
        say = lambda *a: print(*a, file=out)
        defined = registries_mod.extract(root)
        have_source = any(defined.values())

        say("COVERAGE LEDGER -- what this run sent. Not a verdict.")
        say()
        if not have_source:
            say("No checkout at %s, so the registry denominators are not" % root)
            say("available: this report says what the run sent, not out of how")
            say("many. Point the first argument at a hostap source tree for the")
            say("'defined members' column.")
            say()
        say("frames with a hexdump: %d" % self.frames)
        if self.unparsed:
            say("unparsable [fuzz] lines: %d" % self.unparsed)
        if self.truncated:
            say("length cases that truncated the frame: %d" % self.truncated)
            say("  (no as-built form: the octets past the new length were")
            say("   never sent, so they are not in the log to recover)")
        if self.no_hdr:
            say("frames without 'hdr', so the as-built column is short by: %d"
                % self.no_hdr)
            say("  (pass --legacy-hdr to infer it for a log written before the")
            say("   field existed; the column is then inferred, not recorded)")
        if self.legacy_hdr:
            say("as-built column: 'hdr' INFERRED from the target name, not read")
            say("  from the log. Correct for every target in the tree today.")
        say()

        say("TARGETS")
        if self.inventory is None:
            say("  no inventory message: cannot tell a target that does not")
            say("  exist from one that was never reached. Rebuild with the")
            say("  current src/common/fuzz.c.")
            known = sorted(t for t in self.seen if t)
        else:
            known = self.inventory
        for name in sorted(known):
            say("  %-28s %s"
                % (name, "reached" if name in self.seen else "NEVER REACHED"))
        missing = [n for n in known if n not in self.seen]
        say("  %d of %d reached" % (len(known) - len(missing), len(known)))
        say()

        if self.synth or self.chain_ops:
            say("SYNTHESIS -- elements this run put into frames")
            say("  %d element(s) synthesised and inserted" % self.synth)
            if self.chain_ops:
                say("  chain shape changed: %s" % ", ".join(
                    "%s %d" % kv for kv in sorted(self.chain_ops.items())))
            say()

        if self.fields or self.patterns:
            say("NAMED FIELDS -- what fraction of each field's domain this")
            say("run sent, and under which tier")
            say("  %-26s %8s %10s  %s"
                % ("field", "cases", "of domain", "tier"))
            tier_of = {}
            for tier, names in self.tiers.items():
                for name in names:
                    tier_of[name] = tier
            for name, n in sorted(self.fields.items()):
                width = self.widths.get(name)
                domain = (1 << (8 * width)) if width else None
                say("  %-26s %8d %10s  %s"
                    % (name, n, domain if domain else "?",
                       tier_of.get(name, "")))
            for name, n in sorted(self.patterns.items()):
                say("  %-26s %8d %10s  PATTERN" % (name, n, "fills"))
            say()
            say("  A tier is what gives the middle column a denominator.")
            say("  FULL is the whole domain. LADDER is its edges, and the")
            say("  edges of where the frame already was. STRIDE is the")
            say("  ladder plus the rest walked at a prime stride from this")
            say("  run's offset -- so it is complete over the set of runs,")
            say("  not over this one, and the offset is in every message so")
            say("  any case replays.")
            say("  A field reported here was driven across its own domain.")
            say("  The octet sweep reaches 511 values of a two-octet field,")
            say("  never the pairs between.")
            say()

        if self.peers:
            bypeer = {}
            for (peer, target), n in self.peers.items():
                bypeer.setdefault(peer, {})[target] = n
            say("PEERS -- which peer received which cases")
            for peer in sorted(bypeer):
                total = sum(bypeer[peer].values())
                say("  %-20s %6d case(s)  %s"
                    % (peer, total,
                       ", ".join("%s %d" % kv
                                 for kv in sorted(bypeer[peer].items()))))
            if len(bypeer) > 1:
                say("  %d peers in one run. They share each target's case"
                    % len(bypeer))
                say("  counter, so each received a different case: this is")
                say("  %dx the stimulus, not %d copies of it."
                    % (len(bypeer), len(bypeer)))
            say("  Which peer, not whether it minded. Record, not verdict.")
            say()

        if len(self.opsets) > 1:
            say("MORE THAN ONE CASE SPACE IN THIS LOG")
            for o in sorted(self.opsets):
                say("  %s" % o)
            say("  A case_id indexes one of these. Cases recorded under")
            say("  different ones are not comparable and will not replay")
            say("  across them.")
            say()

        if self.lengths:
            lo, hi = min(self.lengths), max(self.lengths)
            say("FRAME LENGTH -- the length domain, as swept")
            say("  %d length case(s), %d distinct length(s), %d..%d"
                % (sum(self.lengths.values()), len(self.lengths), lo, hi))
            say("  %d truncated the frame, %d grew it"
                % (self.truncated,
                   sum(self.lengths.values()) - self.truncated))
            short = sum(n for v, n in self.lengths.items() if v < 24)
            if short:
                say("  %d sent a frame under the 802.11 header length; the"
                    % short)
                say("  nl80211 driver refuses those, so they were built and")
                say("  counted here but did not leave the machine.")
            say()

        if self.stages:
            say("STAGE MULTIPLICITY -- extra occurrences delivered")
            for name in sorted(self.stages):
                n = self.repeats.get(name, 0)
                say("  %-28s %s" % (
                    name,
                    "%d extra occurrence(s)" % n if n else
                    "1 occurrence per session (no FUZZ_REPEAT_%s, or the "
                    "branch was never taken)"
                    % re.sub(r"[^A-Za-z0-9]", "_", name).upper()))
            say()
        elif self.repeats:
            say("STAGE MULTIPLICITY")
            for name, n in sorted(self.repeats.items()):
                say("  %-28s %d extra occurrence(s)" % (name, n))
            say("  (no stage inventory: a stage with no repeats cannot be")
            say("   told from one this build does not have)")
            say()

        if not have_source:
            # Every cell in this section is counted against the number of
            # members a family has, and without the header that number is 0.
            # A table of zeros reads as "nothing was sent", which is the one
            # thing it does not mean, so print the raw counts instead.
            say("REGISTRIES -- distinct values this run put in each family.")
            say("No checkout, so there is no denominator to compare them to.")
            for _, name in registries_mod.REGISTRIES:
                b = len(self.built.get(name, Tally()).values)
                a = len(self.air.get(name, Tally()).values)
                if b or a:
                    say("  %-24s %5d as built %5d on air" % (name, b, a))
            return

        say("REGISTRIES                    defined members seen    distinct values")
        say("                            defined  as built  on air   as built  on air")
        for _, name in registries_mod.REGISTRIES:
            members = defined.get(name, {})
            bvals = self.built.get(name, Tally()).values
            avals = self.air.get(name, Tally()).values
            say("  %-24s %5d %9d %7d %10d %7d"
                % (name, len(members),
                   len(set(bvals) & set(members)),
                   len(set(avals) & set(members)),
                   len(bvals), len(avals)))
        say()
        say("  as built = the running configuration's own output, mutation undone.")
        say("             This column is the width of the spotlight.")
        say("  on air   = after mutation. Wider, but an id rewritten in place keeps")
        say("             the old element's length and body, so most parse helpers")
        say("             reject on the first guard. Reach is not depth.")
        say("  distinct values includes values with no defined member, which for a")
        say("  one-octet id field is the rest of its 0..255 domain.")


def main():
    args = sys.argv[1:]
    root = os.getcwd()
    if args and os.path.isdir(args[0]):
        root = os.path.abspath(args[0])
        args = args[1:]

    legacy_hdr = "--legacy-hdr" in args
    args = [a for a in args if not a.startswith("--")]

    ledger = Ledger(legacy_hdr)
    if args:
        for path in args:
            with open(path, encoding="utf-8", errors="replace") as f:
                for line in f:
                    ledger.feed_line(line)
    else:
        for line in sys.stdin:
            ledger.feed_line(line)

    ledger.report(root)
    return 0


if __name__ == "__main__":
    sys.exit(main())
