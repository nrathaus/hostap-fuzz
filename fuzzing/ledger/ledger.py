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

import collections
import itertools
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import registries as registries_mod   # noqa: E402
import targets as targets_mod         # noqa: E402

PREFIX = "[fuzz] "

# W13's correlation. A receiver cannot be told which case it is holding, so a
# parse is matched to a case by the octets it quotes -- and by OVERLAP with
# them rather than by containment, because what a walker is handed is not
# always what the sender built.
#
# Windows of REACH_NEEDLE octets taken every REACH_STEP: any common run of
# 16 + 8 - 1 = 23 octets or more is found, and 23 octets of agreement between
# two frames is not chance. Stepping rather than sliding keeps the scan to a
# couple of dozen substring searches per parse, which matters because a
# receiver parses every frame it hears, not only ours.
REACH_NEEDLE = 16
REACH_STEP = 8

# W15. Guards arrive in the log as C preprocessor expressions, and this
# evaluates them against the flag set a binary reported. They are PARSED, not
# eval()'d: a log is a file from somewhere else, and the one thing a report
# must never do is execute it. The grammar is the whole of what a generated
# guard contains.
_GUARD_TOK = re.compile(r"\s*(defined\(\s*([A-Za-z_]\w*)\s*\)|&&|\|\||!|\(|\)|.)")

# How many off flags a guard may name before the search below gives up and
# lists them instead of naming the one that would flip it. 2**8 is already
# more than any guard in this tree needs.
GUARD_SEARCH_MAX = 8


def _wrap(names, width):
    """Names packed into lines of at most `width` characters."""
    rows, row = [], ""
    for n in names:
        if row and len(row) + 1 + len(n) > width:
            rows.append(row)
            row = ""
        row = n if not row else row + " " + n
    if row:
        rows.append(row)
    return rows


def guard_tokens(expr):
    """The guard as a token list, or None if it holds something unexpected."""
    out, pos = [], 0
    while pos < len(expr):
        m = _GUARD_TOK.match(expr, pos)
        if not m:
            return None
        pos = m.end()
        tok = m.group(1)
        if tok.startswith("defined"):
            out.append(("sym", m.group(2)))
        elif tok in ("&&", "||", "!", "(", ")"):
            out.append((tok, None))
        elif tok.strip() == "":
            continue
        else:
            return None       # something this grammar does not model
    return out


def guard_true(expr, on, daemon):
    """Is this build condition true for a binary with flag set `on`?

    None when the expression cannot be parsed, which the caller reports as
    "cannot tell" rather than as false. Claiming a guard is false would turn
    an unreadable condition into a confident "absent from this build", and
    that is exactly the four-state distinction this whole file exists for.
    """
    toks = guard_tokens(expr or "")
    if toks is None:
        return None
    pos = [0]

    def peek():
        return toks[pos[0]][0] if pos[0] < len(toks) else None

    def unary():
        t = peek()
        if t == "!":
            pos[0] += 1
            v = unary()
            return None if v is None else not v
        if t == "(":
            pos[0] += 1
            v = or_expr()
            if peek() != ")":
                return None
            pos[0] += 1
            return v
        if t == "sym":
            name = toks[pos[0]][1]
            pos[0] += 1
            if name == "HOSTAPD":
                return daemon == "hostapd"
            return name in on
        return None

    def and_expr():
        v = unary()
        while peek() == "&&":
            pos[0] += 1
            r = unary()
            v = None if (v is None or r is None) else (v and r)
        return v

    def or_expr():
        v = and_expr()
        while peek() == "||":
            pos[0] += 1
            r = and_expr()
            v = None if (v is None or r is None) else (v or r)
        return v

    val = or_expr()
    return val if pos[0] == len(toks) else None


def guard_flags(expr):
    """The flag names a guard tests, HOSTAPD excluded."""
    toks = guard_tokens(expr or "") or []
    return sorted({n for k, n in toks if k == "sym" and n != "HOSTAPD"})


def absent_because(expr, on, daemon):
    """Why a guard is false: a list of flag sets that would make it true.

    Returns ([], reason) when no combination of the flags it names can, which
    is the "wrong daemon" case -- and it is found by searching rather than by
    looking for HOSTAPD in the text, because a guard can also be unsatisfiable
    for less obvious reasons. Turning every off flag on at once is NOT a valid
    probe: a guard with a !defined() in it is not monotone, and that was the
    first thing this got wrong.
    """
    off = [f for f in guard_flags(expr) if f not in on]
    if not off:
        return [], "no flag it names is off"
    if len(off) > GUARD_SEARCH_MAX:
        return [], "names %d flags that are off" % len(off)
    best = []
    for size in range(1, len(off) + 1):
        for combo in itertools.combinations(off, size):
            if guard_true(expr, set(on) | set(combo), daemon) is True:
                best.append(list(combo))
        if best:
            return best, None
    return [], "no combination of the flags it names would do it"

# Which registry a named field draws its values from. Keyed on the field's
# own name as struct ieee80211_mgmt spells it, so a field upstream renames
# stops matching rather than silently counting into the wrong registry.
FIELD_REGISTRY = {
    "status_code": "status code",
    "reason_code": "reason code",
    "auth_alg": "authentication algorithm",
}

ELEM_ID = "element id"
ELEM_EXT_ID = "element id extension"
ELEM_EXTLEN_ID = "extended length element id"

# How to walk an element, by id. Filled from the checkout by load_shapes();
# until then, and when there is no checkout, every id is the basic shape --
# which is what this walker did before shapes existed, and is now stated in
# the report rather than assumed in silence.
BASIC_SHAPE = {"walk_hdr": 2, "len_off": 1, "len_width": 1, "len_le": False,
               "sub": None, "ext_off": 0, "ext_width": 0, "ext_le": False,
               "covers": False, "name": "BASIC"}
SHAPES = {None: BASIC_SHAPE}
SHAPES_FROM = None


def load_shapes(root):
    """Take the element shapes from the checkout, as the engine does.

    Returns the source, or None when there is no checkout to read -- in which
    case the walk stays on the basic shape and the report says so. The
    alternative, a hand-written copy of the shape table here, is the drift
    this project generates its tables to avoid: the engine would build an
    extended length element and the ledger would walk it two octets at a
    time, and the only visible symptom would be a chain that stopped
    walking.
    """
    global SHAPES, SHAPES_FROM
    try:
        info = registries_mod.shapes(root)
    except Exception:                         # noqa: BLE001 - no checkout
        return None
    sub_for = {"EXT": ELEM_EXT_ID, "EXTLEN": ELEM_EXTLEN_ID}
    table = {None: BASIC_SHAPE}
    for sh in info["shapes"]:
        entry = {
            # A shape whose length field covers its sub-registry id has that
            # id inside the body as far as the walk is concerned.
            "walk_hdr": (sh["len_off"] + sh["len_width"] if sh["covers"]
                         else sh["hdr"]),
            "len_off": sh["len_off"],
            "len_width": sh["len_width"],
            "len_le": bool(sh["len_le"]),
            "sub": sub_for.get(sh["name"]),
            "ext_off": sh["extid_off"],
            "ext_width": sh["extid_width"],
            "ext_le": bool(sh["extid_le"]),
            "covers": bool(sh["covers"]),
            "name": sh["name"],
        }
        if sh["sel"] is None:
            table[None] = entry
        else:
            defs = registries_mod.extract(root)
            for reg in defs.values():
                for val, names in reg.items():
                    if sh["sel"] in names:
                        table[val] = entry
    SHAPES = table
    SHAPES_FROM = root
    return root


# W11. How many element ids the tree's parser enforces a length for, and how
# many lengths struct ieee802_11_elems holds. The denominator a run's "aimed
# at a guard" figure is against; without it the report could say 39 and leave
# the reader to guess whether that was 39 of 39 or 39 of 241.
MINIMA = {}
MINIMA_DENOM = None


def load_minima(root):
    """The parser's own enforced lengths, from the checkout.

    Same reason as load_shapes(): a copy of those numbers here would detune
    itself the first time upstream moved one, and a detuned ledger reports a
    sweep as aimed when it is not.
    """
    global MINIMA, MINIMA_DENOM
    try:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        import minima as minima_mod
        rows = minima_mod.extract(root)
        MINIMA = {(r[0], r[1]): (r[5] + r[6], r[3], r[4]) for r in rows}
        MINIMA_DENOM = minima_mod.pairs(root)
    except Exception:                         # noqa: BLE001 - no checkout
        return None
    return root


# The ledger ships inside the checkout it describes, so the shapes are loaded
# the moment it is imported. A caller that feeds frames before it ever calls
# report() -- monitor_fuzzing.py does, and so does every verifier -- would
# otherwise walk the whole run on the basic shape and then print a shape
# section derived from the right table, which is the worst of the two.
load_shapes(os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__)))))
load_minima(os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__)))))


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
    """Walk an element chain. Returns {registry: [values]} or None if it does
    not consume the region exactly.

    Refusing a partial walk is deliberate. An authentication frame's variable
    part is only an element chain for some (algorithm, transaction, status)
    combinations; for the rest it starts with fixed fields whose octets would
    parse as plausible elements and invent members that were never sent. A
    tally that over-reports is worse than one that reports less.

    Shape matters here for the same reason it matters in the engine: an
    element's header is two octets for most ids, three for the extension id
    and five -- with a little-endian u16 length -- for the extended length id.
    Walking a chain containing one of the latter two octets at a time reads a
    length out of octets that are not the length field, and every offset after
    that point is arithmetic on unrelated bytes. The walk then either refuses
    the whole region, which under-reports, or lands on it by luck and tallies
    ids that were never sent.
    """
    out = {name: [] for name in (ELEM_ID, ELEM_EXT_ID, ELEM_EXTLEN_ID)}
    i = 0
    while i < len(body):
        eid = body[i]
        shape = SHAPES.get(eid, SHAPES[None])
        hdr = shape["walk_hdr"]
        if i + hdr > len(body):
            return None
        dlen = int.from_bytes(body[i + shape["len_off"]:
                                   i + shape["len_off"] + shape["len_width"]],
                              "little" if shape["len_le"] else "big")
        if i + hdr + dlen > len(body):
            return None
        out[ELEM_ID].append(eid)
        # A sub-registry id is only a member this frame carries when the
        # declared length reaches far enough to contain it.
        if shape["sub"] is not None:
            room = dlen if shape["covers"] else len(body) - i - shape["ext_off"]
            if room >= shape["ext_width"]:
                at = i + shape["ext_off"]
                out[shape["sub"]].append(
                    int.from_bytes(body[at:at + shape["ext_width"]],
                                   "little" if shape["ext_le"] else "big"))
        i += hdr + dlen
    return out


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

    if walked is not None:
        out.update(walked)
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
        # The element domains, each reported apart: six of them write
        # MUT_ELEM and a consumer that could only count them together would
        # report a run that never left the first one as a run that swept all
        # six.
        self.elem_dom = {}
        self.elem_shapes = {}
        self.declared = {}
        self.frags = {}
        self.depths = {}
        self.lying = 0
        # W10. A case that does not walk is a case whose octets stop the
        # consumer's walk, and it is only legitimate at the END of the chain
        # -- anywhere else it is absorbed by the element that follows and the
        # rest of the chain is not hostile, it is UNREAD. Counted, not
        # assumed: 'absorbed' is a case that broke that rule and 'chain_lost'
        # is one that measurably cost the consumer elements it had already
        # been given. Not 'truncated' -- that name is taken, by the length
        # cases that shortened the frame, and sharing it would have added two
        # unrelated numbers together and reported the sum as either.
        self.unwalkable = 0
        self.absorbed = 0
        self.chain_lost = 0
        self.clamped = 0
        self.walk_seen = 0
        # W11. Which element ids this run aimed a length at, and whether the
        # lengths it sent landed in the window above the guard. Counted per
        # id, not per case: a thousand cases against one id is not coverage
        # of the family, and a figure that could not tell the two apart
        # would report the narrow run as the wide one.
        self.aimed = {}
        self.unaimed = set()
        self.in_window = 0
        self.aimed_cases = 0
        # W12. How many cases came from the tail case space, where the span
        # under test is pinned to the end of the frame. Counted so the W10
        # section can tell a truncation that was the point from one that was
        # a mistake, and so the report can state the limit of the claim.
        self.tail_cases = 0
        self.cut_cases = 0
        self.cut_octets = 0
        self.claimed = {}
        self.absent_sub = 0
        self.deflen = 0
        self.inventory = None
        # One entry per announcing process. A run with a hooked AP and a
        # hooked station has two, and the union of their target lists is what
        # "this run could have reached" means -- not either one alone.
        self.inventories = []
        # Every label the tree has, with the build condition under which it
        # exists. Identical in every process, so the last one wins harmlessly.
        self.roster = {}
        self.stages = None
        # W15. The compile-time axis. Every domain above this line says what
        # was SWEPT; this one says what existed to sweep. Keyed by daemon,
        # because the two binaries are two builds and a run is only as
        # comparable as the less comparable of them.
        self.builds = {}
        # A log that unions two runs of the same daemon built differently is
        # a log whose numbers do not add up, and nothing else here would
        # notice. Recorded when seen, reported loudly.
        self.build_conflicts = []
        self.config_roster = {}
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
        # W16. Where a field row came from -- a struct member, a solved
        # offset, an Action layout -- and whether the receiver on the other
        # side of the target reads it. Keyed per (target, field), because
        # that is the granularity the claim is made at: the same field is
        # live at one target and dead at the other, which is the finding.
        self.field_from = {}
        self.field_read = {}
        self.field_cases = {}
        self.var_unplaced = {}
        # The Action layouts this binary has, and the ones a run named. A
        # layout never named is not a layout the tree lacks, and the two are
        # only distinguishable if both lists are kept.
        self.layout_roster = {}
        self.layout_refused = []
        self.layouts_seen = {}
        # (members bound, members in the union). A count of layouts without
        # this denominator reads as coverage of the union rather than of
        # part of it.
        self.layout_members = None
        self.var_roster = {}
        self.reader_roster = []
        # W16d. The TLV formats this binary has, and which of them a run
        # built items in. Four of the five are not what the element domains
        # walk, and their parsers sit behind flags W15 reports as off, so
        # "no cases" and "no such chain here" have to stay distinguishable.
        self.chain_roster = {}
        self.chains_seen = {}
        self.chain_cases = {}
        self.opsets = set()
        # Cases per (peer, target). Several peers share a target's case
        # counter, so each receives a different case -- a multi-peer run is N
        # times the stimulus, not N copies of it -- and this is the record
        # that says so rather than leaving it to be assumed.
        self.peers = {}
        self.lengths = {}
        self.truncated = 0
        self.short_mgmt = 0
        self.synth = 0
        self.chain_ops = {}
        self.last_case = {}
        # W13. What the RECEIVER read, which is a different question from
        # what the sender sent and is the one nothing here could answer
        # before. A case space that is being discarded at the door looks
        # exactly like one that is sweeping, and it looks like it in every
        # number above this line.
        self.reach_inventories = []
        self.reach_roster = {}
        self.reach_walkers = None
        self.reach_parsers = {}
        self.reach_attributed = 0
        self.reach_ambient = 0
        self.reach_short = 0
        self.reach_by_target = {}
        self.reach_sources = {}
        # The frames this run put on the air, most recent last. A receiver
        # cannot be told which case it is holding without the harness putting
        # something on the air that a real peer would not send, so the
        # correlation is done on the octets: the parser quotes the head of
        # the span it was handed and this is what that is looked for in.
        #
        # Shallow on purpose. A hwsim frame is parsed within microseconds of
        # being sent, so a window of a few cases is generous; a deep one
        # would start attributing a parse to a case from a second ago and
        # would do it most often exactly where the run is repetitive.
        self.recent = collections.deque(maxlen=16)
        self.sent_cases = {}
        # The weaker signal, for a victim that is not ours: whether it said
        # anything at all after a case. Counted here rather than inferred
        # later, because it is only meaningful while the case order is known.
        self.victim_lines = 0
        self.victim_after = {}
        self.victim_pending = None
        # W14. How many distinct source addresses one peer presented.
        # Counted as a SET, not as a count of changes: a run that cycles a
        # domain of four addresses twenty times has presented four
        # identities, and a figure that could not tell those apart would be
        # counting reconnections.
        self.source_addrs = {}
        self.source_who = {}
        self.source_changes = 0
        self.source_domain = None
        self.source_roster = {}
        self.sources_present = set()

    def feed(self, msg, source="subject"):
        """One decoded [fuzz] message.

        'source' is which process it came from. A run in the inverted
        direction has two that speak: the subject, which says what it sent,
        and the victim, which says what it read. Merging them would report
        the victim's parses of ordinary traffic as the subject's coverage.
        """
        kind = msg.get("msg")
        if kind == "reach_inventory":
            self.reach_inventories.append(
                (source, msg.get("daemon") or "?",
                 list(msg.get("parsers") or [])))
            for entry in msg.get("roster") or []:
                if isinstance(entry, dict) and entry.get("name"):
                    self.reach_roster[entry["name"]] = {
                        "fn": entry.get("fn"),
                        "guard": entry.get("guard"),
                    }
            walkers = msg.get("walkers")
            if isinstance(walkers, list) and len(walkers) == 2:
                self.reach_walkers = (walkers[0], walkers[1])
            return
        if kind == "reach":
            self._feed_reach(msg, source)
            return
        if kind == "inventory":
            targets = list(msg.get("targets") or [])
            daemon = msg.get("daemon") or "?"
            self.inventories.append((daemon, targets))
            # Kept for consumers that predate the per-process split: the union
            # is what the single field used to mean when there was one process.
            merged = []
            for _, ts in self.inventories:
                for t in ts:
                    if t not in merged:
                        merged.append(t)
            self.inventory = merged
            for entry in msg.get("roster") or []:
                if isinstance(entry, dict) and entry.get("name"):
                    self.roster[entry["name"]] = entry.get("guard")
            self.stages = list(msg.get("stages") or [])
            # W14. The domain the run was ASKED for, announced rather than
            # inferred from the changes -- because the interesting failure is
            # the one with no changes in it at all, and a report that only
            # counted what it saw would read that exactly like a run that
            # never asked.
            if msg.get("addrs") is not None:
                self.source_domain = msg["addrs"]
            self.sources_present.update(msg.get("sources") or [])
            for entry in msg.get("source_roster") or []:
                if isinstance(entry, dict) and entry.get("name"):
                    self.source_roster[entry["name"]] = entry.get("guard")
            # W15. What this binary was BUILT with, which is the one thing
            # above that is not a property of the run at all.
            if msg.get("config") is not None:
                cur = {"version": msg.get("version"),
                       "on": sorted(msg.get("config") or [])}
                prev = self.builds.get(daemon)
                if prev and prev != cur:
                    self.build_conflicts.append(daemon)
                self.builds[daemon] = cur
            for entry in msg.get("config_roster") or []:
                # Positional: [name, daemons, witness, stock, value]. The
                # encoding is fuzz_config.h's and is repeated there.
                if isinstance(entry, list) and len(entry) == 5:
                    self.config_roster[entry[0]] = {
                        "daemons": entry[1], "witness": entry[2],
                        "stock": entry[3], "value": entry[4]}
            # W16. The frame past the struct: which Action layouts this
            # binary has, which (category, code) keys it declined to guess
            # at, the field whose offset it solves for, and who reads what.
            for entry in msg.get("layouts") or []:
                # Positional: [member, cat, code, chain_at, nfields].
                if isinstance(entry, list) and len(entry) == 5:
                    self.layout_roster[(entry[1], entry[2])] = {
                        "member": entry[0], "chain_at": entry[3],
                        "nfields": entry[4]}
            if msg.get("layout_members") is not None:
                self.layout_members = (msg.get("layout_bound"),
                                       msg["layout_members"])
            for entry in msg.get("layouts_refused") or []:
                if entry not in self.layout_refused:
                    self.layout_refused.append(entry)
            for entry in msg.get("var_fields") or []:
                # [name, base, width, gap, [gap widths], exact]
                if isinstance(entry, list) and len(entry) == 6:
                    self.var_roster[entry[0]] = {
                        "base": entry[1], "width": entry[2],
                        "gap": entry[3], "gaps": entry[4],
                        "exact": entry[5]}
            for entry in msg.get("chains") or []:
                # [name, walker, hdr, id width, id le, len width, len le,
                #  members]
                if isinstance(entry, list) and len(entry) == 8:
                    self.chain_roster[entry[0]] = {
                        "walker": entry[1], "hdr": entry[2],
                        "id_width": entry[3], "id_le": entry[4],
                        "len_width": entry[5], "len_le": entry[6],
                        "members": entry[7]}
            for entry in msg.get("readers") or []:
                # [frame, role, fn, file, [fields]]
                if isinstance(entry, list) and len(entry) == 5 and \
                   entry not in self.reader_roster:
                    self.reader_roster.append(entry)
            return
        if kind == "claimed":
            # A label whose frames are always taken by a hook further up the
            # transmit path. Counted apart from "never reached", because the
            # two look identical in the targets table and mean opposite
            # things: one is a parser nothing is aimed at, the other is a
            # parser something more specific is aimed at.
            self.claimed[(msg.get("target"), msg.get("by"))] = \
                self.claimed.get((msg.get("target"), msg.get("by")), 0) + 1
            return
        if kind == "source":
            addr = msg.get("addr")
            who = msg.get("who") or "?"
            if addr:
                self.source_addrs[addr] = self.source_addrs.get(addr, 0) + 1
            self.source_who[who] = self.source_who.get(who, 0) + 1
            self.source_changes += 1
            if msg.get("of") is not None:
                self.source_domain = msg["of"]
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
            # The case number this target is on. 'progress' is emitted
            # immediately before the mutation and is the only message that
            # carries it, so a ledger that waited for the 'fuzz' message to
            # name its own case would file every one of them under None --
            # and would then report one case per target however many it sent.
            self.last_case[msg.get("target")] = msg.get("case_id")
            if msg.get("layout"):
                key = (msg["target"], msg["layout"])
                self.layouts_seen[key] = self.layouts_seen.get(key, 0) + 1
            if msg.get("var_unplaced"):
                # A field the solver could not place in THIS frame. A domain
                # that quietly is not there is the one thing this report is
                # not allowed to produce, so the frames it happened on are
                # counted rather than left as a silently shorter table.
                self.var_unplaced[msg["target"]] = \
                    self.var_unplaced.get(msg["target"], 0) + \
                    msg["var_unplaced"]
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
        # The window the receive side is correlated against, and the case
        # the victim's next log line is attributed to.
        case_id = msg.get("case_id")
        if case_id is None:
            case_id = self.last_case.get(target)
        self.recent.append((target, case_id, data))
        self.sent_cases.setdefault(target, set()).add(case_id)
        self.victim_pending = (target, case_id)
        kind = frame_kind(msg)
        for name, values in parse_frame(kind, data).items():
            for v in values:
                self.air.setdefault(name, Tally()).add(v, target)
        if msg.get("type") == "MUT_ELEM":
            # W16d. Which TLV format the item was built in. The identity
            # spaces overlap -- 0x1001 is a WPS attribute type and a DPP one
            # and neither is an element id -- so an item from another chain
            # must not be tallied against the element registries. It gets a
            # count of its own instead, which is also what says a chain was
            # reached at all.
            chain = msg.get("chain", "elem")
            self.chain_cases[chain] = self.chain_cases.get(chain, 0) + 1
            if chain != "elem":
                self.chains_seen.setdefault(chain, {})
                self.chains_seen[chain][msg.get("eid")] = \
                    self.chains_seen[chain].get(msg.get("eid"), 0) + 1
                self.synth = getattr(self, "synth", 0) + 1
                self.elem_dom[msg.get("dom", "elem")] = \
                    self.elem_dom.get(msg.get("dom", "elem"), 0) + 1
                return
            # The id the engine says it synthesised, not one re-derived by
            # parsing. A management frame's variable part is only an element
            # chain for some frames, so a parser that refuses a partial walk --
            # as it must -- would miss exactly the ids that were appended to a
            # frame it could not walk. The engine knows; it is asked.
            if msg.get("eid") is not None:
                self.air.setdefault(ELEM_ID, Tally()).add(msg["eid"], target)
            # A sub-registry member counts only when it is IN the frame. A
            # declared length below its width leaves it out, and counting it
            # anyway would report the one case of the length domain that
            # removes a member as a case of the identity domain that sends
            # one.
            present = msg.get("present")
            for key, reg in (("ext_id", ELEM_EXT_ID),
                             ("extlen_id", ELEM_EXTLEN_ID)):
                if msg.get(key) is not None and present != 0:
                    self.air.setdefault(reg, Tally()).add(msg[key], target)
                elif msg.get(key) is not None:
                    self.absent_sub = getattr(self, "absent_sub", 0) + 1
            self.synth = getattr(self, "synth", 0) + 1
            self.elem_dom[msg.get("dom", "elem")] = \
                self.elem_dom.get(msg.get("dom", "elem"), 0) + 1
            if msg.get("shape"):
                # (id, sub-registry member) pairs, not ids: exactly one id
                # selects each of the two wider shapes, so counting ids would
                # report "1 built" for a shape whose whole registry was swept
                # and for one that was emitted once.
                self.elem_shapes.setdefault(msg["shape"], set()).add(
                    (msg.get("eid"),
                     msg.get("ext_id", msg.get("extlen_id"))))
            # What the element said about itself, against what followed it.
            # The gap is the whole point of the declared-length domain, and
            # for a two-octet length field it is the largest gap any single
            # field in this engine can open.
            dec, body = msg.get("declared"), msg.get("body")
            if dec is not None and body is not None:
                shape = SHAPES.get(msg.get("eid"), SHAPES[None])
                honest = body + (shape["ext_width"] if shape["covers"] else 0)
                self.declared.setdefault(msg.get("shape") or shape["name"],
                                         set()).add(dec)
                if dec > honest:
                    self.lying = getattr(self, "lying", 0) + 1
            if msg.get("nfrag"):
                self.frags[msg["nfrag"]] = self.frags.get(msg["nfrag"], 0) + 1
                if msg.get("deflen") is not None:
                    self.deflen = max(getattr(self, "deflen", 0),
                                      msg["deflen"])
            if msg.get("depth"):
                self.depths[msg["depth"]] = \
                    self.depths.get(msg["depth"], 0) + 1

            # W11. What the engine aimed this length at, and whether it
            # landed. The minimum comes from the message rather than from
            # this file's copy of the table, for the same reason the element
            # id does: the engine knows what it aimed at, and a consumer that
            # re-derived it would be checking its own arithmetic.
            if msg.get("dom") in ("elem", "elen") and \
                    msg.get("min") is not None:
                key = (msg.get("reg"),
                       msg.get("ext_id", msg.get("extlen_id"))
                       if msg.get("reg") != "element id" else msg.get("eid"))
                if msg.get("min_known"):
                    self.aimed_cases += 1
                    self.aimed.setdefault(
                        key, (msg["min"], msg.get("min_rel"),
                              msg.get("min_expr")))
                    dec = msg.get("declared")
                    if dec is not None and \
                            msg["min"] - 2 <= dec <= msg["min"] + 8:
                        self.in_window += 1
                else:
                    self.unaimed.add(key)

            # W10's two invariants, taken from the engine's own reading of the
            # octets it emitted rather than re-derived here. Re-deriving would
            # be the same walk against the same shape table and would agree by
            # construction; what is wanted is the engine's answer, so that a
            # disagreement between the two is visible at all.
            walks, tail = msg.get("walks"), msg.get("tail")
            if walks is not None:
                self.walk_seen += 1
                if not walks:
                    self.unwalkable += 1
                    if not tail:
                        self.absorbed += 1
            pre, post = msg.get("pre"), msg.get("post")
            if pre is not None and post is not None and post < pre:
                self.chain_lost += 1
            if msg.get("copies_req") is not None:
                self.clamped += 1

        if msg.get("tail_mode") is not None:
            # W12. Counted here rather than inside one type's branch,
            # because both the element domains and the octet sweep pin the
            # span and only one of them is an element case.
            if msg["tail_mode"]:
                self.tail_cases += 1
            if msg.get("cut"):
                self.cut_cases += 1
                self.cut_octets += msg["cut"]

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
            self._feed_field_w16(msg, target)

        if msg.get("type") == "MUT_PATTERN":
            self.patterns[msg.get("field")] = \
                self.patterns.get(msg.get("field"), 0) + 1
            self._feed_field_w16(msg, target)

        if msg.get("type") == "MUT_CHAIN":
            self.chain_ops[msg.get("op")] = \
                self.chain_ops.get(msg.get("op"), 0) + 1

        if msg.get("type") == "MUT_LEN":
            # The length domain, tallied like any other: what was sent, not
            # whether it was any good.
            was, now = msg.get("was"), msg.get("len")
            if now is not None:
                self.lengths[now] = self.lengths.get(now, 0) + 1
                # Only a management frame has an 802.11 header for a length
                # to be under. W16 gave the EAPOL-Key targets a length
                # domain of their own, and counting those runts against a
                # header they do not carry would report a driver refusing
                # frames it never saw.
                if kind == "mgmt" and now < 24:
                    self.short_mgmt += 1
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

    def _feed_field_w16(self, msg, target):
        """Where this field row came from, and who reads it.

        Both travel on every field case rather than being looked up here: a
        log is read by someone who has the log and not this checkout, and a
        claim that cannot be read back out of the record is a claim the
        record does not make."""
        field = msg.get("field")
        if field is None:
            return
        if msg.get("from"):
            self.field_from[field] = msg["from"]
        read = msg.get("read")
        if read is not None:
            self.field_read[(target, field)] = read
        key = (target, field)
        self.field_cases[key] = self.field_cases.get(key, 0) + 1

    def _feed_reach(self, msg, source):
        """One parse, as the receiver reported it.

        Three facts come out of it and they are kept apart on purpose:

          the parser got a span at all      -- the hook fired
          it got through the whole span     -- the walk completed
          the span belongs to a case we sent -- it is OUR coverage

        The third is the one that is easy to lose. A victim parses ordinary
        traffic too, and a report that counted every parse would say the run
        was read perfectly while every mutated frame was being dropped at the
        door. So a parse is attributed to a case only when the octets it
        quotes are findable in a frame this run transmitted.
        """
        parser = msg.get("parser") or "?"
        try:
            span = bytes.fromhex(msg.get("span") or "")
        except ValueError:
            span = b""
        n = msg.get("n") or 0
        got = msg.get("got") or 0

        p = self.reach_parsers.setdefault(
            parser, {"parses": 0, "whole": 0, "got": 0, "offered": 0,
                     "attributed": 0, "stopped": 0, "enclosing": 0})
        p["parses"] += 1
        p["got"] += got
        p["offered"] += n
        if n and got >= n:
            p["whole"] += 1
        elif n:
            p["stopped"] += 1
        self.reach_sources[(source, parser)] = \
            self.reach_sources.get((source, parser), 0) + 1

        # A span too short to be a needle is not attributed to anything. It
        # is counted, because a run where most parses are unattributable is
        # a run whose reach figure means less than it looks like it does.
        if len(span) < REACH_NEEDLE:
            self.reach_short += 1
            return

        for target, case_id, frame in reversed(self.recent):
            hit, enclosing = span in frame, False
            if not hit:
                # OVERLAP, not containment, and the difference is the whole
                # reason this is a window scan rather than a `find`. A
                # station's association request is not the buffer the
                # station built: wpa_supplicant hands the driver its
                # elements, mac80211 puts its own in FRONT of them and a WMM
                # element AFTER them. What the run sent is 85 octets in the
                # middle of the 143 the AP walks, so neither end matches and
                # neither does the whole.
                hit = any(span[i:i + REACH_NEEDLE] in frame
                          for i in range(0, len(span) - REACH_NEEDLE + 1,
                                         REACH_STEP))
                enclosing = hit
            if not hit:
                continue
            self.reach_attributed += 1
            p["attributed"] += 1
            if enclosing:
                p["enclosing"] += 1
            t = self.reach_by_target.setdefault(
                target, {"read": set(), "through": set(), "parsers": {}})
            t["read"].add(case_id)
            if n and got >= n:
                t["through"].add(case_id)
            t["parsers"][parser] = t["parsers"].get(parser, 0) + 1
            return
        self.reach_ambient += 1

    def victim_line(self, text=None):
        """The victim printed something.

        This is the whole signal available where the victim is NOT ours: no
        counter, no roster, nothing on the air that was not already going
        there. It is attributed to the case in flight, and its limit is
        printed beside it rather than left to be inferred -- a line is not a
        parse, and a victim that logs on a timer would make every case look
        answered.
        """
        self.victim_lines += 1
        if not self.victim_pending:
            return
        target, case_id = self.victim_pending
        self.victim_after.setdefault(target, set()).add(case_id)

    def reach_states(self):
        """Every instrumented parser, and why it reported nothing.

        The same four states the transmit side uses, for the same reason:
        "this parser was never reached" and "this parser is not in the
        binary" are opposite facts and a two-state report buries the first
        in the second.
        """
        if not self.reach_inventories:
            return [(name, "unknown", "")
                    for name in sorted(self.reach_parsers)]
        present = set()
        for _, _, parsers in self.reach_inventories:
            present.update(parsers)
        universe = set(self.reach_roster) | present | set(self.reach_parsers)
        rows = []
        for name in sorted(universe):
            if name in self.reach_parsers:
                rows.append((name, "reached", ""))
            elif name in present:
                rows.append((name, "never", ""))
            else:
                guard = (self.reach_roster.get(name) or {}).get("guard")
                rows.append((name, "absent",
                             guard or "no build condition recorded"))
        order = {"never": 0, "reached": 1, "absent": 2, "unknown": 3}
        rows.sort(key=lambda r: (order[r[1]], r[0]))
        return rows

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
            "inventories": [{"daemon": d, "targets": t}
                            for d, t in self.inventories],
            "roster": dict(sorted(self.roster.items())),
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
            # W13. Kept in the campaign summary rather than only in the
            # printed report, because "this target was never read" is
            # exactly the fact a campaign unioning runs must not lose.
            "reach": {
                "measured": bool(self.reach_inventories),
                "walkers": list(self.reach_walkers)
                if self.reach_walkers else None,
                "parsers": {k: dict(v)
                            for k, v in sorted(self.reach_parsers.items())},
                "roster": dict(sorted(self.reach_roster.items())),
                "attributed": self.reach_attributed,
                "ambient": self.reach_ambient,
                "short": self.reach_short,
                "by_target": {
                    t: {"read": len(v["read"]),
                        "through": len(v["through"]),
                        "parsers": dict(sorted(v["parsers"].items()))}
                    for t, v in sorted(self.reach_by_target.items())},
                "never_read": sorted(
                    t for t, c in self.sent_cases.items()
                    if c and not self.reach_by_target.get(t)),
            },
            "sources": {
                "asked": self.source_domain,
                "changes": self.source_changes,
                "distinct": len(self.source_addrs),
                "addrs": dict(sorted(self.source_addrs.items())),
                "by_identity": dict(sorted(self.source_who.items())),
                "roster": dict(sorted(self.source_roster.items())),
            },
            "victim_lines": self.victim_lines,
            "victim_after": {t: len(v)
                             for t, v in sorted(self.victim_after.items())},
        }
        for key, src in (("built", self.built), ("air", self.air)):
            for name, tally in src.items():
                out[key][name] = sorted(tally.values)
        return out

    def stride_modulus(self):
        """The stride from this run's opset, or None.

        The opset reads v2/<hash>/<tier>/<stride>@<offset>. The stride is what
        turns a per-run fraction into a campaign one, and taking it from the
        log rather than from a constant here means a run recorded under a
        different case space reports its own number rather than this file's
        idea of one.
        """
        strides = set()
        for o in self.opsets:
            m = re.search(r"/(\d+)@\d+$", o)
            if m:
                strides.add(int(m.group(1)))
        return strides.pop() if len(strides) == 1 else None

    def target_states(self):
        """Every label this run could know about, and why it produced no case.

        Four answers, not two, because "no case for this target" has four
        causes and exactly one of them is a finding:

          reached       cases were sent.
          never         the label is in a running process and produced
                        nothing. This is the interesting one -- a hook that
                        exists, in a binary that ran, that the configuration
                        or the state machine never drove. B1 and B2.
          absent        the label exists in the tree but is in no process of
                        this run: either the build excluded it or the daemon
                        that carries it was not started. The guard says which.
          unknown       no inventory at all, so nothing can be told apart.

        Returns a list of (name, state, detail), ordered by state so the
        interesting rows are not buried in the uninteresting ones.
        """
        if not self.inventories and self.inventory is None:
            return [(n, "unknown", "") for n in sorted(t for t in self.seen if t)]

        compiled = set()
        for _, targets in self.inventories:
            compiled.update(targets)
        if not compiled and self.inventory:
            compiled = set(self.inventory)

        universe = set(self.roster) | compiled | {t for t in self.seen if t}
        rows = []
        for name in sorted(universe):
            if name in self.seen:
                rows.append((name, "reached", ""))
            elif name in compiled:
                rows.append((name, "never", ""))
            else:
                rows.append((name, "absent", self.roster.get(name) or
                             "no build condition recorded"))
        order = {"never": 0, "reached": 1, "absent": 2, "unknown": 3}
        rows.sort(key=lambda r: (order[r[1]], r[0]))
        return rows

    # W15. The compile-time axis.

    DAEMON_BIT = {"hostapd": 1, "wpa_supplicant": 2}

    def build_states(self, daemon):
        """One build against upstream's defaults: (on, added, dropped, blind).

        `added` and `dropped` are measured against the upstream defconfig
        bit in the roster, not against another run, because that is the
        baseline a finding's STRENGTH is measured in: a defect behind a flag
        upstream ships commented out is a weaker claim than one in a default
        build, and the run has to be able to say which it made.

        `dropped` counts only flags this binary could have reported. A stock
        flag that reaches no -D is not absent from the on-list because it is
        off -- it is absent because nothing could have put it there -- and
        counting it as dropped would be inventing a narrowing that may not
        exist.
        """
        b = self.builds.get(daemon)
        if not b:
            return None
        on = set(b["on"])
        bit = self.DAEMON_BIT.get(daemon, 0)
        tested = {n: e for n, e in self.config_roster.items()
                  if not bit or (e["daemons"] & bit)}
        blind = sorted(n for n, e in tested.items() if not (e["witness"] & bit))
        stock = {n for n, e in tested.items() if e["stock"] & bit}
        added = sorted(on - stock)
        dropped = sorted(n for n in stock
                         if n not in on and n not in set(blind))
        return {"on": sorted(on), "added": added, "dropped": dropped,
                "blind": blind, "tested": sorted(tested),
                "version": b.get("version")}

    def _report_chains(self, say):
        """W16d. The TLV formats this product has, and which were built in.

        W5b synthesised every item as `u8 id, u8 len, body` and inserted it
        into a flat chain. That is one of five formats here. Emitting an
        attribute under the wrong one is not a weaker case but a different
        one: the parser takes its length from octets the engine filled with
        body, the chain walks anyway, and the run reports a length domain it
        did not sweep.
        """
        if not self.chain_roster:
            return

        say("TLV CHAINS -- the shapes this product's walkers parse, and")
        say("which of them this run built items in")
        say("  %-6s %-24s %-30s %8s %7s"
            % ("chain", "walker", "format", "members", "cases"))
        for name, e in sorted(self.chain_roster.items()):
            seen = self.chains_seen.get(name, {})
            cases = self.chain_cases.get(name, 0)
            say("  %-6s %-24s %-30s %8d %7s"
                % (name, e["walker"],
                   "id u%d%s, len u%d%s, hdr %d"
                   % (e["id_width"] * 8,
                      "" if e["id_width"] == 1
                      else (" le" if e["id_le"] else " be"),
                      e["len_width"] * 8,
                      "" if e["len_width"] == 1
                      else (" le" if e["len_le"] else " be"),
                      e["hdr"]),
                   e["members"], cases if cases else "-"))
            if name != "elem" and seen:
                say("         %d of %d identity member(s) built"
                    % (len(seen), e["members"]))
        say()
        say("  A chain with no cases is not a chain this tree lacks. Four")
        say("  of the five are reached only through hooks whose parsers sit")
        say("  behind build flags -- which the BUILD section above reports")
        say("  separately, and which is the answer to 'why is this zero'.")
        say("  Each format's header size was measured from its walker's")
        say("  reads and checked against the minimum that same loop refuses")
        say("  to walk below: the same number, stated twice, by two")
        say("  different lines of one function.")
        say()

    def _report_past_struct(self, say):
        """W16. The frame past the end of the struct, and who reads it.

        Three things live out there on this product and the field model
        could not see any of them: the EAPOL-Key frame's one length field,
        which sits behind a gap the AKM sizes; the Action payload, which is
        keyed by a category the struct says nothing about; and the question
        of whether the receiver on the other side reads what was swept.

        The last of those is W13's acceptance argument at field granularity.
        A field driven through 65,536 values against a parser that never
        looks at those two octets is not weak coverage -- it is none, and it
        is reported in the same words as coverage unless something says so.
        """
        dead = {}
        unknown = 0
        for (target, field), read in sorted(self.field_read.items()):
            n = self.field_cases.get((target, field), 0)
            if read == 0:
                dead.setdefault(target, []).append((field, n))
            elif read < 0:
                unknown += n

        if not (dead or self.var_roster or self.layout_roster or
                self.layout_refused or unknown):
            return

        say("PAST THE STRUCT -- the fields the generated member table")
        say("could not see, and the receivers that will not read them")

        if self.var_roster:
            say()
            say("  A field whose OFFSET is solved for in each frame, the gap")
            say("  before it being as wide as the negotiated AKM says:")
            for name, e in sorted(self.var_roster.items()):
                say("    %-20s at %d + %s, %d octet(s), %s"
                    % (name, e["base"], e["gap"], e["width"],
                       "candidates %s" % ",".join(str(x) for x in e["gaps"])))
                if not e["exact"]:
                    say("      the tree can return a width this set does")
                    say("      not contain, so a frame the solver cannot")
                    say("      place is not necessarily a malformed one")
            if self.var_unplaced:
                for target, n in sorted(self.var_unplaced.items()):
                    say("    %-20s %d frame(s) the solver could not place"
                        % (target, n))
            else:
                say("    placed in every frame this run built")

        if self.layout_roster:
            used = {}
            for (target, member), n in self.layouts_seen.items():
                used[member] = used.get(member, 0) + n
            say()
            say("  Action layouts -- which union member a (category, code)")
            say("  selects, read off the tree's own dispatch:")
            say("    %-20s %-10s %-9s %s"
                % ("member", "cat/code", "chain at", "cases"))
            for (cat, code), e in sorted(self.layout_roster.items()):
                say("    %-20s %-10s %-9s %s"
                    % (e["member"], "%d/%s" % (cat, code if code >= 0
                                               else "*"),
                       e["chain_at"] if e["chain_at"] >= 0 else "none",
                       used.get(e["member"], 0) or "-"))
            say("    %d of %d named by this run. A layout never named is"
                % (len([e for e in self.layout_roster.values()
                        if used.get(e["member"])]), len(self.layout_roster)))
            say("    not a layout the tree lacks.")
            if self.layout_members:
                bound, total = self.layout_members
                say("    They cover %s of the union's %d members. The rest"
                    % (bound, total))
                say("    are members the tree's dispatch never names, and")
                say("    their frames keep the byte sweep -- which is a")
                say("    denominator, not a gap somebody forgot.")

        if self.layout_refused:
            say()
            say("  REFUSED -- a (category, code) more than one union member")
            say("  claims. The engine declines to guess, because the wrong")
            say("  layout writes real values at the wrong offsets under the")
            say("  right names:")
            for text in self.layout_refused:
                say("    %s" % text)

        if dead or unknown:
            say()
            say("  SWEPT AT A RECEIVER THAT DOES NOT READ IT")
            total = 0
            for target in sorted(dead):
                say("    %s" % target)
                for field, n in sorted(dead[target]):
                    total += n
                    say("      %-24s %4d case(s)" % (field, n))
            if dead:
                say("    %d case(s) in all, at the LADDER tier -- the edges"
                    % total)
                say("    of the domain and of where the frame was, and not")
                say("    the stride walk, which is 251 runs spent completing")
                say("    a domain nothing on the other side will look at.")
            if unknown:
                say("    %d case(s) went to fields where nothing here can"
                    % unknown)
                say("    say: shared code, or a frame kind with no receiver")
                say("    rostered. Three states, and this is the third.")

        if self.reader_roster:
            say()
            say("  The receive paths this claim rests on:")
            for frame, role, fn, path, reads in sorted(self.reader_roster):
                say("    %-6s %-4s %-20s %s" % (frame, role, fn, path))
                say("      reads %s" % (", ".join(reads) or "nothing"))
            say("  The read set is scoped to the FILE, not the function: a")
            say("  receiver hands the frame to helpers beside it, and a")
            say("  claim scoped to one function would call a field dead")
            say("  that a helper three lines down reads.")
        say()

    def _report_build(self, say):
        say("BUILD -- what existed to sweep")
        if not self.builds:
            say("  No build line in this log. Every number below says what")
            say("  the run reached; none of them says what the binaries")
            say("  CONTAINED, so a clean result here is indistinguishable")
            say("  from a result on code that was never compiled in.")
            say()
            return
        say("  A run built without a flag finds nothing in the code that")
        say("  flag would have compiled in, and says so in exactly the words")
        say("  it uses for code it swept and cleared. These are opposite")
        say("  results. This section is the only thing that tells them")
        say("  apart, and it is also what makes two runs comparable at all.")
        say()
        for daemon in sorted(self.builds):
            st = self.build_states(daemon)
            say("  %-16s %s" % (daemon, st["version"] or "no version"))
            if not self.config_roster:
                say("  %-16s %d flag(s) on. No roster in this log, so there"
                    % ("", len(st["on"])))
                say("  %-16s is no denominator and no upstream baseline."
                    % "")
                continue
            say("  %-16s %d flag(s) on, of %d this Makefile tests"
                % ("", len(st["on"]), len(st["tested"])))
            for label, names in (("NOT set by upstream defconfig",
                                  st["added"]),
                                 ("set by upstream defconfig and NOT here",
                                  st["dropped"])):
                chosen = [n for n in names if n.startswith("CONFIG_")]
                derived = [n for n in names if not n.startswith("CONFIG_")]
                say("  %-16s %d %s" % ("", len(chosen), label))
                for row in _wrap(chosen, 56):
                    say("  %-16s   %s" % ("", row))
                if derived:
                    say("  %-16s   and %d the Makefile derived from them"
                        % ("", len(derived)))
            say("  %-16s %d flag(s) it cannot report either way: they reach"
                % ("", len(st["blind"])))
            say("  %-16s   no -D and steer the link only." % "")
        say()
        if self.build_conflicts:
            say("  TWO BUILDS UNDER ONE NAME: %s announced more than one flag"
                % ", ".join(sorted(set(self.build_conflicts))))
            say("  set in this log. The numbers below union runs of code that")
            say("  was not the same code. Split the log, or say so.")
            say()
        self._report_absent_by_flag(say)
        blind = set()
        for daemon in self.builds:
            st = self.build_states(daemon)
            if st:
                blind.update(st["blind"])
        say("  THE LIMIT: this says what the BINARY was built with, which is")
        say("  not what a .config asked for -- the Makefile derives a great")
        say("  deal, and at least one option in this tree's own station")
        say("  config is off in the file and on in the build. It is also")
        say("  silent about %d flag(s) that reach no -D in the binary that"
            % len(blind))
        say("  tests them: for those, absent from the on-list means 'cannot")
        say("  tell', not 'off'.")
        say()

    def _report_absent_by_flag(self, say):
        """What the build cost this run, per roster, with the flag named.

        The rosters all have the same shape -- a name and the condition under
        which its call site exists -- so they are walked by one function.
        "Absent from this build" was already one of the four states each of
        them reports; this is the sentence that follows it.
        """
        rosters = []
        if self.roster:
            present = {t for _, ts in self.inventories for t in ts}
            rosters.append(("target", self.roster, present))
        if self.source_roster:
            rosters.append(("identity",
                            {k: v for k, v in self.source_roster.items()},
                            set(self.sources_present)))
        if self.reach_roster:
            present = {p for _, _, ps in self.reach_inventories for p in ps}
            rosters.append(("parser",
                            {k: v.get("guard")
                             for k, v in self.reach_roster.items()},
                            present))
        if not rosters:
            return

        by_flag, unexplained, unreadable = {}, [], []
        for kind, roster, present in rosters:
            for name in sorted(roster):
                if name in present:
                    continue
                guard = roster[name]
                explained = False
                for daemon in sorted(self.builds):
                    on = set(self.builds[daemon]["on"])
                    if guard_true(guard, on, daemon) is None:
                        continue
                    sets, _ = absent_because(guard, on, daemon)
                    for combo in sets:
                        by_flag.setdefault("+".join(combo), []).append(
                            (kind, name))
                        explained = True
                    if sets:
                        break
                if explained:
                    continue
                if guard and guard_true(guard, set(), "hostapd") is None:
                    unreadable.append((kind, name))
                else:
                    unexplained.append((kind, name))

        say("  WHAT THE BUILD COST THIS RUN -- the rosters' 'absent from")
        say("  this build' state, with the flag that would undo it. A name")
        say("  appears under every flag that ALONE would bring it back, so")
        say("  an entry behind a disjunction is listed more than once: four")
        say("  lines naming one identity are four ways to have it, not four")
        say("  losses.")
        if not by_flag:
            say("    Nothing in any roster is absent for a flag this build")
            say("    can name.")
        for flag in sorted(by_flag, key=lambda f: (-len(by_flag[f]), f)):
            items = sorted(set(by_flag[flag]))
            say("    %-34s %2d  %s" % (flag, len(items),
                                       " ".join(n for _, n in items[:4]) +
                                       (" ..." if len(items) > 4 else "")))
        if unexplained:
            say("    %-34s %2d  absent for a reason no flag explains: the"
                % ("", len(unexplained)))
            say("    %-34s     wrong daemon, or a roster entry with no"
                % "")
            say("    %-34s     build condition at all." % "")
        if unreadable:
            say("    %-34s %2d  guard this report cannot parse, so it says"
                % ("", len(unreadable)))
            say("    %-34s     nothing about them rather than guessing." % "")
        say()

    def _report_targets(self, say):
        rows = self.target_states()
        say("TARGETS")
        if not rows:
            say("  nothing announced and nothing reached.")
            say()
            return

        if rows[0][1] == "unknown":
            say("  no inventory message: cannot tell a target that does not")
            say("  exist from one that was never reached. Rebuild with the")
            say("  current src/common/fuzz.c.")
            for name, _, _ in rows:
                say("  %-28s reached" % name)
            say()
            return

        if self.inventories:
            say("  processes that announced hooks: %s"
                % ", ".join("%s (%d target%s)"
                            % (d, len(t), "" if len(t) == 1 else "s")
                            for d, t in self.inventories))
        counts = {}
        for _, state, _ in rows:
            counts[state] = counts.get(state, 0) + 1

        for name, state, detail in rows:
            by = sorted({b for (t, b), n in self.claimed.items()
                         if t == name and n})
            if state == "reached":
                say("  %-28s reached" % name)
            elif state == "never" and by:
                # Not a gap. Every frame this label would have taken was
                # taken by a hook further up the same transmit path, which
                # named it more precisely than the convergence point could.
                say("  %-28s claimed upstream by %s" % (name, ", ".join(by)))
                counts["claimed"] = counts.get("claimed", 0) + 1
                counts["never"] -= 1
                continue
            elif state == "never":
                say("  %-28s NEVER REACHED" % name)
            else:
                say("  %-28s absent from this run's binaries" % name)
                if detail:
                    say("  %-28s   %s" % ("", detail))

        say("  %d reached, %d never reached, %d absent%s"
            % (counts.get("reached", 0), counts.get("never", 0),
               counts.get("absent", 0),
               ", %d claimed upstream" % counts["claimed"]
               if counts.get("claimed") else ""))
        if counts.get("never"):
            say("  NEVER REACHED is the one worth reading: the hook is in a")
            say("  binary that ran and nothing drove it. Absent is a build or")
            say("  a topology that does not carry the target at all, which is")
            say("  not a gap in the sweep.")
        say()

    def source_states(self):
        """Every identity whose address this tree can vary, and why it did
        not. The same four states the transmit side uses."""
        if not self.source_roster and not self.sources_present:
            return [(w, "unknown", "") for w in sorted(self.source_who)]
        universe = (set(self.source_roster) | self.sources_present |
                    set(self.source_who))
        rows = []
        for name in sorted(universe):
            if name in self.source_who:
                rows.append((name, "varied", ""))
            elif name in self.sources_present:
                rows.append((name, "never", ""))
            else:
                rows.append((name, "absent",
                             self.source_roster.get(name) or
                             "no build condition recorded"))
        order = {"never": 0, "varied": 1, "absent": 2, "unknown": 3}
        rows.sort(key=lambda r: (order[r[1]], r[0]))
        return rows

    def _report_sources(self, say):
        """W14. How many identities one peer presented.

        The state that gates a second attempt on this product is keyed by
        address, not by radio, so one fixed address gets one attempt through
        per run and everything behind the second is unreachable however many
        cases run. This says whether the run had more than one.
        """
        if not self.source_domain and not self.source_changes:
            return

        say("SOURCE ADDRESSES -- how many identities one peer presented")
        asked = self.source_domain
        if asked:
            say("  asked for: %d (FUZZ_ADDRS)" % asked)

        if not self.source_changes:
            say("  AND NOT ONE ADDRESS EVER CHANGED.")
            say("  The domain is configured and nothing drove it. A station")
            say("  changes its address only where its configuration asks it")
            say("  to -- mac_addr= and rand_addr_lifetime= -- so this run")
            say("  presented ONE identity however many cases it sent, and")
            say("  every per-address table behind it saw a single peer.")
            say()
            return

        say("  changes: %d, distinct addresses presented: %d"
            % (self.source_changes, len(self.source_addrs)))
        if asked and len(self.source_addrs) > asked:
            say("  MORE than the domain asked for, which is not a fault:")
            say("  this domain varies octets 1..5 and leaves octet 0 to the")
            say("  caller's own picker. Where that picker randomises it, the")
            say("  identities multiply. Both numbers are printed rather than")
            say("  one of them being quietly reconciled with the other.")
        elif asked and len(self.source_addrs) < asked:
            say("  FEWER than the domain asked for: the run did not cycle")
            say("  far enough to present them all. The domain is the ask;")
            say("  this is what was delivered.")

        rows = self.source_states()
        for name, state, detail in rows:
            if state == "varied":
                say("  %-16s varied, %d change(s)"
                    % (name, self.source_who.get(name, 0)))
            elif state == "never":
                say("  %-16s NEVER VARIED" % name)
            elif state == "absent":
                say("  %-16s absent from this run's binaries" % name)
                say("  %-16s   %s" % ("", detail))
            else:
                say("  %-16s varied, but no inventory to place it in" % name)

        shown = sorted(self.source_addrs)[:8]
        say("  addresses: %s%s"
            % (", ".join(shown),
               ", ..." if len(self.source_addrs) > len(shown) else ""))
        say("  THE LIMIT: this is occupancy and eviction -- what the tables")
        say("  behind it are keyed on. It does not claim to exercise how")
        say("  they HASH: the values are a counter, so adjacent identities")
        say("  may land in adjacent buckets.")
        say("  THE PRICE: an address change takes the interface down and up,")
        say("  which costs a whole reconnect. This run: %d frame(s) over %d"
            % (self.frames, self.source_changes))
        say("  change(s). A run with the domain off sends several times more")
        say("  in the same minutes, so a case rate is NOT comparable across")
        say("  runs with different domains and a campaign unioning them has")
        say("  to say which it was.")
        say()

    def _report_reach(self, say):
        """W13. What the receiving parsers read, against what was sent.

        Every other section of this report is written from the transmit
        side. They are all true and none of them can tell a case space that
        is sweeping from one that is being discarded at the door, because
        from the transmit side those two look identical -- same frames, same
        counters, same green run.
        """
        measured = bool(self.reach_inventories or self.reach_parsers)
        if not measured and not self.victim_lines:
            return

        say("WHAT THE VICTIM READ -- reach, not correctness")
        if not measured:
            say("  NOT MEASURED. Nothing in this run reported what it read,")
            say("  so every number above is about what was SENT. Build the")
            say("  victim with CONFIG_FUZZ_REACH=y to tell a case space that")
            say("  is sweeping from one that is discarded at the door.")
        else:
            if self.reach_inventories:
                say("  processes reporting: %s"
                    % ", ".join("%s as %s (%d parser%s)"
                                % (d, src, len(p), "" if len(p) == 1 else "s")
                                for src, d, p in self.reach_inventories))
            if self.reach_walkers:
                total, hooked = self.reach_walkers
                say("  element walkers in the tree: %d, instrumented: %d"
                    % (total, hooked))
                if total > hooked:
                    say("    the other %d are NOT MEASURED. A reach figure is"
                        % (total - hooked))
                    say("    a claim about the walkers that report, and this")
                    say("    is how many of them there are.")

            rows = self.reach_states()
            say("  parser        parses    whole   stopped   attributed")
            for name, state, detail in rows:
                p = self.reach_parsers.get(name)
                if state == "reached" and p:
                    say("  %-12s %7d  %7d   %7d      %7d"
                        % (name, p["parses"], p["whole"], p["stopped"],
                           p["attributed"]))
                elif state == "never":
                    say("  %-12s NEVER REACHED" % name)
                elif state == "absent":
                    say("  %-12s absent from this run's binaries" % name)
                    say("  %-12s   %s" % ("", detail))
                else:
                    say("  %-12s reported, but no inventory to place it in"
                        % name)
            say("  parses attributed to a case this run sent: %d"
                % self.reach_attributed)
            say("    ambient (the receiver's ordinary traffic): %d"
                % self.reach_ambient)
            if self.reach_short:
                say("    span too short to attribute: %d"
                    % self.reach_short)
            enclosing = sum(p.get("enclosing", 0)
                            for p in self.reach_parsers.values())
            if enclosing:
                say("    of which the walker was handed MORE than this run")
                say("    sent: %d. The hook mutates the buffer the call site"
                    % enclosing)
                say("    built; what arrives can have octets around it that")
                say("    the sender never saw -- mac80211 builds a station's")
                say("    association request with its own elements first.")

            # Per target: sent, read, walked through. This is the column the
            # whole item exists for.
            if self.sent_cases:
                say()
                say("  per target        sent     read   through")
                dead = []
                for target in sorted(self.sent_cases):
                    sent = len(self.sent_cases[target])
                    t = self.reach_by_target.get(target)
                    read = len(t["read"]) if t else 0
                    through = len(t["through"]) if t else 0
                    say("  %-16s %6d  %7d  %8d" % (target, sent, read,
                                                   through))
                    if sent and not read:
                        dead.append((target, sent))
                if dead:
                    say()
                    say("  TARGETS WHOSE CASES WERE NEVER READ")
                    for target, sent in dead:
                        say("    %-16s %d case%s sent, 0 reached an"
                            " instrumented parser"
                            % (target, sent, "" if sent == 1 else "s"))
                    say("  This is a FAILURE and is printed as one. Until")
                    say("  this run there was no way to tell it apart from a")
                    say("  target that was working perfectly.")
                    say("  THE LIMIT: 'never read' means no INSTRUMENTED")
                    say("  parser read it. A target whose frames no hooked")
                    say("  walker handles reads zero here and is a gap in the")
                    say("  instrument, not in the sweep -- which is why the")
                    say("  walker count above is printed beside this one.")

        if self.victim_lines:
            say()
            say("  WITHOUT INSTRUMENTATION, the signal is what the victim")
            say("  said: %d line%s, after %d of %d case%s."
                % (self.victim_lines, "" if self.victim_lines == 1 else "s",
                   sum(len(v) for v in self.victim_after.values()),
                   sum(len(v) for v in self.sent_cases.values()),
                   "" if sum(len(v) for v in self.sent_cases.values()) == 1
                   else "s"))
            say("  THE LIMIT: a log line is not a parse. The victim logs on")
            say("  its own events too, so this counts ACTIVITY after a case,")
            say("  not acceptance of it. It is here because it is the only")
            say("  signal available where the victim is not ours to build.")
        say()

    def report(self, root, out=None):
        load_shapes(root)
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

        self._report_build(say)
        self._report_targets(say)
        self._report_reach(say)
        self._report_sources(say)

        if self.synth or self.chain_ops:
            say("SYNTHESIS -- elements this run put into frames")
            say("  %d element(s) synthesised and inserted" % self.synth)
            if self.elem_dom:
                say("  by domain: %s" % ", ".join(
                    "%s %d" % kv for kv in sorted(self.elem_dom.items())))
            if self.chain_ops:
                say("  chain shape changed: %s" % ", ".join(
                    "%s %d" % kv for kv in sorted(self.chain_ops.items())))
            say()

            say("  ELEMENT SHAPES -- an element's header is not always two")
            say("  octets, and an id built under the wrong one reports reach")
            say("  it did not have.")
            if SHAPES_FROM is None:
                say("  shape table: NOT READ. No checkout, so every id was")
                say("    walked as the two-octet shape. Ids with a wider")
                say("    header are walked wrong, and a chain containing one")
                say("    is refused rather than mis-tallied.")
            known = sorted({v["name"] for v in SHAPES.values()})
            for name in known:
                pairs = sorted(p for p in self.elem_shapes.get(name, ())
                               if p[0] is not None)
                if pairs:
                    say("  %-8s %4d distinct element(s) built: %s" %
                        (name, len(pairs),
                         " ".join("%d" % a if b is None else "%d/%d" % (a, b)
                                  for a, b in pairs[:6]) +
                         (" ..." if len(pairs) > 6 else "")))
                else:
                    say("  %-8s NOT BUILT this run. Every id that selects it"
                        % name)
                    say("  %-8s was built as some other shape, or not at all."
                        % "")
            if self.absent_sub:
                say("  %d case(s) declared a length too short to hold the"
                    % self.absent_sub)
                say("    sub-registry id they selected, so the member was not")
                say("    counted: the frame carried the shape without the id.")
            say()

            if self.declared:
                say("  DECLARED LENGTH -- what an element says about itself.")
                say("  %-8s %7s %8s %8s %8s" %
                    ("shape", "values", "min", "max", "domain"))
                for name in sorted(self.declared):
                    vals = self.declared[name]
                    width = next((v["len_width"] for v in SHAPES.values()
                                  if v["name"] == name), 1)
                    say("  %-8s %7d %8d %8d %8d"
                        % (name, len(vals), min(vals), max(vals), 1 << (8 *
                                                                       width)))
                say("  %d case(s) declared more than followed them." %
                    self.lying)
                say()

            if self.tail_cases:
                say("  THE SPAN UNDER TEST, LAST -- every parser on this")
                say("  product hands out pointers INTO the frame and copies")
                say("  nothing, so a consumer that reads one octet past its")
                say("  span reads the next element's id: same allocation,")
                say("  same page, no fault, and nothing for a crash oracle")
                say("  to see. This run pinned the span to the end of the")
                say("  frame, so an over-read leaves the frame instead.")
                say("  %6d case(s) ran in the tail case space" %
                    self.tail_cases)
                say("  %6d of them cut the frame to end at the span,"
                    % self.cut_cases)
                say("         dropping %d octet(s) in all" % self.cut_octets)
                say("  THE LIMIT: this makes the defect REACH past the")
                say("  buffer. It does not make it DETECTABLE. Whether a")
                say("  read past the frame is observable at all depends on")
                say("  the victim's allocator and on how its driver handed")
                say("  the frame up. Against a victim built from source it")
                say("  is the difference between a sanitizer that can fire")
                say("  and one that cannot, and that is the whole claim.")
                say("  THE PRICE: position in the chain is a domain, and")
                say("  pinning the span removes it. This run swept it at one")
                say("  value. The other case space sweeps it and does not")
                say("  pin; the opset says which run a case came from.")
                say()

            if self.aimed or self.unaimed:
                known = len(MINIMA)
                say("  AIMED AT THE MINIMUM -- a fixed-offset read behind a")
                say("  `len >= N` guard is wrong, where it is wrong at all,")
                say("  for lengths just above N and nowhere else. A length")
                say("  domain swept uniformly reaches that window once in")
                say("  251 runs; aimed, it reaches it in run 1.")
                if MINIMA_DENOM:
                    say("  %6d element id(s) have a guard this tree enforces,"
                        % known)
                    say("         against %d length field(s) in struct"
                        % MINIMA_DENOM[1])
                    say("         ieee802_11_elems -- the rest take what they")
                    say("         are given, so there is no window to aim at.")
                say("  %6d of them this run aimed a length at" % len(self.aimed))
                say("  %6d case(s) landed in the window, of %d aimed"
                    % (self.in_window, self.aimed_cases))
                say("  %6d id(s) with no guard were swept from 0 as before"
                    % len(self.unaimed))
                for key in sorted(self.aimed,
                                  key=lambda k: (str(k[0]), k[1] or 0))[:6]:
                    low, rel, expr = self.aimed[key]
                    say("         %-26s %-4s %-32s -> %d"
                        % ("%s %s" % (key[0], key[1]), rel or "?",
                           expr or "?", low))
                if len(self.aimed) > 6:
                    say("         ... and %d more" % (len(self.aimed) - 6))
                say("  The guard's own words, not just its number: a record")
                say("  that says 82 has lost the one fact that makes it")
                say("  re-aimable after upstream changes the struct.")
                say()

            if self.walk_seen:
                say("  ONE HOSTILE FIELD -- the rest of the message stays")
                say("  readable, because a walker that stops has not tested")
                say("  what was behind it. It has not sent it.")
                say("  %6d of %d case(s) stopped the walk at all"
                    % (self.unwalkable, self.walk_seen))
                if self.absorbed:
                    say("  %6d of those were NOT last in the chain, so the"
                        % self.absorbed)
                    say("         overrun was absorbed by the element after")
                    say("         them and the walker's bound was never")
                    say("         tested. THIS IS A BROKEN CASE SPACE.")
                else:
                    say("  %6d were not last in the chain -- every one of"
                        % 0)
                    say("         them went in at the end, which is the one")
                    say("         place an overrun can leave the buffer.")
                if self.chain_lost and self.tail_cases:
                    say("  %6d case(s) left the consumer able to read fewer"
                        % self.chain_lost)
                    say("         elements than the frame had. In the tail")
                    say("         case space that is the point, not a fault:")
                    say("         the frame is cut so the span under test is")
                    say("         last, and what was behind it was never")
                    say("         going to be the thing under test.")
                elif self.chain_lost:
                    say("  %6d case(s) left the consumer able to read FEWER"
                        % self.chain_lost)
                    say("         elements than the frame had before the")
                    say("         mutation. Those registry members went out")
                    say("         and the chain behind them did not.")
                else:
                    say("       0 case(s) cost the consumer an element it")
                    say("         could read before the mutation.")
                if self.clamped:
                    say("  %6d multiplicity case(s) were clamped to the"
                        % self.clamped)
                    say("         copies the headroom held; the count sent is")
                    say("         reported, not the count asked for.")
                say()

            if self.frags or self.depths:
                say("  BEYOND ONE ELEMENT")
                if self.frags:
                    say("  fragment runs: %s" % ", ".join(
                        "%d frag %d case(s)" % kv
                        for kv in sorted(self.frags.items())))
                    say("    longest defragmented body: %d octets, which no"
                        % self.deflen)
                    say("    length field in the frame states")
                else:
                    say("  fragment runs: NONE. The only route to an element")
                    say("    longer than its length field can say was not")
                    say("    taken this run.")
                if self.depths:
                    say("  nesting depth: %s" % ", ".join(
                        "depth %d, %d case(s)" % kv
                        for kv in sorted(self.depths.items())))
                else:
                    say("  nesting depth: 0 only. Every element went into the")
                    say("    top-level chain.")
                say()

        if self.fields or self.patterns:
            stride = self.stride_modulus()
            say("NAMED FIELDS -- what fraction of each field's domain this")
            say("run sent, and under which tier")
            say("  %-26s %-7s %7s %9s %8s %8s  %s"
                % ("field", "from", "cases", "domain", "this run",
                   "campaign", "tier"))
            tier_of = {}
            for tier, names in self.tiers.items():
                for name in names:
                    tier_of[name] = tier
            for name, n in sorted(self.fields.items()):
                width = self.widths.get(name)
                domain = (1 << (8 * width)) if width else None
                tier = tier_of.get(name, "")
                run_pct = "%6.2f%%" % (100.0 * n / domain) if domain else "?"
                # A STRIDE field is deferred, not sampled: case k is
                # (offset + k*stride) mod domain, so the union over every
                # stride offset is the whole domain and this run holds one
                # offset's share. Printing only the per-run figure reads as a
                # sampling rate, which is the one thing it is not.
                if tier == "STRIDE" and stride:
                    camp = "%6.2f%%" % min(100.0, 100.0 * n * stride / domain) \
                        if domain else "?"
                elif domain and n >= domain:
                    camp = "100.00%"
                else:
                    camp = run_pct
                say("  %-26s %-7s %7d %9s %8s %8s  %s"
                    % (name, self.field_from.get(name, "struct"), n,
                       domain if domain else "?", run_pct, camp, tier))
            for name, n in sorted(self.patterns.items()):
                say("  %-26s %-7s %7d %9s %8s %8s  PATTERN"
                    % (name, self.field_from.get(name, "struct"), n,
                       "fills", "-", "-"))
            say()
            say("  'this run' is cases over the field's own domain. 'campaign'")
            say("  is what the same case space reaches once every stride")
            say("  offset has run: %s"
                % ("%d runs at stride %d" % (stride, stride) if stride
                   else "unknown, no opset in this log"))
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
            say("  'from' is where the row came from: a member of a struct")
            say("  the generator could read, an offset SOLVED for in each")
            say("  frame, or the layout an Action frame's category selects.")
            say()

        self._report_past_struct(say)
        self._report_chains(say)

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
            short = self.short_mgmt
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
            for name, _, _ in registries_mod.REGISTRIES:
                b = len(self.built.get(name, Tally()).values)
                a = len(self.air.get(name, Tally()).values)
                if b or a:
                    say("  %-24s %5d as built %5d on air" % (name, b, a))
            return

        say("REGISTRIES                    defined members seen    distinct values")
        say("                            defined  as built  on air   as built  on air")
        for name, _, _ in registries_mod.REGISTRIES:
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

    load_shapes(root)
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
