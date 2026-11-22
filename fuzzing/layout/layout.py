#!/usr/bin/env python3
"""The frame layout past the end of the struct, and who reads it.

W6a derives (offset, width, kind, order) from struct ieee80211_mgmt, struct
ieee802_1x_hdr and struct wpa_eapol_key, and refuses to invent anything the
structs do not say. That was the right call and it is still the right call. It
also means the model ends where each struct ends, and on this product three
important things live past that point. This generator is the three of them.

  THE VARIABLE FIELD.  struct wpa_eapol_key ends at key_id, and what follows
  it is three COMMENTS: a variable length MIC, a big-endian two-octet Key Data
  Length, and the key data that length counts. key_data_length is THE length
  field on the EAPOL-Key frame, the shape W6b's FIELD/LEN distinction was
  built for, and the one field of the frame that is unswept as a field. It
  cannot be another constant-offset row, because it sits at
  sizeof(struct wpa_eapol_key) + mic_len and mic_len comes from the negotiated
  AKM. A W2 axis moves a W6a offset, which no other field in the table does.

  The widths that gap can have are read out of wpa_mic_len() and the function
  it delegates to, so the engine solves for the offset at mutation time from
  a value it already has -- the frame's own length -- rather than being told.
  Where the solution is not unique the field is not swept and the message says
  so, which is a third answer and not a quiet 0.

  THE ACTION PAYLOAD.  W6a says it plainly: action.category is the only field
  an Action frame contributes, because the union that follows is keyed by
  category and nothing in the struct says which category selects which member.
  Every surface in the plan's section 8 is an Action frame, so that is nine
  protocols to which the field model contributes one octet each.

  The mapping is not invented here either. The tree dispatches on the category
  and then on the code after it, and the function that does so NAMES the union
  member in the same breath: a scope that sets or tests u.action.category
  against one constant and sets or tests the first member of u.action.u.M
  against another binds (category, code) to M. The binding is taken from the
  whole tree, and a key more than one member claims is refused rather than
  guessed -- which is what keeps a wrong layout, whose fields would be written
  at the wrong offsets under the right names, out of the table.

  WHO READS IT.  A field's domain is per TARGET, not per frame layout. The
  802.1X header's length field is a u16 -- 65,536 values, 270 a run -- and at
  sta-eapol, where the station transmits and the AP parses, the receiver
  provably never reads those two octets. Sweeping it there is not weak
  coverage, it is no coverage, and a run that counts it as covered is wrong in
  the direction this plan is about. So the receive paths are named, their
  reads are extracted, and every target carries the role that says which of
  them will see its frames.

  The read set is scoped to the FILE that holds the receive path rather than
  to the function, deliberately: a receiver hands the frame to helpers beside
  it, and a claim scoped to one function would call a field dead that a helper
  three lines down reads. Over-claiming reads loses a finding; under-claiming
  them states a falsehood, so the scope errs the first way.

    python3 layout.py [CHECKOUT]            list what was derived
    python3 layout.py [CHECKOUT] --emit-c   the generated header
    python3 layout.py [CHECKOUT] --check    compare against the header, exit 1
"""

import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "ledger"))

import fields as F                                        # noqa: E402
import targets as T                                       # noqa: E402

HEADER = "src/common/fuzz_layout.h"
DEFS_H = "src/common/ieee802_11_defs.h"
WPA_COMMON_H = "src/common/wpa_common.h"
SCAN_DIRS = ["src", "hostapd", "wpa_supplicant"]


class Drift(Exception):
    """A source no longer has the shape this extractor reads.

    Raised rather than worked around, for the reason registries.py gives: a
    fallback here produces a table that compiles and is wrong, and a wrong
    layout table is invisible -- it writes real values at the wrong offsets,
    under the right names, into every frame of the run."""


def read(root, rel):
    path = os.path.join(root, rel)
    if not os.path.isfile(path):
        raise Drift("%s: not in the checkout" % rel)
    with open(path, encoding="utf-8", errors="replace") as f:
        return f.read()


# ---------------------------------------------------------------------------
# W16a. The field past the end of struct wpa_eapol_key.
# ---------------------------------------------------------------------------
#
# The trailing comments ARE the declaration here, and that is worth saying out
# loud rather than relying on: --check fails when a member moves because a
# member has a type and a name this reader understands, and it fails when
# these three lines change only because the three lines are matched exactly.
# That is a weaker guarantee than the one the table above it has. A comment
# reworded upstream fails the check, which is the behaviour wanted; a comment
# DELETED upstream while the frame keeps the field would take the field out of
# the model and the run would report one domain fewer without saying why. So
# the count is asserted below as well: this tree has exactly one such field,
# and a tree with none fails rather than quietly shrinking.
TRAILING = [
    (re.compile(r"^variable length (.+?) field$"), "gap"),
    (re.compile(r"^(big endian|little endian) (\d+)-octet (.+?) field$"),
     "field"),
    (re.compile(r"^followed by (.+?) bytes of (.+)$"), "body"),
]

# What decides the width of a variable gap, named by the function that returns
# it. Declared by NAME and never by value: the literals come out of the tree,
# and a function that is gone fails the check instead of leaving the engine
# with a candidate set that is silently short.
GAP_WIDTH_FN = {
    "key_mic": ("src/common/wpa_common.c", ["wpa_mic_len",
                                            "rsn_mic_len_hash"]),
}


def _comment_lines(text):
    """The /* ... */ comments of a struct body, as single-line strings."""
    out = []
    for m in re.finditer(r"/\*(.*?)\*/", text, re.S):
        body = " ".join(m.group(1).split())
        out.append(body)
    return out


def _literal_returns(src, fn, followed=()):
    """(integers returned by fn, how many returns were not literals).

    A return of a function this extractor also reads is not an unknown: its
    own literals are in the set already. Anything else -- an arithmetic
    expression, a call to a function nobody here follows -- is counted, and
    the count is what makes the candidate set say whether it is complete.
    """
    body = _func(src, fn, fn)
    lits, other = [], 0
    for m in re.finditer(r"\breturn\b([^;]*);", body):
        text = m.group(1).strip()
        if re.match(r"^\d+$", text):
            lits.append(int(text))
            continue
        call = re.match(r"^(\w+)\s*\(", text)
        if call and call.group(1) in followed:
            continue
        if text:
            other += 1
    return lits, other


def var_fields(root):
    """[(name, base, width, big_endian, gap name, [gap widths], exact)].

    'base' is where the struct the generator CAN read ends. 'exact' is 1 when
    every return of the function that decides the gap reduced to a literal, so
    the candidate set is the whole of what this tree can produce.
    """
    src = F.strip_comments(read(root, WPA_COMMON_H))
    raw = read(root, WPA_COMMON_H)

    # The 802.1X header, then the key descriptor: the same two structs the
    # field table is built from, so 'base' cannot drift away from it.
    laid = F.eapol_fields(root)
    if not laid:
        raise Drift("%s: the EAPOL-Key structs no longer read" % WPA_COMMON_H)
    base = laid[-1][1] + laid[-1][2]

    body = F.struct_body(raw, "wpa_eapol_key")
    if body is None:
        raise Drift("%s: struct wpa_eapol_key is gone" % WPA_COMMON_H)
    # Everything after the last member's semicolon is the trailing comment
    # block. Taking it from the raw text rather than the comment-stripped one
    # is the point: here the comments are the declaration.
    tail = body[body.rfind(";") + 1:]
    lines = _comment_lines(tail)

    gap = field = None
    for text in lines:
        for rx, kind in TRAILING:
            m = rx.match(text)
            if not m:
                continue
            if kind == "gap" and gap is None:
                gap = m.group(1)
            elif kind == "field" and field is None:
                field = (m.group(3), int(m.group(2)),
                         1 if m.group(1) == "big endian" else 0)
            elif kind == "body":
                if field and m.group(1) != field[0]:
                    raise Drift(
                        "%s: the trailing comments say '%s' counts the body "
                        "but the length field is '%s'"
                        % (WPA_COMMON_H, m.group(1), field[0]))
    if not gap or not field:
        raise Drift(
            "%s: struct wpa_eapol_key's trailing comments no longer declare "
            "a variable gap and a length field; the frame's one length field "
            "would silently leave the model. Lines read: %r"
            % (WPA_COMMON_H, lines))

    slug = gap.lower().replace(" ", "_")
    rel, fns = GAP_WIDTH_FN.get(slug, (None, None))
    if rel is None:
        raise Drift("%s: nothing here says what decides the width of the "
                    "'%s' gap" % (WPA_COMMON_H, gap))
    csrc = F.strip_comments(read(root, rel))
    widths, inexact = set(), 0
    for fn in fns:
        lits, other = _literal_returns(csrc, fn, fns)
        widths.update(lits)
        inexact += other
    if not widths:
        raise Drift("%s: %s returns no literal width, so the gap before '%s' "
                    "cannot be solved for" % (rel, fns[0], field[0]))

    name = field[0].lower().replace(" ", "_")
    return [(name, base, field[1], field[2], slug,
             sorted(widths), 1 if not inexact else 0)]


# ---------------------------------------------------------------------------
# W16c. The Action frame's category-keyed body.
# ---------------------------------------------------------------------------

MEMBER_USE = re.compile(r"u\.action\.u\.(\w+)\.(\w+)")
CAT_LEFT = re.compile(r"u\.action\.category\s*(?:==|=|!=)\s*(\w+)")
CAT_RIGHT = re.compile(r"(\w+)\s*(?:==|!=)\s*[\w>\-\.\[\]]*u\.action\.category")


def _func(text, name, rel):
    """The body of a function DEFINITION, by brace matching from its '{'."""
    for m in re.finditer(r"\b%s\s*\(" % re.escape(name), text):
        depth, j = 1, m.end()
        while j < len(text) and depth:
            if text[j] == "(":
                depth += 1
            elif text[j] == ")":
                depth -= 1
            j += 1
        if depth:
            continue
        k = j
        while k < len(text) and text[k] in " \t\n":
            k += 1
        if k >= len(text) or text[k] != "{":
            continue                        # a call, or a prototype
        depth, i = 0, k
        while i < len(text):
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
                if depth == 0:
                    return text[k:i + 1]
            i += 1
        raise Drift("%s: %s() does not close" % (rel, name))
    raise Drift("%s: %s() is gone" % (rel, name))


def _bodies(src):
    """(name, body) for every function definition in a .c file."""
    out = []
    for m in re.finditer(r"(?m)^(\w[\w \t\*]*?)\b(\w+)\s*\([^;{]*?\)\s*\n?\{",
                         src):
        start = src.index("{", m.start())
        depth, i = 0, start
        while i < len(src):
            if src[i] == "{":
                depth += 1
            elif src[i] == "}":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        out.append((m.group(2), src[start:i + 1]))
    return out


def _scopes(body):
    """[(categories named, text)] -- the body, split at switch case labels.

    A switch on u.action.category gives each case label a scope of its own;
    what is left of the function is one scope holding whatever categories it
    names anywhere. Without the split, hostapd's handle_action() is one scope
    naming five categories and binds nothing -- which is safe but blind, and
    the dispatch is exactly where the mapping is written down.
    """
    out = []
    m = re.search(r"switch\s*\(\s*[\w>\-\.\[\]]*u\.action\.category\s*\)\s*\{",
                  body)
    if m:
        depth, i = 0, body.index("{", m.start())
        start = i
        while i < len(body):
            if body[i] == "{":
                depth += 1
            elif body[i] == "}":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        sw, body = body[start + 1:i], body[:start] + body[i + 1:]
        parts = re.split(r"\bcase\s+(\w+)\s*:", sw)
        for k in range(1, len(parts), 2):
            out.append(({parts[k]}, parts[k + 1]))
    cats = set(m.group(1) for m in CAT_LEFT.finditer(body))
    cats |= set(m.group(1) for m in CAT_RIGHT.finditer(body))
    out.append((set(c for c in cats if c.startswith("WLAN_ACTION")), body))
    return out


def action_members(root):
    """{member name: ([(field, width, kind, order)], chain offset or None)}.

    Offsets are from the Category octet, so a layout row reads the same
    whether the engine is holding a whole management frame or an Action body.
    """
    src = F.strip_comments(read(root, DEFS_H))
    consts = F.constants(root)
    top = F.struct_body(src, "ieee80211_mgmt")
    if top is None:
        raise Drift("%s: struct ieee80211_mgmt is gone" % DEFS_H)
    outer = [i for t, i in F.split_members(top)
             if i is not None and "union" in t]
    if len(outer) != 1:
        raise Drift("%s: struct ieee80211_mgmt no longer has one union of "
                    "frame bodies" % DEFS_H)

    action = None
    for text, inner in F.split_members(outer[0]):
        if inner is None:
            continue
        names = [n.strip() for n in text[text.rfind("}") + 1:]
                 .replace("STRUCT_PACKED", "").split(",") if n.strip()]
        if "action" in names:
            action = inner
    if action is None:
        raise Drift("%s: the frame-body union has no 'action' member" % DEFS_H)

    inner_union = [i for t, i in F.split_members(action)
                   if i is not None and "union" in t]
    if len(inner_union) != 1:
        raise Drift("%s: struct ieee80211_mgmt's action member is no longer "
                    "a category and one union" % DEFS_H)

    # The category octet is what precedes the union, and it is already a row
    # of the generated field table. Its width is taken from there rather than
    # assumed, so the two tables cannot disagree about where a layout starts.
    before, _ = F.member_fields(
        "".join(t + ";" for t, i in F.split_members(action) if i is None),
        consts)
    if not before or len(before) != 1 or before[0][1] != 1:
        raise Drift("%s: the Action body no longer begins with one octet of "
                    "category" % DEFS_H)
    base = 1

    out = {}
    for text, inner in F.split_members(inner_union[0]):
        if inner is None:
            continue
        names = [n.strip() for n in text[text.rfind("}") + 1:]
                 .replace("STRUCT_PACKED", "").split(",") if n.strip()]
        flds, flexible = F.member_fields(inner, consts)
        if flds is None:
            continue                        # a shape this reader cannot lay out
        laid, end = F.layout(flds, base)
        for n in names:
            out[n] = (laid, end if flexible else None)
    if not out:
        raise Drift("%s: no member of the Action union reads as a layout"
                    % DEFS_H)
    return out


def action_bindings(root):
    """{(category const, code const or None): {member: [(file, fn)]}}.

    Every scope in the tree that names one category contributes. A scope that
    names none, or more than one, contributes nothing: it is not evidence, and
    this table is the one place where a plausible wrong answer is worse than
    no answer at all.
    """
    members = action_members(root)
    first = {m: (flds[0][0] if flds else None)
             for m, (flds, _) in members.items()}
    out = {}
    for d in SCAN_DIRS:
        for dirpath, _, names in os.walk(os.path.join(root, d)):
            for name in sorted(names):
                if not name.endswith(".c"):
                    continue
                path = os.path.join(dirpath, name)
                rel = os.path.relpath(path, root).replace(os.sep, "/")
                with open(path, encoding="utf-8", errors="replace") as f:
                    src = F.strip_comments(f.read())
                if "u.action.u." not in src:
                    continue
                for fn, body in _bodies(src):
                    for cats, text in _scopes(body):
                        if len(cats) != 1:
                            continue
                        cat = list(cats)[0]
                        for mem in sorted(set(m.group(1) for m in
                                              MEMBER_USE.finditer(text))):
                            if mem not in members:
                                continue
                            codes = set()
                            f0 = first.get(mem)
                            if f0:
                                for m in re.finditer(
                                        r"u\.action\.u\.%s\.%s\s*(?:==|=)\s*"
                                        r"([A-Z][A-Z0-9_]*)"
                                        % (re.escape(mem), re.escape(f0)),
                                        text):
                                    codes.add(m.group(1))
                            for code in (sorted(codes) or [None]):
                                out.setdefault((cat, code), {}).setdefault(
                                    mem, []).append((rel, fn))
    return out


def _prefix_consistent(a, b):
    """True when the shorter layout is a prefix of the longer one."""
    for x, y in zip(a, b):
        if x[0] != y[0] or x[1] != y[1] or x[2] != y[2]:
            return False
    return True


def action_layouts(root):
    """([(cat, code or -1, member, fields, chain at or -1)], [refusals]).

    A key more than one member claims is resolved only when every claimant is
    a prefix of the longest: a layout that names more octets is a stronger
    claim and the shorter ones agree with it as far as they go. Anything else
    is refused and SAID, because a refusal that is not reported looks exactly
    like a category nobody uses.
    """
    members = action_members(root)
    bind = action_bindings(root)
    values = _constants(root)

    # A category's claimants, coded and uncoded together. An uncoded claim
    # says the member belongs to the category; it does NOT say the member is
    # what an unrecognised code of that category looks like. Reading it that
    # way filed every WNM frame under the one member that happened never to
    # be set from a constant, which is a wrong layout rather than a missing
    # one. So a fallback stands only where the category has exactly ONE
    # member in the whole tree -- a category with one layout.
    percat = {}
    for (cat_const, code_const), claims in bind.items():
        percat.setdefault(cat_const, set()).update(claims)

    # The other half of the same rule. A category with exactly one member in
    # the whole tree HAS a fallback, whether or not any scope happened to
    # name it without a code: one layout is the category's layout. Without
    # this, FST binds only the one code a builder sets from a constant and
    # every other FST frame falls back to the byte sweep for no reason the
    # tree states.
    for cat_const, claims in percat.items():
        if len(claims) == 1:
            bind.setdefault((cat_const, None), {}).setdefault(
                list(claims)[0], []).append(("(derived)",
                                             "one layout in this category"))

    rows, refused = [], []
    for (cat_const, code_const), claims in sorted(
            bind.items(), key=lambda kv: (kv[0][0], kv[0][1] or "")):
        if code_const is not None and \
           len(percat.get(cat_const, ())) == 1 and \
           set(claims) == percat[cat_const]:
            continue            # the fallback row above says the same thing
        if code_const is None and len(percat.get(cat_const, ())) > 1:
            refused.append((cat_const, code_const, sorted(claims),
                            "the category has %d layouts, so an uncoded "
                            "claim is not its fallback"
                            % len(percat[cat_const])))
            continue
        if cat_const not in values:
            refused.append((cat_const, code_const, sorted(claims),
                            "the category constant is gone"))
            continue
        if code_const is not None and code_const not in values:
            refused.append((cat_const, code_const, sorted(claims),
                            "the code constant is gone"))
            continue
        ordered = sorted(claims, key=lambda m: -len(members[m][0]))
        longest = members[ordered[0]][0]
        if not all(_prefix_consistent(members[m][0], longest)
                   for m in ordered):
            refused.append((cat_const, code_const, sorted(claims),
                            "the claimants disagree about the octets they "
                            "share"))
            continue
        chain = members[ordered[0]][1]
        rows.append((values[cat_const],
                     values[code_const] if code_const is not None else -1,
                     ordered[0], longest,
                     chain if chain is not None else -1,
                     cat_const, code_const))

    # Most specific first, so the lookup takes the first row whose stated
    # fields match -- the same precedence the Action label table has, and for
    # the same reason.
    rows.sort(key=lambda r: (r[0], 0 if r[1] >= 0 else 1, r[1]))
    return rows, refused


def _constants(root):
    """Integer #defines and plain enum members of ieee802_11_defs.h.

    An Action code is a #define in some protocols and an enum member in
    others -- WNM_SLEEP_MODE_REQ is a define, FST_ACTION_SETUP_REQUEST is an
    enum -- and a reader that saw only one of the two would bind half the
    layouts and refuse the rest for no reason it could state.
    """
    src = F.strip_comments(read(root, DEFS_H))
    out = {}
    for m in re.finditer(r"(?m)^#define\s+([A-Z][A-Z0-9_]*)\s+"
                         r"(0x[0-9a-fA-F]+|\d+)\s*$", src):
        out.setdefault(m.group(1), int(m.group(2), 0))
    for m in re.finditer(r"enum\s+\w*\s*\{(.*?)\}\s*;", src, re.S):
        value = 0
        for item in m.group(1).split(","):
            item = item.strip()
            if not item:
                continue
            eq = item.split("=")
            name = eq[0].strip()
            if not re.match(r"^[A-Z][A-Z0-9_]*$", name):
                value += 1
                continue
            if len(eq) > 1:
                try:
                    value = int(eq[1].strip(), 0)
                except ValueError:
                    value += 1
                    continue
            out.setdefault(name, value)
            value += 1
    return out


# ---------------------------------------------------------------------------
# W16b. Which receiver reads which field.
# ---------------------------------------------------------------------------
#
# Declared by FUNCTION NAME and by nothing else. The names are checked against
# the tree and the reads are extracted from the file that holds them, so a
# receiver that is renamed or moved fails the check rather than silently
# reporting that nothing reads anything -- which would mark every field dead
# and read as a spectacular finding.
#
# 'role' is who runs this parser, and it is what pairs a receiver with a
# target: a frame a target transmits from the AP side is read by the station's
# parser and the other way round. The pairing is by role rather than by name
# so that a third role -- a mesh peer, which runs both -- is a case the table
# can express rather than one it gets wrong.
RECEIVERS = [
    ("eapol", "ap", "wpa_receive", "src/ap/wpa_auth.c"),
    ("eapol", "sta", "wpa_sm_rx_eapol", "src/rsn_supp/wpa.c"),
]

# Which role a hook site transmits as, by the directory it is in. Stated once,
# and every hooked file must match exactly one rule or the extraction fails --
# a file nobody classified would otherwise take the default and be wrong in
# whichever direction the default happened to be.
ROLE_DIRS = [
    ("src/ap/", "ap"),
    ("hostapd/", "ap"),
    ("src/rsn_supp/", "sta"),
    ("wpa_supplicant/", "sta"),
]

# A hook in neither tree: shared code that both daemons link, where the
# transmitting role is whichever daemon is running. 'either' is a real answer
# and the engine makes no reader claim for it.
ROLE_SHARED = ["src/common/", "src/wps/", "src/nan/", "src/fst/",
               "src/drivers/", "src/eap_peer/", "src/eap_server/",
               "src/p2p/", "src/radius/", "src/utils/", "src/crypto/",
               "src/eapol_auth/", "src/eapol_supp/", "src/l2_packet/",
               "src/tls/", "src/pae/"]


def _role_of(rel):
    for prefix, role in ROLE_DIRS:
        if rel.startswith(prefix):
            return role
    for prefix in ROLE_SHARED:
        if rel.startswith(prefix):
            return "either"
    raise Drift("%s: no rule here says which role transmits from this "
                "directory" % rel)


# Writing a member is not reading it, and the three ways this tree writes one
# are an assignment, a WPA_PUT_* of its address, and a copy into it. Each is
# recognised by what comes immediately BEFORE the member expression and only
# in the first argument position, so `os_memcpy(dst, key->key_nonce, len)` --
# which is a read -- is not caught by the rule that catches
# `os_memcpy(key->key_nonce, src, len)`.
#
# Over-claiming a read costs a finding; under-claiming one states a falsehood.
# So an occurrence this list does not recognise counts as a read.
WRITE_BEFORE = re.compile(
    r"(?:WPA_PUT_[A-Z0-9_]+|os_memcpy|os_memset|os_memmove)\s*\(\s*"
    r"(?:\([^()]*\)\s*)?$")


def field_reads(root, rel, names):
    """Which of 'names' the file at 'rel' READS through a -> dereference.

    Telling a read from a write is the whole measurement: src/ap/wpa_auth.c
    sets hdr->length on the way out and never looks at it on the way in.

    'names' are the members as the SOURCE spells them. The field table renames
    one of them -- struct wpa_eapol_key's own 'type' collides with the 802.1X
    header's and is emitted as 'desc_type' -- and looking the generated
    spelling up in the tree finds nothing, which would report a field that
    every receiver reads as one that none does. The mapping is taken from the
    structs rather than restated here.
    """
    src = F.strip_comments(read(root, rel))
    out = set()
    for name in names:
        for m in re.finditer(r"([A-Za-z_][\w.\[\]>-]*)->%s\b"
                             % re.escape(name), src):
            if re.match(r"\s*=[^=]", src[m.end():]):
                continue                    # an assignment
            if WRITE_BEFORE.search(src[max(0, m.start() - 48):m.start()]):
                continue                    # written through a helper
            out.add(name)
            break
    return out


def eapol_member_names(root):
    """[(generated name, the name the source gives it)], in table order."""
    raw = read(root, "src/common/eapol_common.h")
    key = read(root, WPA_COMMON_H)
    src_names = []
    for text, struct in ((raw, "ieee802_1x_hdr"), (key, "wpa_eapol_key")):
        body = F.struct_body(F.strip_comments(text), struct)
        if body is None:
            raise Drift("struct %s is gone" % struct)
        flds, _ = F.member_fields(body, F.constants(root))
        if flds is None:
            raise Drift("struct %s no longer reads as a flat layout" % struct)
        src_names += [n for n, _, _, _ in flds]
    gen = [n for n, _, _, _, _ in F.eapol_fields(root) or []]
    if len(gen) != len(src_names):
        raise Drift("the EAPOL-Key field table and the structs it comes from "
                    "no longer have the same members (%d vs %d)"
                    % (len(gen), len(src_names)))
    return list(zip(gen, src_names))


def readers(root):
    """[(frame, role, fn, file, [field names it reads])].

    A VARIABLE field is not looked for as a member, because it is not one:
    nothing dereferences key_data_length, the tree computes where it is. What
    locates it is the width of the gap before it, so a receive path that
    calls the function that returns that width can find the field and one
    that does not cannot. That is the test, and it comes from the same
    declaration that gave the candidate widths.
    """
    rows = []
    pairs = eapol_member_names(root)
    for frame, role, fn, rel in RECEIVERS:
        src = F.strip_comments(read(root, rel))
        _func(src, fn, rel)                 # exists, or Drift
        if frame != "eapol":
            raise Drift("no field set is known for frame kind '%s'" % frame)
        hit = field_reads(root, rel, [s for _, s in pairs])
        reads = sorted(g for g, s in pairs if s in hit)
        for name, _, _, _, gap, _, _ in var_fields(root):
            _, fns = GAP_WIDTH_FN[gap]
            if any(re.search(r"\b%s\s*\(" % re.escape(f), src)
                   for f in fns):
                reads.append(name)
        rows.append((frame, role, fn, rel, sorted(reads)))
    return rows


def target_roles(root):
    """[(target, role)] for every label the tree can emit."""
    out = []
    for name, files in sorted(T.extract(root).items()):
        roles = set(_role_of(rel) for rel in files)
        role = list(roles)[0] if len(roles) == 1 else "either"
        out.append((name, role))
    return out


# ---------------------------------------------------------------------------
# The generated header.
# ---------------------------------------------------------------------------

KIND_C = {"int": "FUZZ_FIELD_INT", "opaque": "FUZZ_FIELD_OPAQUE"}


def emit_c(root):
    var = var_fields(root)
    lay, refused = action_layouts(root)
    rds = readers(root)
    roles = target_roles(root)

    o = []
    w = o.append
    w("/*")
    w(" * The frame layout past the end of the struct, and who reads it.")
    w(" *")
    w(" * GENERATED by fuzzing/layout/layout.py. Do not edit:")
    w(" * regenerate with")
    w(" *")
    w(" *     python3 fuzzing/layout/layout.py . --emit-c \\")
    w(" *             > src/common/fuzz_layout.h")
    w(" *")
    w(" * and check it has not gone stale with --check.")
    w(" *")
    w(" * Three tables, because the field model stops where each")
    w(" * struct stops and the frame does not:")
    w(" *")
    w(" *   fuzz_var_fields[]      a field whose OFFSET is solved for")
    w(" *                          at mutation time, the gap before")
    w(" *                          it being as wide as the AKM says")
    w(" *   fuzz_action_layouts[]  which union member a (category,")
    w(" *                          code) selects, read off the tree's")
    w(" *                          own dispatch rather than invented")
    w(" *   fuzz_field_readers[]   which named fields the receiver on")
    w(" *                          the other side of a target reads,")
    w(" *                          so a dead domain can say it is one")
    w(" */")
    w("")
    w("#ifndef FUZZ_LAYOUT_H")
    w("#define FUZZ_LAYOUT_H")
    w("")

    # --- 16a -------------------------------------------------------------
    w("/*")
    w(" * W16a. struct wpa_eapol_key ends at key_id and the frame")
    w(" * does not. What follows is three comments, and they are the")
    w(" * declaration this table is built from -- which is a WEAKER")
    w(" * guarantee than the one the member table has, and is said")
    w(" * here rather than left to be discovered: --check fails when")
    w(" * a member moves because a member has a type and a name;")
    w(" * it fails on these only because the text is matched exactly.")
    w(" *")
    w(" * 'base' is where the struct ends. 'gap' is the field between")
    w(" * base and this one, whose width the negotiated AKM decides,")
    w(" * and 'gaps' is every width this tree's own wpa_mic_len() can")
    w(" * return. The engine solves for which one applies from the")
    w(" * frame's own length; where more than one fits, or none, the")
    w(" * field is not swept and the message says which it was.")
    w(" */")
    w("struct fuzz_var_field {")
    w("\tconst char *name;")
    w("\tenum fuzz_frame_type frame;")
    w("\tunsigned int base;")
    w("\tunsigned int width;")
    w("\tenum fuzz_field_kind kind;")
    w("\tint big_endian;")
    w("\tconst char *gap;")
    w("\tconst unsigned short *gaps;")
    w("\tunsigned int ngaps;")
    w("\t/* 1 when every return of the function that decides the gap")
    w("\t * reduced to a literal, so the candidate set is the whole")
    w("\t * of what this tree can produce. 0 means the solver may")
    w("\t * have no candidate for a frame that is perfectly valid. */")
    w("\tint gaps_exact;")
    w("};")
    w("")
    for name, base, width, be, gap, widths, exact in var:
        w("static const unsigned short fuzz_gaps_%s[] = { %s };"
          % (gap, ", ".join(str(x) for x in widths)))
    w("")
    w("static const struct fuzz_var_field fuzz_var_fields[] = {")
    for name, base, width, be, gap, widths, exact in var:
        w('\t{ "%s", FUZZ_TYPE_IEEE802_1X_HDR, %d, %d, %s, %d, "%s", '
          'fuzz_gaps_%s, %d, %d },'
          % (name, base, width,
             KIND_C["int" if width <= 2 else "opaque"], be, gap, gap,
             len(widths), exact))
    w("};")
    w("")

    # --- 16c -------------------------------------------------------------
    w("/*")
    w(" * W16c. An Action frame is one octet of field model and nine")
    w(" * protocols of opaque bytes, because the union after the")
    w(" * category says nothing about which member a category")
    w(" * selects. The tree says: a scope that tests or sets the")
    w(" * category against one constant, and the first member of a")
    w(" * union member against another, has named the pair. A key")
    w(" * that more than one member claims is refused rather than")
    w(" * guessed -- the wrong layout would write real values at the")
    w(" * wrong offsets under the right names.")
    w(" *")
    w(" * Offsets are from the CATEGORY octet, so one row reads the")
    w(" * same whether the engine holds a whole management frame or")
    w(" * an Action body. 'chain_at' is where the member's flexible")
    w(" * array begins, or -1 where the member has none -- which is a")
    w(" * frame with no element chain, and is not the same as a frame")
    w(" * whose chain this engine failed to find.")
    w(" */")
    w("struct fuzz_action_field {")
    w("\tconst char *name;")
    w("\tunsigned char off;")
    w("\tunsigned char width;")
    w("\tenum fuzz_field_kind kind;")
    w("\tunsigned char big_endian;")
    w("};")
    w("")
    w("struct fuzz_action_layout {")
    w("\tunsigned char cat;")
    w("\t/* The code after the category, or -1 for the category's")
    w("\t * fallback -- a category whose every member agrees. */")
    w("\tshort code;")
    w("\tconst char *member;")
    w("\tconst struct fuzz_action_field *fields;")
    w("\tunsigned char nfields;")
    w("\tshort chain_at;")
    w("};")
    w("")
    for cat, code, member, flds, chain, cc, dc in lay:
        w("static const struct fuzz_action_field fuzz_action_f_%s_%s[] = {"
          % (member, cat if code < 0 else "%d_%d" % (cat, code)))
        for fname, off, fwidth, fkind, forder in flds:
            w('\t{ "%s.%s", %d, %d, %s, %d },'
              % (member, fname, off, fwidth, KIND_C[fkind],
                 1 if forder == "be" else 0))
        w("};")
    w("")
    members = action_members(root)
    bound = sorted(set(r[2] for r in lay))
    w("/*")
    w(" * THE HONESTY FIGURE. %d layout(s) over %d of the union's %d"
      % (len(lay), len(bound), len(members)))
    w(" * members. A member nothing in the tree binds to a category is")
    w(" * not a member this engine has decided to skip -- it is one the")
    w(" * dispatch never names, and the frames under it keep the byte")
    w(" * sweep. Stated as a ratio for the reason the reach roster")
    w(" * states one: a count without its denominator reads as")
    w(" * coverage of the union rather than of part of it.")
    w(" */")
    w("#define FUZZ_ACTION_UNION_MEMBERS %d" % len(members))
    w("#define FUZZ_ACTION_MEMBERS_BOUND %d" % len(bound))
    w("")
    w("/* %d layout(s)%s */"
      % (len(lay), ", %d key(s) refused" % len(refused) if refused else ""))
    w("static const struct fuzz_action_layout fuzz_action_layouts[] = {")
    for cat, code, member, flds, chain, cc, dc in lay:
        w('\t/* %s%s */' % (cc, " / " + dc if dc else " (fallback)"))
        w('\t{ %d, %d, "%s", fuzz_action_f_%s_%s, %d, %d },'
          % (cat, code, member, member,
             cat if code < 0 else "%d_%d" % (cat, code), len(flds), chain))
    w("};")
    w("")
    w("/* Keys the tree claims twice. A refusal that is not reported")
    w(" * looks exactly like a category nobody uses, so it is named. */")
    w("#define FUZZ_ACTION_LAYOUTS_REFUSED %d" % len(refused))
    w("static const char * const fuzz_action_layouts_refused[] = {")
    for cc, dc, claims, why in refused:
        w('\t"%s/%s: %s -- %s",'
          % (cc, dc if dc else "*", "+".join(claims), why))
    w("\tNULL,")
    w("};")
    w("")

    # --- 16b -------------------------------------------------------------
    w("/*")
    w(" * W16b. A field's domain is per TARGET, not per frame layout.")
    w(" * The 802.1X header's length field is a u16, so 65,536 values")
    w(" * and 270 of them a run; at sta-eapol, where the station")
    w(" * transmits and the AP parses, the receiver never reads those")
    w(" * two octets. That is not weak coverage, it is none, and a")
    w(" * run that counts it as covered is wrong in the direction")
    w(" * this whole plan is about.")
    w(" *")
    w(" * The read set is scoped to the FILE holding the receive")
    w(" * path, not to the function: a receiver hands the frame to")
    w(" * helpers beside it, and a claim scoped to one function would")
    w(" * call a field dead that a helper three lines down reads.")
    w(" * Over-claiming a read costs a finding; under-claiming one")
    w(" * states a falsehood, so the scope errs the first way.")
    w(" */")
    w("struct fuzz_field_reader {")
    w("\tconst char *frame;")
    w("\tconst char *role;")
    w("\tconst char *fn;")
    w("\tconst char *file;")
    w("\tconst char * const *reads;")
    w("};")
    w("")
    for frame, role, fn, rel, reads in rds:
        w("static const char * const fuzz_reads_%s_%s[] = {" % (frame, role))
        for name in reads:
            w('\t"%s",' % name)
        w("\tNULL,")
        w("};")
    w("")
    w("static const struct fuzz_field_reader fuzz_field_readers[] = {")
    for frame, role, fn, rel, reads in rds:
        w('\t{ "%s", "%s", "%s", "%s", fuzz_reads_%s_%s },'
          % (frame, role, fn, rel, frame, role))
    w("};")
    w("")
    w("/* Which role a target transmits AS, from the directory its")
    w(" * hook is in. 'either' is shared code, where the transmitting")
    w(" * role is whichever daemon is running -- a real answer, and")
    w(" * one the engine makes no reader claim for. */")
    w("struct fuzz_target_role {")
    w("\tconst char *target;")
    w("\tconst char *role;")
    w("};")
    w("")
    w("/* %d target(s) */" % len(roles))
    w("static const struct fuzz_target_role fuzz_target_roles[] = {")
    for name, role in roles:
        w('\t{ "%s", "%s" },' % (name, role))
    w("};")
    w("")
    w("#endif /* FUZZ_LAYOUT_H */")
    return "\n".join(o) + "\n"


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    root = os.path.abspath(args[0]) if args else os.getcwd()

    try:
        text = emit_c(root)
    except Drift as e:
        print("FAIL: %s" % e)
        return 1

    if "--emit-c" in sys.argv:
        sys.stdout.write(text)
        return 0

    path = os.path.join(root, HEADER)
    if "--check" in sys.argv:
        if not os.path.isfile(path):
            print("FAIL: %s does not exist" % HEADER)
            return 1
        with open(path, encoding="utf-8") as f:
            have = f.read()
        if have != text:
            print("FAIL: %s does not match the tree" % HEADER)
            print("Regenerate with: python3 fuzzing/layout/layout.py %s "
                  "--emit-c > %s" % (root, HEADER))
            return 1
        lay, refused = action_layouts(root)
        bound = len(set(r[2] for r in lay))
        print("OK: %d variable field(s), %d Action layout(s) over %d of %d "
              "union member(s) (%d refused), %d receiver(s), header matches "
              "the tree"
              % (len(var_fields(root)), len(lay), bound,
                 len(action_members(root)), len(refused),
                 len(readers(root))))
        return 0

    for name, base, width, be, gap, widths, exact in var_fields(root):
        print("var field  %-20s base=%-4d width=%d %s gap=%s in %s%s"
              % (name, base, width, "be" if be else "le", gap,
                 widths, "" if exact else "  (candidates incomplete)"))
    print()
    lay, refused = action_layouts(root)
    for cat, code, member, flds, chain, cc, dc in lay:
        print("action     cat=%-3d code=%-4s %-18s chain=%-4s %-34s %s/%s"
              % (cat, code if code >= 0 else "*", member,
                 chain if chain >= 0 else "-",
                 ",".join("%s@%d:%d" % (f[0], f[1], f[2]) for f in flds),
                 cc, dc or "*"))
    for cc, dc, claims, why in refused:
        print("REFUSED    %s/%s: %s -- %s"
              % (cc, dc if dc else "*", "+".join(claims), why))
    print()
    for frame, role, fn, rel, reads in readers(root):
        print("reader     %-6s %-5s %-18s %-26s reads %s"
              % (frame, role, fn, rel, ",".join(reads) or "-"))
    print()
    roles = target_roles(root)
    byrole = {}
    for name, role in roles:
        byrole[role] = byrole.get(role, 0) + 1
    print("target roles: %s" % dict(sorted(byrole.items())))
    return 0


if __name__ == "__main__":
    sys.exit(main())
