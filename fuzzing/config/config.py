#!/usr/bin/env python3
"""The compile-time axis: the options that decide whether the code exists.

W2 enumerates the 591 options `hostapd/config_file.c` parses at run time.
Underneath it is a second registry nobody has enumerated: the Makefile flags
that decide whether a parser is in the binary at all. A sweep built without a
flag reports clean on code the binary never contained, and it reports it in
exactly the same words as a sweep that found nothing.

Four jobs, and the second is the one that makes the rest honest.

  the flag space  every CONFIG_*/NEED_* the two daemon Makefiles test, read
                  out of the Makefiles rather than listed by hand, including
                  the ones reached through `include`.

  the witness     whether a flag can be SEEN from C at all. A Makefile flag
                  is not a preprocessor macro: `CONFIG_WPS` turns into
                  `-DCONFIG_WPS` and a binary can report it, `CONFIG_EAP_MD5`
                  turns into `-DEAP_SERVER_MD5` and can only be reported
                  through that proxy, and `NEED_AES_CBC` turns into no -D at
                  all and steers the link only. The three are kept apart,
                  because a flag this cannot witness must be reported as
                  unreportable rather than as off -- off and invisible are
                  not the same answer and only one of them is true.

  the reasons     every setting on which `defconfig-fuzz` differs from
                  upstream `defconfig` carries a `# WHY` line. Turning a flag
                  on to reach code is a decision about what a finding MEANS:
                  a defect behind a flag that ships commented out is a weaker
                  claim than one in a default build. The delta is computed
                  from the two files; the prose is written by hand; --check
                  fails on a delta with no reason AND on a reason for
                  something that is no longer a delta, so neither side rots.

  the failures    three flags in this tree do not compile when turned on one
                  at a time, which reads as a broken checkout and costs an
                  afternoon. Each is recorded as its STRUCTURAL CAUSE -- a
                  member declared under one flag and read under another --
                  and the cause is re-derived from the tree, so the record
                  fails loudly when upstream fixes it instead of quietly
                  telling the next person a lie.

    python3 config.py [CHECKOUT]             the flag space, by daemon
    python3 config.py [CHECKOUT] --delta     defconfig vs defconfig-fuzz
    python3 config.py [CHECKOUT] --failures  the flags that do not compile
    python3 config.py [CHECKOUT] --check     compare against the tree, exit 1
    python3 config.py [CHECKOUT] --emit-c    write src/common/fuzz_config.h
"""

import os
import re
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "..", "ledger"))

import targets as targets_mod      # noqa: E402

HEADER = "src/common/fuzz_config.h"

# The two builds. Everything below is computed per daemon, because a flag can
# be tested by one Makefile and not the other, and because the two upstream
# defconfigs are different baselines.
DAEMONS = [("hostapd", "hostapd/Makefile",
            "hostapd/defconfig", "hostapd/defconfig-fuzz"),
           ("wpa_supplicant", "wpa_supplicant/Makefile",
            "wpa_supplicant/defconfig", "wpa_supplicant/defconfig-fuzz")]

DAEMON_BIT = {"hostapd": 1, "wpa_supplicant": 2}

# What counts as a compile-time flag. Everything else a Makefile tests --
# LIBS, CFLAGS, GITVER, TLS_FUNCS -- is build plumbing rather than a decision
# about which code exists.
FLAG_RE = re.compile(r"^(CONFIG|NEED)_[A-Z0-9_]+$")

WITNESS_SILENT, WITNESS_SELF, WITNESS_ALIAS = 0, 1, 2
WITNESS_NAME = {WITNESS_SILENT: "silent",
                WITNESS_SELF: "self",
                WITNESS_ALIAS: "alias"}

# A `# WHY` entry in defconfig-fuzz. One entry may cover several flags, so
# the file stays readable when a decision is one decision about nine options
# -- and when it is nine the list does not fit on a line, so the names may
# run on across following comment lines up to the colon.
WHY_START = re.compile(r"^#\s*WHY\s+(.*)$")
WHY_CONT = re.compile(r"^#\s+(.*)$")


# --------------------------------------------------------------------------
# The flag space, read out of the Makefiles.

_COND_RE = re.compile(r"^(ifdef|ifndef|ifeq|ifneq|else|endif)\b(.*)$")
_INCLUDE_RE = re.compile(r"^-?include\s+(\S+)\s*$")


def _makefile_lines(root, rel, seen=None, out=None):
    """Every line of a Makefile and of the Makefiles it includes.

    Only a literal include is followed. `include eap_proxy_$(CONFIG_EAP_PROXY).mak`
    names a file that depends on a flag's value, so there is no one file to
    read; it is left out, and left out is the safe direction -- a flag this
    never sees is reported as not in the space rather than as off.
    """
    seen = set() if seen is None else seen
    out = [] if out is None else out
    if rel in seen:
        return out
    seen.add(rel)
    path = os.path.join(root, rel)
    if not os.path.exists(path):
        return out
    base = os.path.dirname(rel)
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            t = line.split("#", 1)[0].strip()
            m = _INCLUDE_RE.match(t)
            if m and "$(" not in m.group(1):
                inc = os.path.normpath(os.path.join(base, m.group(1)))
                _makefile_lines(root, inc, seen, out)
                continue
            out.append((rel, t))
    return out


def scan_makefile(root, rel):
    """One daemon's Makefile as (flags tested, -D ownership, value tests).

    `owns` maps a flag to the -D names introduced under it and under nothing
    deeper, which is what makes a proxy macro attributable. The innermost
    positive condition owns the line: `-DEAP_SERVER_WSC` inside
    `ifdef CONFIG_WPS` belongs to CONFIG_WPS, not to whatever encloses it.
    """
    stack = []                   # [(flag or None, negated)]
    tested, value_tested = set(), set()
    owns, defined = {}, {}       # flag -> {-D}, -D -> {owner or None}
    free = set()                 # flags with a -D of their own name reached
                                 # under nothing but themselves
    for _, t in _makefile_lines(root, rel):
        m = _COND_RE.match(t)
        if m:
            kw, rest = m.group(1), m.group(2).strip()
            if kw in ("ifdef", "ifndef"):
                name = rest.split()[0] if rest.split() else None
                if name and FLAG_RE.match(name):
                    tested.add(name)
                else:
                    name = None
                stack.append((name, kw == "ifndef"))
            elif kw in ("ifeq", "ifneq"):
                for v in re.findall(r"\$\(([A-Za-z_][A-Za-z0-9_]*)\)", rest):
                    if FLAG_RE.match(v):
                        tested.add(v)
                        value_tested.add(v)
                # A value test is not an on/off condition, so nothing inside
                # it is owned by a flag.
                stack.append((None, False))
            elif kw == "else":
                if stack:
                    f, neg = stack[-1]
                    stack[-1] = (f, not neg)
            elif kw == "endif":
                if stack:
                    stack.pop()
            continue
        names = re.findall(r"-D([A-Za-z_][A-Za-z0-9_]*)", t)
        if not names:
            continue
        live = [f for f, neg in stack if f and not neg]
        owner = live[-1] if live else None
        # Reached under nothing but the owner's own ifdef. The distinction is
        # not academic: -DCONFIG_INTERNAL_LIBTOMMATH sits inside
        # `ifeq ($(CONFIG_CRYPTO), internal)`, so a .config can set that flag
        # and the compiler never hear of it -- and then the code it guards is
        # not in the binary, which is the question this whole header asks.
        bound = len(stack) == 1 and stack[0] == (owner, False)
        for d in names:
            defined.setdefault(d, set()).add(owner)
            if owner:
                owns.setdefault(owner, set()).add(d)
                if bound and d == owner:
                    free.add(owner)
    return {"tested": tested, "value_tested": value_tested,
            "owns": owns, "defined": defined, "free": free}


def owned_macros(root):
    """Every -D name either daemon's Makefile emits, with who introduces it.

    The compile line carries macros that LOOK like flags and are not --
    -DCONFIG_JSON comes out of an `ifdef NEED_JSON` block, and nothing tests
    a variable called CONFIG_JSON anywhere. Keeping the two apart is what
    stops the roster claiming a macro is a configuration option.
    """
    out = {}
    for _, mf, _, _ in DAEMONS:
        for d, who in scan_makefile(root, mf)["defined"].items():
            out.setdefault(d, set()).update(who)
    return out


def flag_space(root):
    """daemon -> scan, plus the witness each flag has in that daemon."""
    scans = {}
    for daemon, mf, _, _ in DAEMONS:
        scans[daemon] = scan_makefile(root, mf)

    # A proxy macro is a sound witness for a flag only if NOTHING ELSE
    # defines it, in either Makefile. Two owners means the macro says "one of
    # these two is on", which is not what the roster would be claiming.
    owners = {}
    for s in scans.values():
        for d, who in s["defined"].items():
            owners.setdefault(d, set()).update(who)

    for daemon, s in scans.items():
        wit = {}
        for f in sorted(s["tested"]):
            if f in s["owns"].get(f, ()):
                wit[f] = (WITNESS_SELF, f)
                continue
            proxy = sorted(d for d in s["owns"].get(f, ())
                           if owners.get(d) == {f})
            wit[f] = (WITNESS_ALIAS, proxy[0]) if proxy \
                else (WITNESS_SILENT, None)
        s["witness"] = wit
    return scans


def roster(root):
    """Every flag the tree tests, merged across the two daemons.

    name -> {daemons, witness, stock, value, wit: {daemon: (kind, macro)}}

    The per-daemon witness is kept rather than one best-of, and that is not
    fussiness: CONFIG_EAP_MD5 reaches hostapd as -DEAP_SERVER_MD5 and the
    supplicant as -DEAP_MD5. A roster that picked one of the two would make
    the other binary answer "off" for a flag it was built with, which is a
    WRONG answer where "cannot tell" would have been a true one.

    `daemons` and `witness` are bitmasks over the same two bits: tested by
    this Makefile, and reportable from this binary. A flag tested but not
    witnessed is the silent case. `value` marks a flag tested for its VALUE
    rather than for being set -- CONFIG_TLS=openssl is not a boolean, and an
    on/off report of it would be a wrong answer rather than a missing one.
    """
    scans = flag_space(root)
    stock = {d: settings(root, defc) for d, _, defc, _ in DAEMONS}
    out = {}
    for daemon, s in scans.items():
        bit = DAEMON_BIT[daemon]
        for f in s["tested"]:
            e = out.setdefault(f, {"daemons": 0, "witness": 0, "stock": 0,
                                   "value": False, "wit": {}})
            e["daemons"] |= bit
            kind, macro = s["witness"][f]
            e["wit"][daemon] = (kind, macro)
            if kind != WITNESS_SILENT:
                e["witness"] |= bit
            if f in s["value_tested"]:
                e["value"] = True
            if f in stock[daemon]:
                e["stock"] |= bit
    return out


def witness_guard(entry):
    """The #if under which a flag's name belongs in fuzz_config_on[].

    None when no binary can witness it. When both daemons witness it through
    the same macro the test is that macro alone; otherwise each daemon's
    witness is qualified by HOSTAPD, so one daemon's proxy cannot answer for
    the other's.
    """
    parts, macros = [], set()
    for daemon, _, _, _ in DAEMONS:
        kind, macro = entry["wit"].get(daemon, (WITNESS_SILENT, None))
        if kind == WITNESS_SILENT:
            continue
        macros.add(macro)
        parts.append((daemon, macro))
    if not parts:
        return None
    if len(parts) == 2 and len(macros) == 1:
        return "defined(%s)" % parts[0][1]
    return " || ".join(
        "(%sdefined(HOSTAPD) && defined(%s))"
        % ("" if daemon == "hostapd" else "!", macro)
        for daemon, macro in parts)


# --------------------------------------------------------------------------
# defconfig vs defconfig-fuzz.

_SET_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$")


def settings(root, rel):
    """The options a .config-shaped file actually sets.

    Commented-out lines are not settings: upstream's defconfig documents the
    whole space in comments and sets a fraction of it, and `just setting
    VARIABLE=n is not disabling that variable` is the file's own first
    paragraph, so a value is kept as written rather than interpreted.
    """
    out = {}
    path = os.path.join(root, rel)
    if not os.path.exists(path):
        return out
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            t = line.strip()
            if not t or t.startswith("#"):
                continue
            if "+=" in t:
                continue              # CFLAGS/LIBS plumbing, not an option
            m = _SET_RE.match(t)
            if m:
                out[m.group(1)] = m.group(2).strip()
    return out


def delta(root):
    """daemon -> {flag: (kind, upstream value, fuzz value)}.

    kind is 'added' (the fuzz build turns it on and upstream does not),
    'dropped' (upstream turns it on and the fuzz build does not) or 'changed'.
    Dropped is the direction that is easy to forget and the one that silently
    narrows what a run can claim to have covered.
    """
    out = {}
    for daemon, _, defc, fuzzc in DAEMONS:
        a, b = settings(root, defc), settings(root, fuzzc)
        d = {}
        for k in sorted(set(a) | set(b)):
            if a.get(k) == b.get(k):
                continue
            if k not in a:
                d[k] = ("added", None, b[k])
            elif k not in b:
                d[k] = ("dropped", a[k], None)
            else:
                d[k] = ("changed", a[k], b[k])
        out[daemon] = d
    return out


def reasons(root):
    """daemon -> {flag: reason}, from the `# WHY` lines in defconfig-fuzz."""
    out = {}
    for daemon, _, _, fuzzc in DAEMONS:
        got = {}
        path = os.path.join(root, fuzzc)
        if os.path.exists(path):
            lines = open(path, encoding="utf-8",
                         errors="replace").read().split("\n")
            i = 0
            while i < len(lines):
                m = WHY_START.match(lines[i].rstrip())
                if not m:
                    i += 1
                    continue
                text = m.group(1)
                # The names run up to the colon, and only up to it: a reason
                # that mentions another flag by name must not be read as
                # covering it.
                while ":" not in text and i + 1 < len(lines):
                    c = WHY_CONT.match(lines[i + 1].rstrip())
                    if not c:
                        break
                    i += 1
                    text += " " + c.group(1)
                if ":" not in text:
                    i += 1
                    continue
                # And the reason runs on too, up to the next WHY entry or
                # the first line that is not an indented comment. A reason
                # cut off at the end of its first line reads as a word and a
                # half, which is how the check for a real explanation came
                # to pass on "upstream ships".
                while i + 1 < len(lines):
                    nxt = lines[i + 1].rstrip()
                    if WHY_START.match(nxt):
                        break
                    c = WHY_CONT.match(nxt)
                    if not c:
                        break
                    i += 1
                    text += " " + c.group(1)
                names, reason = text.split(":", 1)
                for name in names.split():
                    got[name] = reason.strip()
                i += 1
        out[daemon] = got
    return out


def reason_gaps(root):
    """(missing, stale) -- deltas with no reason, reasons with no delta."""
    d, r = delta(root), reasons(root)
    missing, stale = [], []
    for daemon, _, _, _ in DAEMONS:
        for k in sorted(d[daemon]):
            if k not in r[daemon]:
                missing.append((daemon, k))
        for k in sorted(r[daemon]):
            if k not in d[daemon]:
                stale.append((daemon, k))
    return missing, stale


# --------------------------------------------------------------------------
# The flags that do not compile on their own.
#
# Each record is the STRUCTURAL CAUSE, not the error message: a member
# declared in `header` under some other flag's #ifdef and read in `reader`
# without it. Only the three coordinates are written down. The guard is
# derived from the header below, so when upstream fixes one of these the
# derivation stops finding a guard and --check fails, instead of this file
# going on telling the next person a flag is broken after it was repaired.

BUILD_FAILURES = [
    {"flag": "CONFIG_PASN",
     "reader": "src/pasn/pasn_initiator.c",
     "header": "src/pasn/pasn_common.h",
     "member": "uncompressed",
     "note": "turning PASN on alone does not build"},
    {"flag": "CONFIG_INTERWORKING",
     "reader": "wpa_supplicant/interworking.c",
     "header": "wpa_supplicant/config_ssid.h",
     "member": "roaming_consortium_selection",
     "note": "needs CONFIG_HS20 with it"},
    {"flag": "CONFIG_IEEE80211AX",
     "reader": "src/ap/ctrl_iface_ap.c",
     "header": "src/ap/ap_config.h",
     "member": "he_oper_chwidth",
     "note": "upstream defconfig does not build: AC+AX+BE are not separable"},
    {"flag": "CONFIG_IEEE80211BE",
     "reader": "src/ap/ctrl_iface_ap.c",
     "header": "src/ap/ap_config.h",
     "member": "eht_oper_chwidth",
     "note": "the same break, the other member"},
]


def _decl_guards(root, rel, member):
    """The conditions under which `member` is DECLARED in a header.

    A declaration, not a use: `#member;` at the end of a struct member line.
    Several declarations under different guards would mean the member exists
    in more than one shape, so every one found is returned and the caller
    decides.
    """
    path = os.path.join(root, rel)
    if not os.path.exists(path):
        return []
    src = open(path, encoding="utf-8", errors="replace").read()
    stripped = targets_mod.strip_comments(src)
    stack = targets_mod.guard_stack(stripped)
    # The file's own include guard wraps everything and conditions nothing.
    # Leaving it in would not break the test below -- it is never in force in
    # a .c -- but it would print as if it were a reason, and this record
    # exists to be read.
    m = re.search(r"^#\s*ifndef\s+(\w+)\s*$", stripped, re.M)
    include_guard = "!defined(%s)" % m.group(1) if m else None
    decl = re.compile(r"^\s*[A-Za-z_][\w \t\*]*\b%s\s*(\[[^\]]*\])?\s*;\s*$"
                      % re.escape(member))
    out = []
    for lineno, line in enumerate(stripped.split("\n"), 1):
        if decl.match(line):
            conds = [c for c in stack.get(lineno, []) if c != include_guard]
            out.append((lineno, conds))
    return out


def _read_lines(root, rel, member):
    """Where `member` is read, with the conditions in force at each read."""
    path = os.path.join(root, rel)
    if not os.path.exists(path):
        return []
    src = open(path, encoding="utf-8", errors="replace").read()
    stripped = targets_mod.strip_comments(src)
    stack = targets_mod.guard_stack(stripped)
    out = []
    for lineno, line in enumerate(stripped.split("\n"), 1):
        if re.search(r"(->|\.)\s*%s\b" % re.escape(member), line):
            out.append((lineno, list(stack.get(lineno, []))))
    return out


def failures(root):
    """The recorded build failures with their causes re-derived from the tree.

    Each comes back with `ok` set when the tree still has the shape the record
    describes: the member declared under at least one guard, and read at least
    once with that guard NOT in force. That second half is the failure -- a
    read under the same guard would compile.
    """
    out = []
    for rec in BUILD_FAILURES:
        r = dict(rec)
        decls = _decl_guards(root, rec["header"], rec["member"])
        r["decls"] = decls
        guards = sorted({c for _, conds in decls for c in conds})
        r["guards"] = guards
        reads = _read_lines(root, rec["reader"], rec["member"])
        unguarded = [(ln, conds) for ln, conds in reads
                     if not any(c in conds for c in guards)]
        r["reads"] = reads
        r["unguarded"] = unguarded
        r["ok"] = bool(decls) and bool(guards) and bool(unguarded)
        out.append(r)
    return out


# --------------------------------------------------------------------------
# The generated header.

def emit_c(root):
    tab = roster(root)
    names = sorted(tab)
    witnessed = [n for n in names if tab[n]["witness"]]
    out = []
    w = out.append
    w("/*")
    w(" * The compile-time flag space, and which of it this binary was")
    w(" * built with.")
    w(" *")
    w(" * GENERATED by fuzzing/config/config.py from the two daemon")
    w(" * Makefiles and the two upstream defconfigs. Do not edit:")
    w(" * regenerate with")
    w(" *")
    w(" *     python3 fuzzing/config/config.py . --emit-c \\")
    w(" *             > %s" % HEADER)
    w(" *")
    w(" * and check it has not gone stale with --check.")
    w(" *")
    w(" * Why a binary reports this at all: a run built without a flag")
    w(" * finds nothing in the code that flag would have compiled in, and")
    w(" * says so in exactly the words it would use for code it swept and")
    w(" * cleared. The two are opposite results. A report that cannot tell")
    w(" * them apart is the same failure as a target roster that cannot")
    w(" * tell 'absent from this build' from 'never reached', one level")
    w(" * down: not which call site exists, but which SOURCE FILE does.")
    w(" *")
    w(" * THE LIMIT, and it is why the roster carries a witness column: a")
    w(" * Makefile flag is not a preprocessor macro. Only a flag that")
    w(" * reaches the compiler as a -D of its own name can be seen from")
    w(" * here; one that only steers which objects are linked cannot, and")
    w(" * is reported as unwitnessable rather than as off.")
    w(" */")
    w("")
    w("#ifndef FUZZ_CONFIG_H")
    w("#define FUZZ_CONFIG_H")
    w("")
    w("/* Flags this binary was built with. Each entry is present only when")
    w(" * its witness macro is defined, so the array IS the answer -- there")
    w(" * is no run-time test and nothing to keep in step by hand. */")
    w("static const char * const fuzz_config_on[] = {")
    for n in names:
        guard = witness_guard(tab[n])
        if not guard:
            continue
        w("#if %s" % guard)
        w('\t"%s",' % n)
        w("#endif")
    w("\tNULL")
    w("};")
    w("")
    w("/* The denominator: every flag the two Makefiles test, and the")
    w(" * number of them a binary can report at all. */")
    w("#define FUZZ_CONFIG_FLAGS %d" % len(names))
    w("#define FUZZ_CONFIG_WITNESSED %d" % len(witnessed))
    w("")
    w("/* All three masks are over the same two bits: 1 hostapd, 2 the")
    w(" * supplicant.")
    w(" *")
    w(" * daemons: which Makefile tests the flag at all.")
    w(" * witness: which binary can REPORT it. A bit set in daemons and")
    w(" *          clear here is the silent case -- the flag steers that")
    w(" *          daemon's link and reaches no -D, so absent from")
    w(" *          fuzz_config_on[] does not mean off for it.")
    w(" * stock:   which upstream defconfig SETS it: the baseline a")
    w(" *          finding's strength is measured against, because behind")
    w(" *          a flag upstream ships off is a weaker claim than in a")
    w(" *          default build.")
    w(" * value:   the Makefile tests this one for its VALUE, not for being")
    w(" *          set, so on/off is the wrong question about it. */")
    w("struct fuzz_config_roster_entry {")
    w("\tconst char *name;")
    w("\tunsigned char daemons;")
    w("\tunsigned char witness;")
    w("\tunsigned char stock;")
    w("\tunsigned char value;")
    w("};")
    w("")
    w("static const struct fuzz_config_roster_entry fuzz_config_roster[] = {")
    for n in names:
        e = tab[n]
        w('\t{ "%s", %d, %d, %d, %d },'
          % (n, e["daemons"], e["witness"], e["stock"], 1 if e["value"] else 0))
    w("};")
    w("")
    w("#endif /* FUZZ_CONFIG_H */")
    return "\n".join(out) + "\n"


# --------------------------------------------------------------------------

def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    opts = [a for a in sys.argv[1:] if a.startswith("--")]
    root = args[0] if args else "."

    if "--emit-c" in opts:
        sys.stdout.write(emit_c(root))
        return 0

    tab = roster(root)

    if "--delta" in opts:
        d, r = delta(root), reasons(root)
        for daemon, _, defc, fuzzc in DAEMONS:
            print("%s: %s vs %s" % (daemon, defc, fuzzc))
            for k in sorted(d[daemon]):
                kind, a, b = d[daemon][k]
                why = r[daemon].get(k, "** NO REASON **")
                print("  %-8s %-34s %s" % (kind, k, why))
            print()
        return 0

    if "--failures" in opts:
        for f in failures(root):
            print("%s -- %s" % (f["flag"], f["note"]))
            print("  %s declares %s under: %s"
                  % (f["header"], f["member"],
                     ", ".join(f["guards"]) or "** NOTHING **"))
            print("  %s reads it unguarded at: %s"
                  % (f["reader"],
                     ", ".join(str(ln) for ln, _ in f["unguarded"])
                     or "** NOWHERE **"))
            print("  cause still in the tree: %s" % ("yes" if f["ok"] else "NO"))
            print()
        return 0

    if "--check" in opts:
        bad = 0
        path = os.path.join(root, HEADER)
        if not os.path.exists(path):
            print("MISSING %s -- regenerate with --emit-c" % HEADER)
            bad = 1
        else:
            have = open(path, encoding="utf-8").read()
            if have != emit_c(root):
                print("STALE %s -- regenerate with --emit-c" % HEADER)
                bad = 1
        missing, stale = reason_gaps(root)
        for daemon, k in missing:
            print("NO REASON  %s/%s differs from upstream defconfig and no "
                  "# WHY line says why" % (daemon, k))
            bad = 1
        for daemon, k in stale:
            print("STALE WHY  %s/%s has a reason but no longer differs from "
                  "upstream defconfig" % (daemon, k))
            bad = 1
        for f in failures(root):
            if not f["ok"]:
                print("STALE FAILURE  %s: %s no longer has the shape this "
                      "record describes in %s/%s -- re-check whether the "
                      "flag builds and update BUILD_FAILURES"
                      % (f["flag"], f["member"], f["header"], f["reader"]))
                bad = 1
        if bad:
            return 1
        wit = sum(1 for e in tab.values() if e["witness"])
        print("OK: %d compile-time flag(s), %d witnessable, header matches "
              "the tree" % (len(tab), wit))
        return 0

    def kinds(e):
        return sorted({WITNESS_NAME[k] for k, _ in e["wit"].values()})

    by = {}
    for n, e in sorted(tab.items()):
        for k in kinds(e):
            by.setdefault(k, []).append(n)
    print("%d compile-time flag(s) across the two Makefiles" % len(tab))
    for kind in ("self", "alias", "silent"):
        print("  %-7s %4d  (per daemon that tests it)" % (kind,
                                                          len(by.get(kind, []))))
    print("  %-7s %4d  flag(s) no binary can report at all"
          % ("blind", sum(1 for e in tab.values() if not e["witness"])))
    print()
    print("%-34s %-8s %-11s %-6s %s" % ("flag", "daemons", "witness", "stock",
                                        "macro"))
    for n, e in sorted(tab.items()):
        d = "".join(c for c, b in (("h", 1), ("s", 2)) if e["daemons"] & b)
        s = "".join(c for c, b in (("h", 1), ("s", 2)) if e["stock"] & b) or "-"
        macro = ",".join(sorted({m for _, m in e["wit"].values() if m}))
        print("%-34s %-8s %-11s %-6s %s"
              % (n, d, "/".join(kinds(e)), s, macro))
    return 0


if __name__ == "__main__":
    sys.exit(main())
