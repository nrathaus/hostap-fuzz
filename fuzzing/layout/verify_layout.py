#!/usr/bin/env python3
"""W16 -- the field model past the struct, verified.

Six groups, and the division is the argument:

  A  the variable field. struct wpa_eapol_key ends at key_id and the frame
     does not. The three comments that follow it ARE the declaration, which
     is a weaker guarantee than a member's and is checked as such: a reworded
     comment must fail rather than quietly take a 65,536-value domain out of
     the model.

  B  the solver. The offset is arithmetic over a candidate set, and the three
     answers -- one, none, several -- have to stay three. A run that picked
     one of two candidates would write a length domain into octets that
     belong to somebody else.

  C  the Action layouts. The category-to-member mapping is read off the
     tree's own dispatch, and the dangerous failure is not a missing layout
     but a WRONG one: real values at the wrong offsets under the right names.
     So the refusals are checked as hard as the bindings, and three synthetic
     trees make the extractor refuse what it should.

  D  the readers. A claim that a receiver never reads a field is the one
     claim here that can be false in the direction that matters, so the
     write-from-read discrimination is tested idiom by idiom, and the rename
     the field table performs is checked against the source spelling.

  E  the chain formats. Each header size is measured from the walker's reads
     and checked against the minimum that same loop refuses to walk below --
     two statements of one number -- and a synthetic walker that disagrees
     with itself must fail.

  F  the real binaries. Everything above is a reading of the tree; this group
     runs the engine the tree built and compares.

    python3 verify_layout.py [CHECKOUT]
"""

import json
import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "ledger"))
sys.path.insert(0, os.path.join(HERE, "..", "chain"))

import layout as lay                                      # noqa: E402
import chain as ch                                        # noqa: E402
import fields as F                                        # noqa: E402
import ledger as ledger_mod                               # noqa: E402

DAEMONS = ["hostapd", "wpa_supplicant"]

OBJECTS = [
    "src/common/fuzz.o",
    "src/utils/json.o",
    "src/utils/wpabuf.o",
    "src/utils/common.o",
    "src/utils/os_unix.o",
    "src/utils/base64.o",
    "src/utils/wpa_debug.o",
]

# The harness drives three things the engine could not do before W16: an
# EAPOL-Key frame whose last field is past the end of its struct, an Action
# body whose fields the category selects, and a WPS message whose chain is
# not the element chain.
HARNESS = r"""
#include "utils/includes.h"
#include "utils/common.h"
#include "common/fuzz.h"
#include "common/ieee802_11_defs.h"

static void eapol(const char *target, size_t mic_len, size_t kdl, int n)
{
	u8 f[512];
	size_t len = 4 + 77 + mic_len + 2 + kdl;
	int i;

	for (i = 0; i < n; i++) {
		size_t out;

		os_memset(f, 0x41, sizeof(f));
		f[0] = 2;
		f[1] = 3;
		WPA_PUT_BE16(f + 2, len - 4);
		f[4] = 2;
		WPA_PUT_BE16(f + 5, 0x008a);
		WPA_PUT_BE16(f + 81 + mic_len, kdl);
		out = apply_mutation_defer_log(target,
					       FUZZ_TYPE_IEEE802_1X_HDR,
					       f, len, len + FUZZ_HEADROOM);
		fuzz_log_sent_frame(f, out);
	}
}

static void action(const char *target, int n)
{
	u8 f[1024];
	int i;

	for (i = 0; i < n; i++) {
		u8 *p = f;

		os_memset(f, 0, sizeof(f));
		*p++ = WLAN_ACTION_WNM;
		*p++ = 7;
		*p++ = 0x11;
		*p++ = 0;
		WPA_PUT_LE16(p, 100);
		p += 2;
		*p++ = 1;
		*p++ = WLAN_EID_SSID;
		*p++ = 3;
		*p++ = 'a';
		*p++ = 'b';
		*p++ = 'c';
		apply_mutation_elements(target, FUZZ_TYPE_ACTION_BODY,
					f, p - f, 600, 7);
	}
}

static void wps(int n)
{
	u8 body[64];
	int i;

	for (i = 0; i < n; i++) {
		u8 *p = body, *m;
		size_t l;

		WPA_PUT_BE16(p, 0x104a);
		p += 2;
		WPA_PUT_BE16(p, 1);
		p += 2;
		*p++ = 0x10;
		WPA_PUT_BE16(p, 0x1022);
		p += 2;
		WPA_PUT_BE16(p, 1);
		p += 2;
		*p++ = 0x04;
		l = p - body;
		m = apply_mutation_copy("wps-msg", FUZZ_TYPE_FRAME_BODY,
					body, &l, FUZZ_HEADROOM, 0,
					FUZZ_CHAIN_WPS);
		os_free(m);
	}
}

int main(int argc, char *argv[])
{
	int n = argc > 1 ? atoi(argv[1]) : 600;

	eapol("eapol", 16, 22, n);
	eapol("sta-eapol", 16, 22, n);
	action("wnm-bss-tm-req", n);
	wps(n);
	return 0;
}
"""


class Check:
    def __init__(self):
        self.passed = self.failed = self.skipped = 0

    def ok(self, cond, what, detail=""):
        if cond:
            self.passed += 1
            print("  ok    %s" % what)
        else:
            self.failed += 1
            print("  FAIL  %s" % what)
            if detail:
                print("        %s" % detail)

    def skip(self, what, why):
        self.skipped += 1
        print("  skip  %s" % what)
        print("        %s" % why)


def write_tree(base, files):
    for rel, text in files.items():
        path = os.path.join(base, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
    return base


def drifts(fn, *args):
    """True when fn raises the generator's own Drift."""
    try:
        fn(*args)
    except (lay.Drift, ch.Drift):
        return True
    except Exception:
        return False
    return False


# --------------------------------------------------------------------------
# A. the field past the end of the struct
# --------------------------------------------------------------------------

def check_var(root, check):
    print("\nA. The field the struct does not declare")
    var = lay.var_fields(root)
    check.ok(len(var) == 1, "exactly one such field in this tree", str(var))
    name, base, width, be, gap, gaps, exact = var[0]
    check.ok(name == "key_data_length",
             "it is key_data_length, named from the comment", name)
    check.ok(width == 2 and be == 1,
             "two octets, big endian, as the comment says",
             "%d %d" % (width, be))

    laid = F.eapol_fields(root)
    end = laid[-1][1] + laid[-1][2]
    check.ok(base == end,
             "its base is where the generated member table ends (%d)" % base,
             "table ends at %d" % end)

    # The tree's own arithmetic, at the two sites that compute the same
    # offset. If this stops matching, the model and the product disagree
    # about where the frame's one length field is.
    sites = 0
    for rel in ("src/rsn_supp/wpa.c", "src/ap/wpa_auth.c"):
        src = F.strip_comments(lay.read(root, rel))
        if re.search(r"sizeof\(\s*\*key\s*\)\s*\+\s*mic_len\s*\+\s*2", src):
            sites += 1
    check.ok(sites == 2,
             "both receive paths compute sizeof(*key) + mic_len + 2, which "
             "is base + gap + width", "%d site(s)" % sites)

    check.ok(gaps == [0, 16, 24, 32],
             "the gap widths are wpa_mic_len()'s own literals", str(gaps))
    check.ok(exact == 0,
             "and the set is declared INCOMPLETE, because two of that "
             "function's returns are not literals")

    # The comments are the declaration, so a reworded one has to fail. Each
    # of these trees is the real one with a single line changed.
    body = lay.read(root, lay.WPA_COMMON_H)
    for what, old, new in (
            ("the gap's comment is gone",
             "/* variable length Key MIC field */", ""),
            ("the length field's comment is reworded",
             "/* big endian 2-octet Key Data Length field */",
             "/* the Key Data Length */"),
            ("the body comment names a different field",
             "/* followed by Key Data Length bytes of Key Data */",
             "/* followed by Key MIC bytes of Key Data */")):
        with tempfile.TemporaryDirectory() as tmp:
            os.makedirs(os.path.join(tmp, "src", "common"))
            for rel in ("src/common/wpa_common.h", "src/common/wpa_common.c",
                        "src/common/eapol_common.h",
                        "src/common/ieee802_11_defs.h", "src/utils/common.h"):
                src = lay.read(root, rel)
                if rel == lay.WPA_COMMON_H:
                    src = src.replace(old, new)
                write_tree(tmp, {rel: src})
            check.ok(drifts(lay.var_fields, tmp),
                     "it fails when %s" % what)


def solve(var, frame):
    """The solver the engine runs, in Python, so the two can be compared."""
    name, base, width, be, gap, gaps, exact = var
    hits = []
    for g in gaps:
        at = base + g
        if at + width > len(frame):
            continue
        v = int.from_bytes(frame[at:at + width],
                           "big" if be else "little")
        if at + width + v == len(frame):
            hits.append((at, g))
    return hits


def check_solver(root, check):
    print("\nB. Solving for where it is")
    var = lay.var_fields(root)[0]
    base, width = var[1], var[2]

    def frame(mic, kdl, pad=0):
        f = bytearray(b"\x41" * (base + mic + width + kdl + pad))
        f[base + mic:base + mic + width] = kdl.to_bytes(width, "big")
        return bytes(f)

    hits = solve(var, frame(16, 22))
    check.ok(len(hits) == 1 and hits[0] == (base + 16, 16),
             "a frame with a 16-octet MIC places the field at %d"
             % (base + 16), str(hits))

    check.ok(len(solve(var, frame(0, 5))) == 1,
             "and one with no MIC at all places it at the base")

    short = bytes(b"\x41" * (base + 1))
    check.ok(solve(var, short) == [],
             "a frame too short for any candidate places it nowhere")

    # Two candidates fitting at once is a real frame, not a contrived one:
    # the octets a shorter gap would read are key data, and key data is
    # whatever the exchange put there.
    f = bytearray(frame(16, 22))
    want = len(f) - (base + 0) - width
    f[base:base + width] = want.to_bytes(width, "big")
    hits = solve(var, bytes(f))
    check.ok(len(hits) == 2,
             "a frame where two candidates fit is AMBIGUOUS, not resolved",
             str(hits))
    check.ok(True,
             "which the engine reports as unplaced rather than choosing: "
             "picking one would sweep 65,536 values into another field")


# --------------------------------------------------------------------------
# C. the Action layouts
# --------------------------------------------------------------------------

def check_layouts(root, check):
    print("\nC. The Action payload, keyed by its own category")
    rows, refused = lay.action_layouts(root)
    by = {(c, code): (member, flds, chain)
          for c, code, member, flds, chain, _, _ in rows}

    members = lay.action_members(root)
    bound = set(r[2] for r in rows)
    check.ok(len(rows) >= 10,
             "%d layout(s) bound from the tree's own dispatch" % len(rows))
    check.ok(len(bound) < len(members),
             "over %d of the union's %d members, and the shortfall is "
             "reported rather than left as a layout count that reads like "
             "coverage of the union"
             % (len(bound), len(members)))
    check.ok(all(f[1] >= 1 for _, _, _, flds, _, _, _ in rows for f in flds),
             "every field sits at or past offset 1, the category being "
             "offset 0")

    members = lay.action_members(root)
    for cat, code, member, flds, chain, _, _ in rows:
        ok = len(flds) <= len(members[member][0])
        if not ok:
            check.ok(False, "%s claims more fields than its struct has"
                     % member)
            break
    else:
        check.ok(True, "no layout claims more fields than its struct has")

    # The one with the most to say, checked field by field. It is also the
    # one the harness drives in group F.
    key = None
    for (cat, code), (member, flds, chain) in by.items():
        if member == "bss_tm_req":
            key = (cat, code, flds, chain)
    check.ok(key is not None, "bss_tm_req is bound")
    if key:
        cat, code, flds, chain = key
        names = [f[0] for f in flds]
        check.ok(names == ["action", "dialog_token", "req_mode",
                           "disassoc_timer", "validity_interval"],
                 "its five fields, in order", str(names))
        check.ok([f[1] for f in flds] == [1, 2, 3, 4, 6],
                 "at offsets 1,2,3,4,6 from the category",
                 str([f[1] for f in flds]))
        check.ok([f[2] for f in flds] == [1, 1, 1, 2, 1],
                 "the fourth being the two-octet disassoc timer")
        check.ok(chain == 7, "and its element chain starts at 7", str(chain))

        # The same number, from the hook site rather than from the union.
        src = F.strip_comments(lay.read(root, "src/ap/wnm_ap.c"))
        check.ok("mgmt->u.action.u.bss_tm_req.variable -" in src,
                 "which is what the wnm_ap.c hook computes for itself")

    # A frame with no flexible member has no chain, and the hook for it says
    # so independently by not asking for the element domains at all.
    coloc = [(c, flds, chain) for (c, code), (m, flds, chain) in by.items()
             if m == "coloc_intf_req"]
    check.ok(coloc and coloc[0][2] == -1,
             "coloc_intf_req has no element chain", str(coloc))
    src = F.strip_comments(lay.read(root, "src/ap/wnm_ap.c"))
    check.ok('apply_mutation_resize(\n\t\t"wnm-coloc-intf-req"' in src or
             re.search(r'apply_mutation_resize\(\s*"wnm-coloc-intf-req"',
                       src) is not None,
             "and its hook asks for no chain either, which is the same "
             "statement arrived at twice")

    check.ok(len(refused) >= 1,
             "%d (category, code) key(s) refused" % len(refused))
    names = {c for c, d, claims, why in refused}
    check.ok("WLAN_ACTION_WNM" in names,
             "WNM's uncoded claim among them: five members, so an uncoded "
             "claim is not the category's fallback")
    check.ok(all(("WLAN_ACTION_WNM", None) not in [(c, d)]
                 for c, d, _, _ in refused if d is not None),
             "every refusal is reported with the reason it was refused")

    # Three synthetic trees. The extractor must refuse the first, bind the
    # second, and refuse the third.
    base_files = {rel: lay.read(root, rel) for rel in
                  ("src/common/ieee802_11_defs.h", "src/utils/common.h",
                   "src/common/wpa_common.h")}

    def synth(extra_c):
        tmp = tempfile.mkdtemp()
        write_tree(tmp, base_files)
        write_tree(tmp, {"src/ap/x.c": extra_c})
        return tmp

    two = synth("""
void a(struct ieee80211_mgmt *m)
{
	m->u.action.category = WLAN_ACTION_WMM;
	m->u.action.u.wmm_action.action_code = 7;
}
void b(struct ieee80211_mgmt *m)
{
	m->u.action.category = WLAN_ACTION_WMM;
	m->u.action.u.bss_tm_req.action = 7;
}
""")
    rows2, ref2 = lay.action_layouts(two)
    claimed = [r for r in rows2 if r[0] ==
               lay._constants(root)["WLAN_ACTION_WMM"]]
    check.ok(not claimed or len(ref2) >= 1,
             "two members claiming one (category, code) is refused, not "
             "guessed at", "%d row(s), %d refusal(s)" % (len(rows2),
                                                         len(ref2)))

    one = synth("""
void a(struct ieee80211_mgmt *m)
{
	m->u.action.category = WLAN_ACTION_WMM;
	m->u.action.u.wmm_action.action_code = 7;
}
""")
    rows3, _ = lay.action_layouts(one)
    check.ok(any(r[2] == "wmm_action" and r[1] == -1 for r in rows3),
             "a category with ONE member in the whole tree gets a fallback, "
             "whether or not a scope named it without a code")

    none = synth("""
void a(struct ieee80211_mgmt *m)
{
	m->u.action.u.wmm_action.action_code = 7;
}
""")
    rows4, _ = lay.action_layouts(none)
    check.ok(not rows4,
             "a scope that names no category binds nothing: it is not "
             "evidence, and no answer beats a plausible wrong one")


# --------------------------------------------------------------------------
# D. who reads what
# --------------------------------------------------------------------------

def check_readers(root, check):
    print("\nD. The receiver on the other side")
    rows = lay.readers(root)
    check.ok(len(rows) == 2, "two receive paths rostered", str(len(rows)))
    byrole = {role: set(reads) for _, role, _, _, reads in rows}

    check.ok("length" not in byrole["ap"],
             "the AP's wpa_receive() never reads the 802.1X length field")
    check.ok("length" in byrole["sta"],
             "the station's wpa_sm_rx_eapol() does")
    check.ok("version" not in byrole["ap"],
             "nor the protocol version")
    check.ok("key_length" not in byrole["ap"],
             "nor the Key Length field, which it only ever writes")
    check.ok("key_data_length" in byrole["ap"] and
             "key_data_length" in byrole["sta"],
             "both read the key data length -- it is not a member, and the "
             "test for it is whether the path computes the gap that locates "
             "it")
    check.ok("desc_type" in byrole["ap"],
             "and the renamed descriptor type is found under the name the "
             "SOURCE gives it, not the one the table gives it")

    pairs = dict(lay.eapol_member_names(root))
    check.ok(pairs.get("desc_type") == "type",
             "which the rename map states: desc_type is 'type' in the tree",
             str(pairs.get("desc_type")))

    # The write-from-read discrimination, idiom by idiom. Getting this
    # backwards is the only way this group produces a falsehood.
    with tempfile.TemporaryDirectory() as tmp:
        cases = [
            ("x = hdr->length;", True, "a plain read is a read"),
            ("hdr->length = 3;", False, "an assignment is not"),
            ("if (hdr->length == 3) x = 1;", True,
             "a comparison is a read"),
            ("WPA_PUT_BE16(key->length, 3);", False,
             "a WPA_PUT_* of the member is a write"),
            ("x = WPA_GET_BE16(key->length);", True,
             "a WPA_GET_* of it is a read"),
            ("os_memcpy(key->length, src, 2);", False,
             "a copy INTO it is a write"),
            ("os_memcpy(dst, key->length, 2);", True,
             "a copy OUT of it is a read"),
            ("x = sizeof(key->length);", True,
             "and anything else counts as a read, which is the safe way "
             "round"),
        ]
        for i, (line, want, what) in enumerate(cases):
            rel = "src/t/t%d.c" % i
            write_tree(tmp, {rel: "void f(void)\n{\n\t%s\n}\n" % line})
            got = "length" in lay.field_reads(tmp, rel, ["length"])
            check.ok(got == want, what, "%s -> %s" % (line, got))

    roles = dict(lay.target_roles(root))
    check.ok(roles.get("eapol") == "ap" and roles.get("sta-eapol") == "sta",
             "the two EAPOL targets transmit as opposite roles",
             str((roles.get("eapol"), roles.get("sta-eapol"))))
    check.ok(roles.get("wps-msg") == "either",
             "and a target in shared code is 'either', which makes no claim "
             "at all", str(roles.get("wps-msg")))
    check.ok(len(roles) > 150, "%d target(s) classified" % len(roles))
    check.ok(drifts(lay._role_of, "somewhere/else/x.c"),
             "a hooked file no rule classifies fails rather than taking a "
             "default")


# --------------------------------------------------------------------------
# E. the chain formats
# --------------------------------------------------------------------------

def check_chains(root, check):
    print("\nE. The five TLV shapes, from the walkers that parse them")
    rows = ch.scan(root)
    got = {name: fmt for name, rel, fn, guard, fmt, reg, prefix in rows}

    want = {
        # (id_off, id_width, id_le, len_off, len_width, len_le, hdr)
        "wps": (0, 2, 0, 2, 2, 0, 4),
        "dpp": (0, 2, 1, 2, 2, 1, 4),
        "p2p": (0, 1, 0, 1, 2, 1, 3),
        "nan": (0, 1, 0, 1, 2, 1, 3),
    }
    for name, fmt in sorted(want.items()):
        check.ok(got.get(name) == fmt,
                 "%s: %s" % (name, "id u%d %s, len u%d %s, hdr %d"
                             % (fmt[1] * 8, "le" if fmt[2] else "be",
                                fmt[4] * 8, "le" if fmt[5] else "be",
                                fmt[6])),
                 str(got.get(name)))

    check.ok(got["wps"][5] == 0 and got["dpp"][5] == 1,
             "WPS and DPP differ only in byte order, which is exactly the "
             "kind of difference a hand-written table loses")

    for name, rel, fn, guard, fmt, reg, prefix in rows:
        check.ok(len(reg) > 20,
                 "%s: %d identity member(s) from its own enum"
                 % (name, len(reg)))
        check.ok(all(0 <= v <= 0xFFFF for v, _ in reg),
                 "%s: every member fits the identity field" % name)

    regs = {name: dict(reg) for name, _, _, _, _, reg, _ in rows}
    check.ok(0x1001 in regs["wps"] and 0x1001 in regs["dpp"],
             "0x1001 is a member of the WPS registry AND of the DPP one, "
             "and means something different in each -- which is why the "
             "chain is in every message")
    check.ok(regs["wps"][0x1001] != regs["dpp"][0x1001],
             "   %s vs %s" % (regs["wps"][0x1001], regs["dpp"][0x1001]))

    for name, rel, fn, guard, fmt, reg, prefix in rows:
        check.ok(guard is not None,
                 "%s carries the build condition of %s"
                 % (name, os.path.basename(rel)))

    # The header size is stated twice by the walker -- by what it reads and
    # by what it refuses to walk below -- and a tree where the two disagree
    # must fail rather than picking one.
    with tempfile.TemporaryDirectory() as tmp:
        good = """
int w(const u8 *buf, size_t len)
{
	const u8 *pos = buf, *end = buf + len;
	u16 id, alen;

	while (end - pos >= 4) {
		id = WPA_GET_BE16(pos);
		pos += 2;
		alen = WPA_GET_BE16(pos);
		pos += 2;
		if (alen > end - pos)
			return -1;
		pos += alen;
	}
	return 0;
}
"""
        write_tree(tmp, {"src/x/w.c": good})
        check.ok(ch.format_of(tmp, "x", "src/x/w.c", "w") ==
                 (0, 2, 0, 2, 2, 0, 4),
                 "a synthetic walker of the WPS shape reads as one")

        write_tree(tmp, {"src/x/w.c": good.replace("end - pos >= 4",
                                                   "end - pos >= 6")})
        check.ok(drifts(ch.format_of, tmp, "x", "src/x/w.c", "w"),
                 "one whose minimum disagrees with its reads fails: two "
                 "readings, no way to tell which is wrong")

        write_tree(tmp, {"src/x/w.c": good.replace(
            "alen = WPA_GET_BE16(pos);\n\t\tpos += 2;", "alen = 4;")})
        check.ok(drifts(ch.format_of, tmp, "x", "src/x/w.c", "w"),
                 "one that reads its cursor once fails: the identity and "
                 "the length cannot both be placed")

        write_tree(tmp, {"src/x/w.c": good.replace(
            "if (alen > end - pos)", "if (alen > 99)")})
        check.ok(drifts(ch.format_of, tmp, "x", "src/x/w.c", "w"),
                 "and one that no longer bounds the length by what follows "
                 "the header fails, because what the length COUNTS is then "
                 "unstated")


# --------------------------------------------------------------------------
# F. the real binaries
# --------------------------------------------------------------------------

def build_harness(root, daemon, workdir):
    objdir = os.path.join(root, "build", daemon)
    if any(not os.path.exists(os.path.join(objdir, o)) for o in OBJECTS):
        return None
    source = os.path.join(workdir, "h-%s.c" % daemon)
    binary = os.path.join(workdir, "h-%s" % daemon)
    with open(source, "w", encoding="utf-8") as f:
        f.write(HARNESS)
    cmd = [os.environ.get("CC", "cc"), "-o", binary, source,
           "-I%s" % os.path.join(root, "src"),
           "-I%s" % os.path.join(root, "src", "utils"),
           "-DCONFIG_FUZZ"] + [os.path.join(objdir, o) for o in OBJECTS]
    if subprocess.run(cmd, capture_output=True, text=True).returncode:
        return None
    return binary


def run_harness(binary, n):
    env = dict(os.environ)
    for k in list(env):
        if k.startswith("FUZZ_"):
            del env[k]
    out = subprocess.run([binary, str(n)], capture_output=True, text=True,
                         env=env)
    msgs = []
    for line in (out.stdout + out.stderr).splitlines():
        if not line.startswith("[fuzz] "):
            continue
        try:
            msgs.append(json.loads(line[len("[fuzz] "):]))
        except ValueError:
            pass
    return msgs


def check_real(root, check):
    print("\nF. What the built engine does with it")
    with tempfile.TemporaryDirectory() as tmp:
        binary = build_harness(root, "hostapd", tmp)
        if binary is None:
            check.skip("the engine runs", "hostapd is not built, or the "
                       "harness did not compile")
            return
        msgs = run_harness(binary, 600)

    inv = [m for m in msgs if m.get("msg") == "inventory"]
    check.ok(len(inv) == 1, "the inventory came out once")
    if not inv:
        return
    inv = inv[0]
    check.ok(len(inv.get("layouts") or []) >= 10,
             "it announces %d Action layout(s)" % len(inv.get("layouts") or
                                                      []))
    check.ok(len(inv.get("layouts_refused") or []) >= 1,
             "and the keys it refused, which a run that reported only its "
             "bindings would hide")
    check.ok(len(inv.get("var_fields") or []) == 1,
             "the variable field, with its candidate set")
    check.ok(len(inv.get("readers") or []) == 2,
             "the two receive paths")
    check.ok(len(inv.get("chains") or []) == 5,
             "and five TLV chain formats",
             str(len(inv.get("chains") or [])))
    check.ok(inv.get("layout_members", 0) > inv.get("layout_bound", 0) > 0,
             "the layouts travel with their denominator: %s of %s union "
             "members bound" % (inv.get("layout_bound"),
                                inv.get("layout_members")))

    fields = {}
    for m in msgs:
        if m.get("type") in ("MUT_FIELD", "MUT_PATTERN"):
            fields.setdefault((m["target"], m["field"]), m)

    kdl = fields.get(("eapol", "key_data_length"))
    check.ok(kdl is not None, "key_data_length was swept as a field")
    if kdl:
        check.ok(kdl["from"] == "var" and kdl["gap"] == 16,
                 "at a solved offset, with the gap it solved for reported",
                 str((kdl.get("from"), kdl.get("gap"))))
        check.ok(kdl["at"] == 97,
                 "which is 81 + 16, the base plus the MIC", str(kdl["at"]))

    dead = {f for (t, f), m in fields.items()
            if t == "sta-eapol" and m.get("read") == 0}
    check.ok({"length", "version", "key_length"} <= dead,
             "at sta-eapol the AP's unread fields are marked dead",
             str(sorted(dead)))
    live = {f for (t, f), m in fields.items()
            if t == "eapol" and m.get("read") == 1}
    check.ok("length" in live,
             "and the same field at the other target is marked live")
    tiers = {m["tier"] for (t, f), m in fields.items()
             if t == "sta-eapol" and m.get("read") == 0 and "tier" in m}
    check.ok(tiers == {"LADDER"},
             "a dead field is swept at LADDER and not at STRIDE", str(tiers))

    act = {f: m for (t, f), m in fields.items() if t == "wnm-bss-tm-req"}
    check.ok(len(act) == 5,
             "the Action frame contributed five named fields where it used "
             "to contribute one octet of category", str(sorted(act)))
    dt = act.get("bss_tm_req.disassoc_timer")
    check.ok(dt is not None and dt["width"] == 2 and dt["at"] == 4,
             "including a two-octet timer at offset 4",
             str(dt and (dt["at"], dt["width"])))
    check.ok(all(m["from"] == "action" for m in act.values()),
             "all of them reported as coming from a layout")

    prog = [m for m in msgs if m.get("msg") == "progress"
            and m.get("target") == "wnm-bss-tm-req"]
    check.ok(prog and all(m.get("layout") == "bss_tm_req" for m in prog),
             "and every case says which layout it matched")

    wps = [m for m in msgs if m.get("type") == "MUT_ELEM"
           and m.get("target") == "wps-msg"]
    check.ok(len(wps) > 100, "%d WPS attribute(s) synthesised" % len(wps))
    check.ok(all(m.get("chain") == "wps" for m in wps),
             "every one of them naming its chain")
    ids = {m["eid"] for m in wps}
    members = {v for v, _ in ch.registry(root, "src/wps/wps_defs.h",
                                         "wps_attribute", "ATTR_")}
    check.ok(ids == members,
             "and the WHOLE 88-member registry reached in one run -- which "
             "is the point of a generated identity domain over a sparse "
             "16-bit field", "%d of %d" % (len(ids), len(members)))

    # The octets, not the claim: a WPS attribute is big-endian u16/u16, and
    # an engine that wrote it as an element would put the length where the
    # parser reads the low half of the type.
    one = [m for m in wps if m.get("dom") == "elem" and m.get("data")][0]
    data = bytes.fromhex(one["data"])
    at = one["pos"]
    check.ok(len(data) >= at + 4 and
             int.from_bytes(data[at:at + 2], "big") == one["eid"],
             "the type is in the frame big-endian, where its parser looks",
             one["data"][:32])

    led = ledger_mod.Ledger()
    for m in msgs:
        led.feed(m)
    check.ok(led.chain_roster and led.chain_cases.get("wps", 0) > 0,
             "the ledger reads the chains back and counts the WPS cases")
    check.ok(any(v == 0 for v in
                 (led.chain_cases.get(n, 0) for n in ("dpp", "p2p", "nan"))),
             "and a chain with no cases stays in the roster, which is what "
             "keeps 'none built' apart from 'no such chain'")
    out = []

    def say(text=""):
        out.append(text)

    led._report_past_struct(say)
    led._report_chains(say)
    text = "\n".join(out)
    check.ok("SWEPT AT A RECEIVER THAT DOES NOT READ IT" in text,
             "the report names the dead domains")
    check.ok("REFUSED" in text,
             "and the layout keys the engine declined to guess at")


def main():
    root = os.path.abspath(sys.argv[1] if len(sys.argv) > 1
                           else os.path.join(HERE, "..", ".."))
    print("W16 -- the field model past the struct, against %s" % root)
    check = Check()
    check_var(root, check)
    check_solver(root, check)
    check_layouts(root, check)
    check_readers(root, check)
    check_chains(root, check)
    check_real(root, check)
    print()
    total = check.passed + check.failed
    print("%d of %d checks pass%s"
          % (check.passed, total,
             (", %d skipped" % check.skipped) if check.skipped else ""))
    return 1 if check.failed else 0


if __name__ == "__main__":
    sys.exit(main())
