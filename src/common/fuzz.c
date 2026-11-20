/*
 * Frame mutation hooks for fuzzing hostapd's transmit paths
 * Copyright (c) 2025, Noam Rathaus <rathaus@gmail.com>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "utils/includes.h"

#include "utils/common.h"
#include "utils/json.h"
#include "ieee802_11_defs.h"
#include "wpa_common.h"
#include "fuzz.h"
#include "fuzz_registries.h"
#include "fuzz_fields.h"

#define TABLE_SIZE 1024

struct fuzz_entry {
	char *key;
	s64 value;
	int held;
	struct fuzz_entry *next;
};

static struct fuzz_entry *case_ids[TABLE_SIZE] = { NULL };


static unsigned int fuzz_hash(const char *s)
{
	unsigned int h = 5381;

	while (*s)
		h = (h * 33) ^ *s++;

	return h % TABLE_SIZE;
}


static struct fuzz_entry * fuzz_dict_get(const char *key)
{
	struct fuzz_entry *e;

	for (e = case_ids[fuzz_hash(key)]; e; e = e->next) {
		if (os_strcmp(e->key, key) == 0)
			return e;
	}

	return NULL;
}


/*
 * Insert 'key' if absent, otherwise update the existing entry in place.
 * Returns the entry, or NULL if a new one could not be allocated.
 */
static struct fuzz_entry * fuzz_dict_set(const char *key, s64 val)
{
	unsigned int h = fuzz_hash(key);
	struct fuzz_entry *e = fuzz_dict_get(key);

	if (e) {
		e->value = val;
		return e;
	}

	e = os_zalloc(sizeof(*e));
	if (!e)
		return NULL;

	e->key = os_strdup(key);
	if (!e->key) {
		os_free(e);
		return NULL;
	}

	e->value = val;
	e->next = case_ids[h];
	case_ids[h] = e;

	return e;
}


/*
 * Output contract: every line under the "[fuzz] " prefix is a JSON object with
 * a "msg" key. A consumer can then parse each one without sniffing for '{',
 * and can ignore a "msg" it does not recognise -- so a message added later
 * breaks nobody. These two are that envelope; 'extra' is room for whatever the
 * caller appends, on top of the object's own keys.
 */
static struct wpabuf * fuzz_report_start(const char *msg, size_t extra)
{
	struct wpabuf *json = wpabuf_alloc(extra + 256);

	if (!json)
		return NULL;

	json_start_object(json, NULL);
	json_add_string(json, "msg", msg);

	return json;
}


static void fuzz_report_end(struct wpabuf *json)
{
	json_end_object(json);
	wpa_printf(MSG_INFO, "[fuzz] %s", (char *) wpabuf_head(json));
	wpabuf_free(json);
}


/* An environment tunable that could not be parsed, and was therefore ignored.
 * The value is escaped because it is whatever the invoker typed. */
static void fuzz_report_bad_env(const char *name, const char *value)
{
	size_t value_len = os_strlen(value);
	struct wpabuf *json;

	json = fuzz_report_start("bad_env",
				 os_strlen(name) + 6 * value_len);
	if (!json)
		return;

	json_value_sep(json);
	json_add_string(json, "name", name);
	json_value_sep(json);
	if (json_add_string_escape(json, "value", value, value_len) < 0) {
		wpabuf_free(json);
		return;
	}
	fuzz_report_end(json);
}


/* A target starting at a resumed case rather than at the warm-up. */
static void fuzz_report_resume(const char *target, int case_id)
{
	struct wpabuf *json = fuzz_report_start("resume", os_strlen(target));

	if (!json)
		return;

	json_value_sep(json);
	json_add_string(json, "target", target);
	json_value_sep(json);
	json_add_int(json, "case_id", case_id);
	fuzz_report_end(json);
}


/*
 * A case that was announced through "progress" and mutated, but whose frame
 * was dropped on an error path before it could be transmitted. The consumer
 * needs this to correct a delivery count taken from "progress", which is the
 * only per-case message that always arrives; 'target' because each target
 * counts separately, and 'case_id' so the lost case can be replayed through
 * FUZZ_START_<TARGET>.
 */
static void fuzz_report_abandoned(const char *target, s64 case_id)
{
	struct wpabuf *json = fuzz_report_start("abandoned", os_strlen(target));

	if (!json)
		return;

	json_value_sep(json);
	json_add_string(json, "target", target);
	json_value_sep(json);
	json_add_int(json, "case_id", case_id);
	fuzz_report_end(json);
}


/*
 * Every target label the tree can emit.
 *
 * The dict below is filled lazily, on a target's first transmitted frame, so a
 * target that the configuration never causes hostapd to build is simply absent
 * from the output -- and a target that does not exist looks exactly like one
 * that was never reached. That is the whole difference between "this frame was
 * swept" and "this frame was never sent", and without this table a consumer
 * cannot tell them apart.
 *
 * Generated, not written: fuzzing/ledger/targets.py walks the call sites of
 * apply_mutation(), apply_mutation_defer_log() and the send_auth_reply()
 * wrapper that passes its 'dbg' argument through, and --check fails the build
 * if this list and the tree disagree. Regenerate with:
 *
 *	python3 fuzzing/ledger/targets.py . --emit
 */
static const char * const fuzz_known_targets[] = {
	"assoc_resp",
	"auth-fils-finish",
	"auth-ft-finish",
	"auth-sae",
	"auth-sae-reflection-attack",
	"deauth",
	"eapol",
	"handle-auth",
	"mesh-plink",
	"mesh-plink-ampe",
	"pasn-sec-profile-reject",
	"probe_resp",
	"sae-commit-override",
	"sae-send-commit",
	"sae-send-confirm",
	"send-8021x-auth-reply",
	"sta-assoc-req",
	"sta-auth",
	"sta-auth-8021x",
	"sta-auth-eppke-1",
	"sta-auth-eppke-3",
	"sta-auth-fils",
	"sta-auth-sae-commit",
	"sta-auth-sae-confirm",
	"sta-eapol",
	"sta-ext-8021x-auth",
	"sta-ext-sae-commit",
	"sta-ext-sae-confirm",
	"wnm-bss-tm-req",
	"wnm-bss-tm-req-full",
	"wnm-coloc-intf-req",
	"wnm-disassoc-imminent",
	"wnm-ess-disassoc-imminent",
	"wnm-sleep-resp",
};


/*
 * The stages fuzz_stage_repeat() guards, for the same reason the targets are
 * listed above: a stage nobody set a budget for emits nothing, and from the
 * outside that is indistinguishable from a stage this build does not have. A
 * consumer that wants to know which FUZZ_REPEAT_* this binary will honour
 * should not have to find out by trying them.
 *
 * Generated, not written: fuzzing/stages/stages.py walks the fuzz_stage_repeat() call
 * sites and --check fails if this list and the tree disagree. Regenerate with:
 *
 *	python3 fuzzing/stages/stages.py . --emit
 */
static const char * const fuzz_known_stages[] = {
	"eapol-m1",
	"eapol-m3",
	"group-m1",
	"sae-comeback",
};


/*
 * Announce the table once, before any case is reported, so a consumer knows the
 * whole target set from the first line rather than discovering it as targets
 * happen to be reached. The labels are compile-time literals from our own call
 * sites and targets.py --check rejects any that is not [A-Za-z0-9_-], so they
 * need no JSON escaping.
 */
static void fuzz_report_inventory(void)
{
	struct wpabuf *json;
	size_t i, extra = 0;

	for (i = 0; i < ARRAY_SIZE(fuzz_known_targets); i++)
		extra += os_strlen(fuzz_known_targets[i]) + 4;
	for (i = 0; i < ARRAY_SIZE(fuzz_known_stages); i++)
		extra += os_strlen(fuzz_known_stages[i]) + 4;

	json = fuzz_report_start("inventory", extra);
	if (!json)
		return;

	json_value_sep(json);
	json_start_array(json, "targets");
	for (i = 0; i < ARRAY_SIZE(fuzz_known_targets); i++) {
		if (i)
			json_value_sep(json);
		wpabuf_printf(json, "\"%s\"", fuzz_known_targets[i]);
	}
	json_end_array(json);

	json_value_sep(json);
	json_start_array(json, "stages");
	for (i = 0; i < ARRAY_SIZE(fuzz_known_stages); i++) {
		if (i)
			json_value_sep(json);
		wpabuf_printf(json, "\"%s\"", fuzz_known_stages[i]);
	}
	json_end_array(json);

	fuzz_report_end(json);
}


int fuzz_env_int(const char *name, int fallback)
{
	const char *val = getenv(name);
	char *end;
	long n;

	if (!val || *val == '\0')
		return fallback;

	n = strtol(val, &end, 0);
	if (*end != '\0') {
		fuzz_report_bad_env(name, val);
		return fallback;
	}

	return (int) n;
}


/*
 * Fold a target name into an environment variable name. Target names come from
 * the call sites and contain spaces, colons and punctuation ("auth-sae",
 * "SAE: TESTING - commit override"), so 'prefix' is followed by the target
 * uppercased with everything that is not alphanumeric replaced by '_'.
 */
static void fuzz_env_name(char *buf, size_t buflen, const char *prefix,
			  const char *target)
{
	size_t i;

	os_snprintf(buf, buflen, "%s%s", prefix, target);

	for (i = 0; buf[i]; i++) {
		unsigned char c = (unsigned char) buf[i];

		if (c >= 'a' && c <= 'z')
			buf[i] = c - 'a' + 'A';
		else if (!((c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')))
			buf[i] = '_';
	}
}


/*
 * Per-target resume, falling back to the global FUZZ_START_CASE.
 *
 *   FUZZ_START_AUTH_SAE=1234 ./hostapd ...
 */
static int fuzz_start_case(const char *target)
{
	const int global = fuzz_env_int("FUZZ_START_CASE", 0);
	char name[128];

	fuzz_env_name(name, sizeof(name), "FUZZ_START_", target);

	return fuzz_env_int(name, global);
}


/*
 * Per-target hold: the target's frames are transmitted unmutated, so the
 * stages behind it stay reachable. Mutating an early-stage frame stops a
 * station ever getting to a later one -- a corrupted probe response breaks
 * security negotiation, so the station rescans instead of authenticating, and
 * the SAE and EAPOL targets behind it never advance. Holding the earlier
 * stages is how a later one is fuzzed:
 *
 *   FUZZ_HOLD_PROBE_RESP=1 FUZZ_HOLD_SAE_SEND_COMMIT=1 ./hostapd ...
 *
 * This is not FUZZ_START_<TARGET> parked at case_max: that skips the frame
 * rather than answering it correctly, and what the later stages need is a
 * well-formed reply. A held target still announces itself through "progress",
 * so a held target and a missing one do not look the same from the outside,
 * and it consumes no cases, so a run without the hold sweeps from the start
 * rather than from wherever the held run left off.
 *
 * Resolved once per target, when the target is first seen: a hold is a property
 * of the run, not something to change under a station mid-exchange.
 */
static int fuzz_hold_target(const char *target)
{
	char name[128];

	fuzz_env_name(name, sizeof(name), "FUZZ_HOLD_", target);

	return fuzz_env_int(name, 0) != 0;
}


/*
 * Runtime kill-switch. A CONFIG_FUZZ binary is still a working AP with
 * FUZZ_DISABLE=1, which is how you confirm a failure comes from the mutation
 * rather than from the configuration. Resolved once.
 */
int fuzz_enabled(void)
{
	static int enabled = -1;

	if (enabled < 0)
		enabled = fuzz_env_int("FUZZ_DISABLE", 0) == 0;

	return enabled;
}


/*
 * Sweep order. Breadth-first by default: one mutation applied at every byte
 * offset before the next mutation is tried anywhere. Resolved once.
 *
 * Depth-first -- the whole set of mutations at offset 0, then offset 1 -- is
 * what you want once a crash has been seen and the question is which field
 * caused it. It is the wrong order for a run bounded by anything other than the
 * full case space, which against a real station every run is: the cases are
 * delivered as replies to station actions, so the rate is set by how fast the
 * station re-joins. A measured ten-minute run reached case 596 of an EAPOL-Key
 * frame's 32,428, which depth-first is three byte offsets out of 121 -- every
 * one of them a fixed header field, with the key data and the RSN IE behind
 * them untouched. Breadth-first the same 596 cases are 4.9 passes over every
 * byte of the frame.
 */
static int fuzz_sweep_depth_first(void)
{
	static int depth_first = -1;

	if (depth_first < 0)
		depth_first = fuzz_env_int("FUZZ_SWEEP_DEPTH_FIRST", 0) != 0;

	return depth_first;
}


static const u8 interesting_values[] = { 0x00, 0x01, 0x7F, 0x80, 0xFF };

#define NUM_INTERESTING ARRAY_SIZE(interesting_values)

/*
 * Cases per byte offset: the XOR masks 1..255. A mask of 0 is excluded because
 * it is a no-op, so the masks are exactly the 255 values a byte can be changed
 * to, each reached exactly once -- an offset's sweep is therefore exhaustive
 * and duplicate-free by construction.
 *
 * This replaced a 268-case offset made of 5 "set to an interesting value"
 * cases, 8 single-bit flips and these same 255 masks. The first 13 were all
 * duplicates: a bit flip is an XOR by a power of two, and setting a byte to v
 * is an XOR by orig ^ v, so for every possible original byte each of the 13
 * repeated a value the mask sweep already produced -- or, where v was the byte
 * it already held, changed nothing at all. What those kinds really supplied
 * was an *order*, and that is kept below in fuzz_xor_mask().
 */
#define CASES_PER_OFFSET 255

/*
 * case_id maps onto (offset, mask) exactly once under either order. The two
 * orders cover the same case space and differ only in the sequence:
 *
 *   breadth-first (default)  idx = case_id % fuzz_len
 *                            rem = case_id / fuzz_len
 *   depth-first              idx = case_id / CASES_PER_OFFSET
 *                            rem = case_id % CASES_PER_OFFSET
 *
 * The orders renumber every case, so a case_id recorded under one does not
 * replay under the other. Both the "progress" and "fuzz" messages carry an
 * "order" field for that reason: a consumer that replays a recorded case_id
 * without checking it will reproduce a different frame and report the crash as
 * non-reproducible. Note that "order" does not distinguish a change to
 * CASES_PER_OFFSET itself, which renumbers just as thoroughly.
 */

/*
 * The 255 masks in the order they are applied to a byte currently holding
 * 'orig'. Every mask 1..255 appears exactly once; what this decides is which
 * of them a run that never finishes an offset actually gets to, which against
 * a real station is every run. The order is:
 *
 *   1. the masks that set the byte to one of 'interesting_values'
 *   2. the single-bit flips
 *   3. everything else, ascending
 *
 * rem advances slowest under the breadth-first sweep, so this is what every
 * offset in the frame sees first. It is the old 5-interesting-then-8-bit-flips
 * opening, now costing no extra cases: a measured ten-minute live run reached
 * rem 4 of 268, which is to say the interesting values were the only cases
 * that ran at all.
 *
 * A mask an earlier rule already emitted is skipped when a later one reaches
 * it: orig ^ v is 0 when the byte already holds v, and some of those masks are
 * powers of two. So the three rules are not a fixed 5/8/242 split -- how many
 * each contributes depends on 'orig' -- but their union is always 1..255.
 */
static u8 fuzz_xor_mask(u8 orig, size_t rem)
{
	u8 emitted[256];
	size_t n = 0;
	unsigned int i;

	os_memset(emitted, 0, sizeof(emitted));
	emitted[0] = 1; /* a mask of 0 changes nothing, so it is never a case */

	for (i = 0; i < NUM_INTERESTING; i++) {
		u8 mask = orig ^ interesting_values[i];

		if (emitted[mask])
			continue;
		emitted[mask] = 1;
		if (n++ == rem)
			return mask;
	}

	for (i = 0; i < 8; i++) {
		u8 mask = 1U << i;

		if (emitted[mask])
			continue;
		emitted[mask] = 1;
		if (n++ == rem)
			return mask;
	}

	for (i = 1; i < 256; i++) {
		if (emitted[i])
			continue;
		if (n++ == rem)
			return (u8) i;
	}

	return 0; /* unreachable: the caller holds rem < CASES_PER_OFFSET */
}


/* First case_id handed out for a target; negative values are not fuzzed, so
 * this gives each target a warm-up period of unmutated frames. */
#define FUZZ_FIRST_CASE_ID (-9)

/*
 * A frame whose hexdump is being held back until the caller finishes building
 * it (see apply_mutation_defer_log()). hostapd is single-threaded, so one
 * pending slot is enough.
 */
static struct wpabuf *pending_log = NULL;

/* Which case that pending frame is, so it can be named if it is abandoned.
 * pending_target points at the dict entry's own key, which lives as long as
 * the process. Both are only meaningful while pending_log is set. */
static const char *pending_target = NULL;
static s64 pending_case_id = 0;


/*
 * What the target did with the case it just announced. The case_id/case_max/
 * target fields are unchanged, so this is additive -- it exists because
 * case_id alone does not say whether a case ran: the range below zero is a
 * warm-up of unmutated frames, and a consumer clamping it to zero reports
 * cases as complete before any has been sent.
 */
static const char * fuzz_state(int held, s64 case_id, s64 case_max)
{
	if (held)
		return "held";
	if (case_id < 0)
		return "warmup";
	if (case_id >= case_max)
		return "done";

	return "mutating";
}


static void fuzz_emit(struct wpabuf *json, const u8 *buf, size_t len)
{
	size_t hexdump_size = 2 * len + 1;
	char *hexdump = os_malloc(hexdump_size);

	if (!hexdump) {
		wpabuf_free(json);
		return;
	}

	/* Use len, as we want the whole buffer (with HDRs) */
	wpa_snprintf_hex(hexdump, hexdump_size, buf, len);

	json_add_string(json, "data", hexdump);
	fuzz_report_end(json);

	os_free(hexdump);
}


/*
 * Stage multiplicity.
 *
 * The sweep delivers one case per occurrence of a stage, so a stage the state
 * machine produces exactly once per peer gets exactly one case per session.
 * How many times a stage occurs is itself a domain -- 0..N -- and it is pinned
 * at the constant 1 by the state machine rather than by anything the mutation
 * engine can reach: the engine changes octets of a frame, and this is about
 * whether there is a second frame at all.
 *
 * fuzz_stage_repeat() is the one primitive for unpinning it. It returns true
 * while this peer's budget for this stage is unspent, and spends one unit each
 * time it does. That single shape covers both ways the tree expresses a
 * one-shot stage:
 *
 *	if (normally_once || fuzz_stage_repeat("x", addr))	a latched branch
 *	while (fuzz_stage_repeat("x", addr)) send_it();		a state that sends
 *
 * The budget is per (stage, peer) and is spent down, never refilled within a
 * session, so a stage is re-issued a bounded number of times no matter how
 * many times the guard is evaluated. That bound matters: unbounded re-issue
 * starves every stage behind it, which is the same failure FUZZ_HOLD_* exists
 * to prevent. FUZZ_REPEAT_MAX is a second bound on top, so a mistyped
 * environment value cannot turn a run into one stage repeated forever.
 *
 * Default 0: a build with this compiled in behaves exactly as before until a
 * FUZZ_REPEAT_<STAGE> is set.
 */
#define FUZZ_REPEAT_MAX 32

/* Prefix on the dict key, so repeat counters share the table with the case
 * counters without being able to collide with a target name. ':' cannot appear
 * in the key fuzz_dict_*() is given for a case, which is a bare target name. */
#define FUZZ_REPEAT_PREFIX "R:"


static void fuzz_repeat_key(char *buf, size_t buflen, const char *stage,
			    const u8 *peer)
{
	if (peer)
		os_snprintf(buf, buflen, FUZZ_REPEAT_PREFIX "%s:" MACSTR,
			    stage, MAC2STR(peer));
	else
		os_snprintf(buf, buflen, FUZZ_REPEAT_PREFIX "%s:-", stage);
}


static void fuzz_report_repeat(const char *stage, const u8 *peer, int n,
			       int budget)
{
	struct wpabuf *json = fuzz_report_start("repeat", os_strlen(stage) + 24);

	if (!json)
		return;

	json_value_sep(json);
	json_add_string(json, "stage", stage);
	json_value_sep(json);
	json_add_int(json, "n", n);
	json_value_sep(json);
	json_add_int(json, "of", budget);
	if (peer) {
		char addr[20];

		os_snprintf(addr, sizeof(addr), MACSTR, MAC2STR(peer));
		json_value_sep(json);
		json_add_string(json, "peer", addr);
	}
	fuzz_report_end(json);
}


/*
 * True while this peer still has budget for an extra occurrence of 'stage',
 * spending one unit each time it returns true.
 *
 *	FUZZ_REPEAT_EAPOL_M1=2 ./hostapd ...
 *
 * 'peer' may be NULL for a stage that is not per-peer; the budget is then
 * shared, which is the honest behaviour rather than an unbounded one.
 */
int fuzz_stage_repeat(const char *stage, const u8 *peer)
{
	char name[128], key[160];
	struct fuzz_entry *e;
	int budget;

	if (!fuzz_enabled() || !stage)
		return 0;

	fuzz_env_name(name, sizeof(name), "FUZZ_REPEAT_", stage);
	budget = fuzz_env_int(name, 0);
	if (budget <= 0)
		return 0;
	if (budget > FUZZ_REPEAT_MAX)
		budget = FUZZ_REPEAT_MAX;

	fuzz_repeat_key(key, sizeof(key), stage, peer);
	e = fuzz_dict_get(key);
	if (!e) {
		e = fuzz_dict_set(key, 0);
		if (!e)
			return 0;
	}

	if (e->value >= budget)
		return 0;

	e->value++;
	fuzz_report_repeat(stage, peer, (int) e->value, budget);

	return 1;
}


/*
 * Forget every stage budget held for this peer, so the next session starts
 * over. Called when a station's state is torn down.
 *
 * Without this a peer that reconnects within one run would find its budget
 * already spent, and the second session would deliver each stage once -- the
 * pinned behaviour this exists to lift, reappearing silently after the first
 * reconnect. Against a real station, which reconnects continuously, that is
 * every session but the first.
 */
/*
 * Which peer the frame about to be mutated is for.
 *
 * Several peers can be in flight at once -- N stations against one AP, N nodes
 * in a mesh -- and they share a target's case counter, so each gets a
 * DIFFERENT case rather than all repeating the first. That is the point of a
 * multi-peer run: it is N times the stimulus, not N copies of it. But it only
 * reads that way if the record says which peer got which case.
 *
 * For a management frame the answer is in the frame: the destination address
 * is octets 4..9 of the 802.11 header, and it is what actually went on the
 * air. Nothing is asked of the call site and nothing can go stale.
 *
 * A frame with no address in it -- an EAPOL-Key body, whose addressing lives
 * in the ethernet header the layer below adds -- has no such answer, so the
 * call site sets a hint immediately before mutating. The hint is one-shot and
 * is cleared on entry to every mutation, so a site that sets one and then
 * returns early cannot have it attached to someone else's frame. hostapd and
 * wpa_supplicant are single-threaded; this is the same assumption the deferred
 * hexdump already makes.
 */
static u8 fuzz_peer_hint_addr[ETH_ALEN];
static int fuzz_peer_hint_set = 0;


void fuzz_peer_hint(const u8 *peer)
{
	if (!peer) {
		fuzz_peer_hint_set = 0;
		return;
	}

	os_memcpy(fuzz_peer_hint_addr, peer, ETH_ALEN);
	fuzz_peer_hint_set = 1;
}


/* The peer for this frame, written into 'out', or NULL if it is not known.
 * Consumes the hint. */
static const char * fuzz_peer_of(enum fuzz_frame_type type, const u8 *buf,
				 size_t len, char *out, size_t outlen)
{
	const u8 *addr = NULL;

	if (type == FUZZ_TYPE_IEEE80211_MGMT && len >= IEEE80211_HDRLEN)
		addr = buf + 4;		/* DA, per the 802.11 header */
	else if (fuzz_peer_hint_set)
		addr = fuzz_peer_hint_addr;

	fuzz_peer_hint_set = 0;

	if (!addr)
		return NULL;

	os_snprintf(out, outlen, MACSTR, MAC2STR(addr));

	return out;
}


void fuzz_peer_reset(const u8 *peer)
{
	char suffix[24];
	unsigned int i;

	if (!fuzz_enabled() || !peer)
		return;

	os_snprintf(suffix, sizeof(suffix), ":" MACSTR, MAC2STR(peer));

	for (i = 0; i < TABLE_SIZE; i++) {
		struct fuzz_entry *e, *prev = NULL, *next;

		for (e = case_ids[i]; e; e = next) {
			size_t klen, slen = os_strlen(suffix);

			next = e->next;
			klen = os_strlen(e->key);
			if (os_strncmp(e->key, FUZZ_REPEAT_PREFIX,
				       os_strlen(FUZZ_REPEAT_PREFIX)) != 0 ||
			    klen < slen ||
			    os_strcmp(e->key + klen - slen, suffix) != 0) {
				prev = e;
				continue;
			}

			if (prev)
				prev->next = next;
			else
				case_ids[i] = next;
			os_free(e->key);
			os_free(e);
		}
	}
}


void fuzz_log_sent_frame(const u8 *buf, size_t len)
{
	struct wpabuf *json = pending_log;

	if (!json)
		return;

	pending_log = NULL;
	pending_target = NULL;
	fuzz_emit(json, buf, len);
}


/*
 * Element synthesis.
 *
 * Rewriting an existing element's id octet in place -- which the octet sweep
 * already does, for all 255 values of it -- selects a different parse helper,
 * but the length and the body still belong to the element that was there. Most
 * helpers reject on length within a line or two, so the reach is wide and the
 * depth is nil. Reaching a helper's body means CONSTRUCTING an element: chosen
 * id, chosen length, inserted into the chain.
 *
 * Four domains, enumerated rather than sampled, and none of them filtered to
 * "legal in this frame". An element appearing where it is not legal is a case
 * worth sending; a legality filter is exactly the hand-curation this engine
 * exists to avoid.
 *
 *	identity	every member of the generated registries -- 179
 *			element ids and 62 extension ids, read out of
 *			src/common/ieee802_11_defs.h, never typed
 *	position	every insertion point in the chain, before the first
 *			element and after the last included
 *	length		the element's body, 0 .. what the headroom allows
 *	multiplicity	the same element present 2..5 times
 *
 * Identity varies fastest, so a run that is cut short -- which against a real
 * station is every run -- has covered every id before it has covered any id
 * twice. That ordering is what makes "all 241 ids reached" a property of a
 * short run rather than of a complete sweep.
 */

/* An element chain longer than this is walked up to here and no further. The
 * cap bounds the position domain; it is not a claim about what a chain may
 * contain. */
#define FUZZ_MAX_ELEMS 32

/* The same element, present this many times. Starts at 2 because once is what
 * the identity domain already covers. */
#define FUZZ_MULT_MIN 2
#define FUZZ_MULT_MAX 5

/* Element overhead: id and length octets, plus the extension id for an element
 * that carries one. Worst case, so one bound serves both kinds. */
#define FUZZ_ELEM_OVERHEAD 3


/*
 * Walk an element chain. Fills offs[] with each element's offset from 'buf'
 * and returns how many there were, or 0 when the region is not a chain -- a
 * length that runs past the end, or a walk that does not land exactly on it.
 *
 * Refusing a partial walk matters. A management frame's variable part is only
 * an element chain for some frames; for the rest it begins with fixed fields
 * whose octets would parse as plausible elements, and inserting "after element
 * three" of a chain that does not exist puts the element at an offset chosen by
 * misreading a scalar. The caller falls back to appending, which is always a
 * real position.
 */
static size_t fuzz_walk_elements(const u8 *buf, size_t len, u16 *offs,
				 size_t max)
{
	size_t pos = 0, n = 0;

	while (pos + 2 <= len) {
		size_t elen = 2 + buf[pos + 1];

		if (pos + elen > len)
			return 0;
		if (n < max)
			offs[n] = (u16) pos;
		n++;
		pos += elen;
		if (n >= max)
			break;
	}

	if (pos != len)
		return 0;

	return n;
}


/*
 * Write one synthesised element into 'out', returning its size.
 *
 * 'which' indexes the two registries end to end: the element ids first, then
 * the extension ids. One flat identity domain, because a consumer asking "has
 * every id been emitted" should not have to know which table an id came from.
 *
 * The body is a constant fill. What the octets say is a domain of its own and
 * not this one; deriving them from the case would mean neither was enumerated.
 */
static size_t fuzz_build_element(u8 *out, size_t which, size_t body_len)
{
	size_t n = 0;

	if (which < ARRAY_SIZE(fuzz_elem_ids)) {
		out[n++] = fuzz_elem_ids[which];
		out[n++] = (u8) body_len;
	} else {
		which -= ARRAY_SIZE(fuzz_elem_ids);
		out[n++] = WLAN_EID_EXTENSION;
		out[n++] = (u8) (body_len + 1);
		out[n++] = fuzz_elem_ext_ids[which];
	}

	os_memset(out + n, 0, body_len);

	return n + body_len;
}


static size_t fuzz_num_ids(void)
{
	return ARRAY_SIZE(fuzz_elem_ids) + ARRAY_SIZE(fuzz_elem_ext_ids);
}


/* The id this identity index denotes, for the report: an extension id is
 * reported under its own key so a consumer is not left to infer which registry
 * a number came from. */
static int fuzz_id_is_ext(size_t which)
{
	return which >= ARRAY_SIZE(fuzz_elem_ids);
}


static u8 fuzz_id_value(size_t which)
{
	if (which < ARRAY_SIZE(fuzz_elem_ids))
		return fuzz_elem_ids[which];

	return fuzz_elem_ext_ids[which - ARRAY_SIZE(fuzz_elem_ids)];
}


/*
 * Insert 'copies' of a synthesised element at insertion point 'pos' of the
 * chain, shifting what follows. Returns the frame's new length, or 'len' when
 * it would not fit -- which cannot happen for a case the domain sizing
 * admitted, and is checked anyway because the alternative is writing past the
 * caller's buffer.
 */
static size_t fuzz_insert_element(u8 *buf, size_t len, size_t capacity,
				  size_t at, size_t which, size_t body_len,
				  size_t copies)
{
	u8 elem[2 + 1 + 255];
	size_t esize, total, i;

	if (body_len > sizeof(elem) - FUZZ_ELEM_OVERHEAD)
		body_len = sizeof(elem) - FUZZ_ELEM_OVERHEAD;

	esize = fuzz_build_element(elem, which, body_len);
	total = esize * copies;

	if (at > len || len + total > capacity)
		return len;

	os_memmove(buf + at + total, buf + at, len - at);
	for (i = 0; i < copies; i++)
		os_memcpy(buf + at + i * esize, elem, esize);

	return len + total;
}


/*
 * Several domains, swept together.
 *
 * A frame's octets are one domain. Its length is another. The elements in it
 * are a third and a fourth. They are independent of each other and of very
 * different sizes, and the engine has to sweep all of them in a run that will
 * not finish any of them -- against a real station a measured ten minutes
 * reached case 596 of an EAPOL-Key frame's 32,428.
 *
 * So the case space is a round robin, not a concatenation. In round r, every
 * domain with more than r cases contributes its case r. Concatenating instead
 * would put every domain after the first past the end of every real run.
 *
 * The mapping is total and duplicate-free: each case_id below the sum of the
 * sizes is exactly one (domain, n), and each n of each domain is reached
 * exactly once. It degenerates correctly -- one domain, and case_id is its
 * index, which is what keeps apply_mutation() the function it has always been.
 */
enum fuzz_domain {
	FUZZ_DOMAIN_BYTE = 0,	/* one octet, XOR-ed by one of 255 masks */
	FUZZ_DOMAIN_LEN,	/* the frame's length */
	FUZZ_DOMAIN_ELEM,	/* a synthesised element, inserted */
	FUZZ_DOMAIN_MULT,	/* the same element, present 2..5 times */
	FUZZ_DOMAIN_CHAIN,	/* the chain's shape: delete, duplicate, swap */
	FUZZ_DOMAIN_FIELD,	/* a named field, taken through its own domain */
	FUZZ_DOMAIN_PATTERN,	/* an opaque field, filled with a pattern */
	FUZZ_NUM_DOMAINS
};


/*
 * The field model.
 *
 * The octet domain knows a frame as a run of bytes. It will put all 255 other
 * values through the low octet of a status code and all 255 through the high
 * one, and never once send the pair that makes the field 300. Two octets is
 * 65,536 values; octet-wise reaches 511 of them. The gap is not a tuning
 * parameter -- it is the difference between sweeping a field and sweeping the
 * bytes it happens to occupy.
 *
 * So: fuzz_fields[] names each field of each frame, with its offset, its width
 * and which management subtype it belongs to. The table is GENERATED from
 * struct ieee80211_mgmt, struct ieee802_1x_hdr and struct wpa_eapol_key by
 * fuzzing/ledger/fields.py; nothing in it is typed. The subtype is read out of
 * the frame's own frame control field, so no call site has to say which
 * layout it built.
 *
 * Two kinds, and the width decides which:
 *
 *	FUZZ_FIELD_INT		one or two octets, so its entire content space
 *				is 256 or 65,536 values and can be counted
 *	FUZZ_FIELD_OPAQUE	wider -- a nonce, a timestamp, an address --
 *				where 2^256 is not a domain anyone finishes,
 *				so it is filled from a small pattern set
 *				instead. Content is not what is under test
 *				there; shape is.
 */
#define FUZZ_MAX_FIELDS 24

/*
 * Reduction tiers, declared rather than quietly applied.
 *
 *	FULL	the entire domain
 *	LADDER	the edges: 0, 1, 2, n-1, n, n+1, max-1, max, where n is the
 *		value the frame was built with. Eight cases whatever the
 *		width, so case_max does not move with the frame
 *	STRIDE	the ladder, then the rest walked at a fixed prime stride from
 *		a per-run offset
 *
 * STRIDE is why this is deferral and not sampling. Case k of the stride walk
 * is (offset + k * FUZZ_STRIDE) mod domain; every value v is reached at
 * offset v % FUZZ_STRIDE, step v / FUZZ_STRIDE, so the union over the
 * FUZZ_STRIDE offsets is the whole domain and nothing is silently skipped --
 * it is deferred to a named future run. The offset is in every message, so any
 * case replays exactly.
 *
 * AUTO -- the default -- is FULL for a domain of FUZZ_TIER_FULL_MAX or fewer
 * and STRIDE above it. That makes every u8 field FULL and every u16 field
 * 270 cases a run, complete in 251.
 */
enum fuzz_tier {
	FUZZ_TIER_AUTO = 0,
	FUZZ_TIER_FULL,
	FUZZ_TIER_LADDER,
	FUZZ_TIER_STRIDE,
};

#define FUZZ_TIER_FULL_MAX 256
#define FUZZ_STRIDE 251
#define FUZZ_LADDER_N 8

/*
 * The fills an opaque field is given. Not a sample of its content space --
 * there is no sampling a 32-octet nonce -- but the shapes that a reader of one
 * tends to treat differently: empty, one, the two sign boundaries, saturated,
 * and a counter that makes an off-by-one in a copy visible in a hexdump.
 */
#define FUZZ_PATTERN_COUNT 6

static void fuzz_fill_pattern(u8 *out, size_t len, size_t which)
{
	static const u8 fills[] = { 0x00, 0x01, 0x7f, 0x80, 0xff };
	size_t i;

	if (which < ARRAY_SIZE(fills)) {
		os_memset(out, fills[which], len);
		return;
	}

	for (i = 0; i < len; i++)
		out[i] = (u8) i;
}


static enum fuzz_tier fuzz_tier_setting(void)
{
	const char *v = getenv("FUZZ_TIER");

	if (!v)
		return FUZZ_TIER_AUTO;
	if (os_strcasecmp(v, "FULL") == 0)
		return FUZZ_TIER_FULL;
	if (os_strcasecmp(v, "LADDER") == 0)
		return FUZZ_TIER_LADDER;
	if (os_strcasecmp(v, "STRIDE") == 0)
		return FUZZ_TIER_STRIDE;

	return FUZZ_TIER_AUTO;
}


static enum fuzz_tier fuzz_tier_for(s64 domain)
{
	enum fuzz_tier t = fuzz_tier_setting();

	if (t != FUZZ_TIER_AUTO)
		return t;

	return domain <= FUZZ_TIER_FULL_MAX ? FUZZ_TIER_FULL :
		FUZZ_TIER_STRIDE;
}


static const char * fuzz_tier_name(s64 domain)
{
	switch (fuzz_tier_for(domain)) {
	case FUZZ_TIER_FULL:
		return "FULL";
	case FUZZ_TIER_LADDER:
		return "LADDER";
	case FUZZ_TIER_STRIDE:
		return "STRIDE";
	default:
		return "AUTO";
	}
}


/* Which offset into the stride this run walks. The union over 0..FUZZ_STRIDE-1
 * is the whole domain, so this says which run of the set this is. */
static s64 fuzz_stride_offset(void)
{
	int v = fuzz_env_int("FUZZ_STRIDE_OFFSET", 0);

	if (v < 0)
		v = -v;

	return (s64) (v % FUZZ_STRIDE);
}


static s64 fuzz_field_domain(const struct fuzz_field *f)
{
	return (s64) 1 << (8 * f->width);
}


/* How many cases this field contributes, under the tier its domain selects. */
static s64 fuzz_field_cases(const struct fuzz_field *f)
{
	s64 domain = fuzz_field_domain(f);

	switch (fuzz_tier_for(domain)) {
	case FUZZ_TIER_FULL:
		return domain;
	case FUZZ_TIER_LADDER:
		return FUZZ_LADDER_N;
	case FUZZ_TIER_STRIDE:
	default:
		return FUZZ_LADDER_N + (domain + FUZZ_STRIDE - 1) / FUZZ_STRIDE;
	}
}


static u64 fuzz_field_read(const u8 *buf, const struct fuzz_field *f)
{
	u64 v = 0;
	size_t i;

	for (i = 0; i < f->width; i++) {
		size_t k = f->big_endian ? i : f->width - 1 - i;

		v = (v << 8) | buf[f->offset + k];
	}

	return v;
}


static void fuzz_field_write(u8 *buf, const struct fuzz_field *f, u64 v)
{
	size_t i;

	for (i = 0; i < f->width; i++) {
		size_t k = f->big_endian ? f->width - 1 - i : i;

		buf[f->offset + k] = (u8) (v >> (8 * i));
	}
}


/* The case'th value of this field's reduced domain, given what the frame was
 * built with. */
static u64 fuzz_field_value(const struct fuzz_field *f, u64 built, s64 n)
{
	s64 domain = fuzz_field_domain(f);
	s64 mask = domain - 1;

	if (fuzz_tier_for(domain) == FUZZ_TIER_FULL)
		return (u64) (n & mask);

	if (n < FUZZ_LADDER_N) {
		/* The edges of the domain, and the edges of where the frame
		 * already is. Entries can coincide -- a built value of 0 makes
		 * four of these the same case -- and they are still eight
		 * cases, because a case count that moved with the frame would
		 * move case_max with it and no case_id would replay. */
		static const int ladder[FUZZ_LADDER_N] = {
			0, 1, 2, -1, 0, 1, -2, -1
		};
		int d = ladder[n];

		if (n < 3)
			return (u64) (d & mask);
		if (n < 6)
			return (u64) (((s64) built + d) & mask);

		return (u64) ((domain + d) & mask);
	}

	return (u64) ((fuzz_stride_offset() + (n - FUZZ_LADDER_N) *
		       FUZZ_STRIDE) % domain);
}


/*
 * The fields that apply to this frame: right frame kind, right management
 * subtype, and wholly inside the octets there are. A field that runs past the
 * end is not clamped -- a shortened frame simply has fewer fields, and
 * clamping would write a different field's octets under this one's name.
 */
static size_t fuzz_collect_fields(enum fuzz_frame_type type, const u8 *buf,
				  size_t len, size_t hdr, u16 *out,
				  size_t max, int opaque)
{
	int stype = -1;
	size_t i, n = 0;

	if (type == FUZZ_TYPE_IEEE80211_MGMT) {
		if (len < 1)
			return 0;
		/* The subtype is in the frame's own frame control field, so no
		 * call site has to declare which layout it built. */
		stype = (buf[0] >> 4) & 0xf;
	}

	for (i = 0; i < ARRAY_SIZE(fuzz_fields) && n < max; i++) {
		const struct fuzz_field *f = &fuzz_fields[i];

		if (f->frame != type)
			continue;
		if (f->stype >= 0 && f->stype != stype)
			continue;
		if (f->offset < hdr)
			continue;	/* inside the header the sweep skips */
		if (f->offset + f->width > len)
			continue;
		if ((f->kind == FUZZ_FIELD_OPAQUE) != (opaque != 0))
			continue;
		out[n++] = (u16) i;
	}

	return n;
}


/* Cases in rounds 0..r-1, which is monotonic in r and is what the search
 * below inverts. */
static s64 fuzz_cases_before_round(const s64 *sizes, size_t nsizes, s64 r)
{
	s64 total = 0;
	size_t i;

	for (i = 0; i < nsizes; i++)
		total += sizes[i] < r ? sizes[i] : r;

	return total;
}


/*
 * Which domain case_id belongs to, and which of that domain's cases it is.
 * Returns FUZZ_NUM_DOMAINS when case_id is past the end of the space, which
 * the caller has already excluded.
 */
static size_t fuzz_round_robin(s64 case_id, const s64 *sizes, size_t nsizes,
			       s64 *n)
{
	s64 lo = 0, hi = 0, r, off;
	size_t i;

	for (i = 0; i < nsizes; i++) {
		if (sizes[i] > hi)
			hi = sizes[i];
	}

	/* The last round whose cases all come before case_id. */
	while (lo < hi) {
		s64 mid = lo + (hi - lo + 1) / 2;

		if (fuzz_cases_before_round(sizes, nsizes, mid) <= case_id)
			lo = mid;
		else
			hi = mid - 1;
	}

	r = lo;
	off = case_id - fuzz_cases_before_round(sizes, nsizes, r);

	for (i = 0; i < nsizes; i++) {
		if (sizes[i] <= r)
			continue;
		if (off == 0) {
			*n = r;
			return i;
		}
		off--;
	}

	*n = 0;

	return nsizes;
}


static enum fuzz_domain fuzz_case_select(s64 case_id, const s64 *sizes,
					 s64 *n)
{
	return (enum fuzz_domain) fuzz_round_robin(case_id, sizes,
						   FUZZ_NUM_DOMAINS, n);
}


/*
 * The n'th length in the domain. The domain is 0..capacity with the frame's
 * own length left out, because resizing a frame to the length it already has
 * is a case that changes nothing -- the same reason a mask of 0 is not one of
 * the 255 cases per byte offset.
 */
static size_t fuzz_resize_length(s64 n, size_t len)
{
	size_t v = (size_t) n;

	return v < len ? v : v + 1;
}


/*
 * What the mutated buffer is, as a name a consumer can switch on. The target's
 * name will not do: it is a label for a call site, chosen by whoever added the
 * hook, and a consumer that guesses the layout from it is wrong the first time
 * someone names a site something sensible. Reported as "frame" on every
 * mutation, beside "hdr", which says how much of it was left alone.
 */
static const char * fuzz_frame_kind(enum fuzz_frame_type type)
{
	switch (type) {
	case FUZZ_TYPE_IEEE80211_MGMT:
		return "mgmt";
	case FUZZ_TYPE_IEEE802_1X_HDR:
		return "eapol";
	case FUZZ_TYPE_FRAME_BODY:
		return "body";
	}

	return "unknown";
}


/*
 * The identity of the case space itself, on every message.
 *
 * A case_id is an index into an enumeration, and the enumeration is defined by
 * which domains exist, which tier each is swept at and which stride offset the
 * run walks. Change any of those and case 1234 is a different frame -- it will
 * replay without complaint and reproduce something else. The hazard is already
 * documented here for 'order' and for CASES_PER_OFFSET; this is the same one
 * with more axes, so it is reported rather than left to be remembered.
 *
 * The version is bumped by hand whenever the numbering changes for a reason
 * the other three fields do not capture -- a domain added, a domain resized.
 */
#define FUZZ_OPSET_VERSION 2

static void fuzz_add_opset(struct wpabuf *json)
{
	char buf[64];

	os_snprintf(buf, sizeof(buf), "v%d/%dd/%s/%d@%d",
		    FUZZ_OPSET_VERSION, (int) FUZZ_NUM_DOMAINS,
		    fuzz_tier_name(1 << 16), FUZZ_STRIDE,
		    (int) fuzz_stride_offset());
	json_add_string(json, "opset", buf);
	json_value_sep(json);
}


/*
 * The peer the current frame is for, as a string, or NULL. Set once per
 * mutation and read by the reporters, rather than threaded through six
 * signatures that would all carry it unchanged.
 */
static const char *fuzz_cur_peer = NULL;


/* What every mutation message says before it says what kind it is. */
static void fuzz_report_common(struct wpabuf *json, const char *target,
			       size_t hdr, const char *kind)
{
	json_value_sep(json);
	json_add_string(json, "target", target);
	json_value_sep(json);
	json_add_string(json, "order",
			fuzz_sweep_depth_first() ? "depth" : "breadth");
	json_value_sep(json);
	fuzz_add_opset(json);
	if (fuzz_cur_peer) {
		json_add_string(json, "peer", fuzz_cur_peer);
		json_value_sep(json);
	}
	json_add_int(json, "hdr", hdr);
	json_value_sep(json);
	json_add_string(json, "frame", kind);
	json_value_sep(json);
}


static void fuzz_report_resize(const char *target, size_t hdr,
			       const char *kind, size_t was, size_t now,
			       int defer_log, const u8 *reply,
			       const char *key, s64 case_id)
{
	struct wpabuf *json = fuzz_report_start("fuzz",
						2 * (now > was ? now : was) +
						os_strlen(target));

	if (!json)
		return;

	fuzz_report_common(json, target, hdr, kind);
	json_add_string(json, "type", "MUT_LEN");
	json_value_sep(json);
	json_add_int(json, "was", was);
	json_value_sep(json);
	json_add_int(json, "len", now);
	json_value_sep(json);

	if (defer_log) {
		pending_log = json;
		pending_target = key;
		pending_case_id = case_id;
	} else {
		fuzz_emit(json, reply, now);
	}
}


static void fuzz_report_elem(const char *target, size_t hdr,
			     const char *kind, size_t was,
			     size_t now, size_t which, size_t body_len,
			     size_t at, size_t npos, size_t copies,
			     size_t off, int defer_log, const u8 *reply,
			     const char *key, s64 case_id)
{
	struct wpabuf *json = fuzz_report_start("fuzz",
						2 * (now > was ? now : was) +
						os_strlen(target));

	if (!json)
		return;

	fuzz_report_common(json, target, hdr, kind);
	json_add_string(json, "type", "MUT_ELEM");
	json_value_sep(json);

	/* An extension id is reported under its own key. A consumer counting
	 * registry coverage must not have to infer which registry a number
	 * came from, and 93 is a different thing in each. */
	if (fuzz_id_is_ext(which))
		json_add_int(json, "ext_id", fuzz_id_value(which));
	else
		json_add_int(json, "eid", fuzz_id_value(which));
	json_value_sep(json);
	json_add_int(json, "body", body_len);
	json_value_sep(json);
	json_add_int(json, "pos", at);
	json_value_sep(json);
	json_add_int(json, "npos", npos);
	json_value_sep(json);

	/* The byte offset the element went in at, as well as its index in the
	 * chain. A consumer needs the offset to recover the frame as built --
	 * cut the inserted octets back out -- and the index to know which
	 * insertion point of the domain this case was. Neither gives the
	 * other. */
	json_add_int(json, "at", off);
	json_value_sep(json);
	json_add_int(json, "copies", copies);
	json_value_sep(json);
	json_add_int(json, "was", was);
	json_value_sep(json);
	json_add_int(json, "len", now);
	json_value_sep(json);

	if (defer_log) {
		pending_log = json;
		pending_target = key;
		pending_case_id = case_id;
	} else {
		fuzz_emit(json, reply, now);
	}
}


static void fuzz_report_field(const char *target, size_t hdr,
			      const char *kind, size_t len,
			      const struct fuzz_field *f, u64 before,
			      u64 after, const char *tier, int defer_log,
			      const u8 *reply, const char *key, s64 case_id)
{
	struct wpabuf *json = fuzz_report_start("fuzz",
						2 * len + os_strlen(target) +
						os_strlen(f->name) + 32);

	if (!json)
		return;

	fuzz_report_common(json, target, hdr, kind);
	json_add_string(json, "type", "MUT_FIELD");
	json_value_sep(json);

	/* The field's name, not just its offset. A consumer counting a
	 * registry -- status codes, reason codes, authentication algorithms --
	 * must not have to work out which field an offset was, and the engine
	 * already knows. The same lesson as the element ids: the one that
	 * built it is asked. */
	json_add_string(json, "field", f->name);
	json_value_sep(json);
	json_add_int(json, "at", f->offset);
	json_value_sep(json);
	json_add_int(json, "width", f->width);
	json_value_sep(json);
	json_add_string(json, "tier", tier);
	json_value_sep(json);
	json_add_int(json, "before", (int) before);
	json_value_sep(json);
	json_add_int(json, "after", (int) after);
	json_value_sep(json);
	json_add_int(json, "len", len);
	json_value_sep(json);

	if (defer_log) {
		pending_log = json;
		pending_target = key;
		pending_case_id = case_id;
	} else {
		fuzz_emit(json, reply, len);
	}
}


static void fuzz_report_pattern(const char *target, size_t hdr,
				const char *kind, size_t len,
				const struct fuzz_field *f, size_t pattern,
				int defer_log, const u8 *reply,
				const char *key, s64 case_id)
{
	struct wpabuf *json = fuzz_report_start("fuzz",
						2 * len + os_strlen(target) +
						os_strlen(f->name) + 32);

	if (!json)
		return;

	fuzz_report_common(json, target, hdr, kind);
	json_add_string(json, "type", "MUT_PATTERN");
	json_value_sep(json);
	json_add_string(json, "field", f->name);
	json_value_sep(json);
	json_add_int(json, "at", f->offset);
	json_value_sep(json);
	json_add_int(json, "width", f->width);
	json_value_sep(json);
	json_add_int(json, "pattern", pattern);
	json_value_sep(json);
	json_add_int(json, "len", len);
	json_value_sep(json);

	if (defer_log) {
		pending_log = json;
		pending_target = key;
		pending_case_id = case_id;
	} else {
		fuzz_emit(json, reply, len);
	}
}


static void fuzz_report_chain(const char *target, size_t hdr,
			      const char *kind, size_t was,
			      size_t now, const char *op, size_t i, size_t j,
			      size_t nelem, int defer_log, const u8 *reply,
			      const char *key, s64 case_id)
{
	struct wpabuf *json = fuzz_report_start("fuzz",
						2 * (now > was ? now : was) +
						os_strlen(target) + 16);

	if (!json)
		return;

	fuzz_report_common(json, target, hdr, kind);
	json_add_string(json, "type", "MUT_CHAIN");
	json_value_sep(json);
	json_add_string(json, "op", op);
	json_value_sep(json);
	json_add_int(json, "i", i);
	json_value_sep(json);
	json_add_int(json, "j", j);
	json_value_sep(json);
	json_add_int(json, "nelem", nelem);
	json_value_sep(json);
	json_add_int(json, "was", was);
	json_value_sep(json);
	json_add_int(json, "len", now);
	json_value_sep(json);

	if (defer_log) {
		pending_log = json;
		pending_target = key;
		pending_case_id = case_id;
	} else {
		fuzz_emit(json, reply, now);
	}
}


/*
 * Rearrange the chain without inventing an element: delete the i'th, duplicate
 * the i'th, or swap the i'th and j'th.
 *
 * These are the shape changes no in-place octet mutation can express. A parser
 * that walks a chain positionally, or re-reads an offset a prior step should
 * have advanced, misbehaves when the chain's shape differs from the one it
 * expected -- and the shape is exactly what a length-preserving byte sweep
 * leaves alone.
 */
static size_t fuzz_chain_op(u8 *buf, size_t len, size_t capacity,
			    const u16 *offs, size_t nelem, size_t n,
			    const char **op, size_t *oi, size_t *oj)
{
	size_t i, j, isize, jsize;
	u8 tmp[2 + 255];

	if (n < nelem) {
		/* delete i */
		i = n;
		isize = 2 + buf[offs[i] + 1];
		os_memmove(buf + offs[i], buf + offs[i] + isize,
			   len - offs[i] - isize);
		*op = "delete";
		*oi = i;
		*oj = i;
		return len - isize;
	}

	n -= nelem;
	if (n < nelem) {
		/* duplicate i */
		i = n;
		isize = 2 + buf[offs[i] + 1];
		if (len + isize > capacity || isize > sizeof(tmp))
			return len;
		os_memcpy(tmp, buf + offs[i], isize);
		os_memmove(buf + offs[i] + isize, buf + offs[i],
			   len - offs[i]);
		os_memcpy(buf + offs[i], tmp, isize);
		*op = "duplicate";
		*oi = i;
		*oj = i;
		return len + isize;
	}

	/* swap i and j, over every unordered pair, i < j */
	n -= nelem;
	for (i = 0; i < nelem; i++) {
		size_t pairs = nelem - 1 - i;

		if (n < pairs) {
			j = i + 1 + n;
			break;
		}
		n -= pairs;
	}
	if (i >= nelem)
		return len;

	isize = 2 + buf[offs[i] + 1];
	jsize = 2 + buf[offs[j] + 1];
	if (isize > sizeof(tmp) || jsize > sizeof(tmp))
		return len;

	/* Rebuilding the span from i to j is simpler than moving three pieces
	 * in place, and the span is bounded by the frame. */
	{
		u8 span[1024];
		size_t span_len = offs[j] + jsize - offs[i], w = 0;
		size_t mid = offs[j] - (offs[i] + isize);

		if (span_len > sizeof(span))
			return len;
		os_memcpy(span, buf + offs[j], jsize);
		w = jsize;
		os_memcpy(span + w, buf + offs[i] + isize, mid);
		w += mid;
		os_memcpy(span + w, buf + offs[i], isize);
		os_memcpy(buf + offs[i], span, span_len);
	}

	*op = "swap";
	*oi = i;
	*oj = j;

	return len;
}


static size_t apply_mutation_int(const char *target, enum fuzz_frame_type type,
				 u8 *reply, size_t len, size_t capacity,
				 size_t chain_off, int defer_log)
{
	struct fuzz_entry *case_entry;
	size_t non_fuzzed_header_size = 0, fuzz_len, idx, new_len;
	size_t nelem = 0, npos = 1, max_body = 0, room, off = 0;
	size_t nfield = 0, nopaque = 0;
	char peerbuf[20];
	const char *peer;
	u16 offs[FUZZ_MAX_ELEMS];
	u16 fieldv[FUZZ_MAX_FIELDS], opaquev[FUZZ_MAX_FIELDS];
	struct wpabuf *json_output;
	u8 *relevant_reply, *b, mask;
	s64 case_id, case_max, rem, n;
	s64 sizes[FUZZ_NUM_DOMAINS];
	enum fuzz_domain kind;
	static int inventory_done = 0;
	int held;

	if (!fuzz_enabled())
		return len;

	/* Emitted here rather than from an init hook so that fuzz.c keeps its
	 * single entry point: there is no fuzz_init() for a caller to forget. */
	if (!inventory_done) {
		inventory_done = 1;
		fuzz_report_inventory();
	}

	if (len == 0)
		return len;

	if (!reply)
		return len;

	/* A caller that did not opt in passes capacity == len, and then the
	 * length domain is empty and every case below is the one it was
	 * before. That is what keeps apply_mutation() bit-identical. */
	if (capacity < len)
		capacity = len;

	/* A frame mutated on a previous call was abandoned before it could be
	 * sent (an error path between mutation and transmission). Report the
	 * case as lost -- it was announced through "progress" but never put on
	 * the air -- and drop its held-back log rather than attaching it to
	 * this frame. */
	if (pending_log) {
		fuzz_report_abandoned(pending_target ? pending_target :
				      "unknown", pending_case_id);
		wpabuf_free(pending_log);
		pending_log = NULL;
		pending_target = NULL;
	}

	case_entry = fuzz_dict_get(target);
	if (!case_entry) {
		/* Resuming skips the warm-up: when replaying a crash you want
		 * the mutation on the first frame, not nine clean ones. */
		int start = fuzz_start_case(target);

		case_id = start > 0 ? start : FUZZ_FIRST_CASE_ID;
		case_entry = fuzz_dict_set(target, case_id);
		if (!case_entry)
			return len;
		case_entry->held = fuzz_hold_target(target);
		if (start > 0)
			fuzz_report_resume(target, start);
	} else if (case_entry->held) {
		/* A held target consumes no cases, so its counter does not
		 * move and its case space is still there for a later run. */
		case_id = case_entry->value;
	} else {
		case_id = case_entry->value + 1;
		case_entry->value = case_id;
	}

	held = case_entry->held;

	if (type == FUZZ_TYPE_IEEE80211_MGMT) {
		/* Skip the whole 802.11 header: mutating bssid or seq_ctrl only
		 * gets the frame dropped by the peer before it is parsed. */
		non_fuzzed_header_size = IEEE80211_HDRLEN;
	}

	/* Nothing left to fuzz once the header is skipped; guard against the
	 * subtraction below wrapping around. */
	if (len <= non_fuzzed_header_size)
		return len;

	relevant_reply = reply + non_fuzzed_header_size;
	fuzz_len = len - non_fuzzed_header_size;

	/* Consumed here, once, so a hint cannot survive into another frame --
	 * including the frames that return early above, which is why the
	 * clearing is unconditional rather than part of a success path. */
	peer = fuzz_peer_of(type, reply, len, peerbuf, sizeof(peerbuf));
	fuzz_cur_peer = peer;

	/* Total number of distinct cases for a frame of this length: every
	 * byte of the fuzzable region taken through all 255 masks, plus -- when
	 * the caller gave us room -- every length in 0..capacity but the one
	 * the frame already has. */
	os_memset(sizes, 0, sizeof(sizes));
	sizes[FUZZ_DOMAIN_BYTE] = (s64) fuzz_len * CASES_PER_OFFSET;
	sizes[FUZZ_DOMAIN_LEN] = capacity > len ? (s64) capacity : 0;

	/* The element domains need somewhere to put an element, and somewhere
	 * to put it IN -- a caller that did not say where the chain starts
	 * gets neither, rather than an element inserted at an offset chosen by
	 * misreading whatever is there. */
	room = capacity > len ? capacity - len : 0;
	if (chain_off < len && room >= FUZZ_ELEM_OVERHEAD) {
		nelem = fuzz_walk_elements(reply + chain_off,
					   len - chain_off, offs,
					   FUZZ_MAX_ELEMS);
		/* A region that is not a clean chain still has one real
		 * insertion point: the end of the frame. */
		npos = nelem ? nelem + 1 : 1;

		max_body = room - FUZZ_ELEM_OVERHEAD;
		if (max_body > 255)
			max_body = 255;

		sizes[FUZZ_DOMAIN_ELEM] = (s64) fuzz_num_ids() * npos *
			(max_body + 1);
		sizes[FUZZ_DOMAIN_MULT] = (s64) fuzz_num_ids() * npos *
			(FUZZ_MULT_MAX - FUZZ_MULT_MIN + 1);
		if (nelem)
			sizes[FUZZ_DOMAIN_CHAIN] = (s64) nelem * 2 +
				(s64) nelem * (nelem - 1) / 2;
	}

	/* The named fields of this frame, each taken through its own domain
	 * rather than through the octets it occupies. */
	nfield = fuzz_collect_fields(type, reply, len, non_fuzzed_header_size,
				     fieldv, FUZZ_MAX_FIELDS, 0);
	for (idx = 0; idx < nfield; idx++)
		sizes[FUZZ_DOMAIN_FIELD] +=
			fuzz_field_cases(&fuzz_fields[fieldv[idx]]);

	nopaque = fuzz_collect_fields(type, reply, len, non_fuzzed_header_size,
				      opaquev, FUZZ_MAX_FIELDS, 1);
	sizes[FUZZ_DOMAIN_PATTERN] = (s64) nopaque * FUZZ_PATTERN_COUNT;

	case_max = 0;
	for (idx = 0; idx < FUZZ_NUM_DOMAINS; idx++)
		case_max += sizes[idx];

	if (case_id > case_max)
		case_id = case_max; /* lock it to max value */

	json_output = fuzz_report_start("progress", os_strlen(target));
	if (!json_output)
		return len;

	json_value_sep(json_output);
	json_add_int(json_output, "case_id", case_id);
	json_value_sep(json_output);
	json_add_int(json_output, "case_max", case_max);
	json_value_sep(json_output);
	json_add_string(json_output, "target", target);
	json_value_sep(json_output);
	json_add_string(json_output, "state",
			fuzz_state(held, case_id, case_max));
	json_value_sep(json_output);
	json_add_string(json_output, "order",
			fuzz_sweep_depth_first() ? "depth" : "breadth");
	json_value_sep(json_output);
	fuzz_add_opset(json_output);
	json_add_int(json_output, "fields", nfield + nopaque);
	if (peer) {
		json_value_sep(json_output);
		json_add_string(json_output, "peer", peer);
	}
	fuzz_report_end(json_output);

	/* A held target is answered correctly, so the frame goes out as built:
	 * announced above, and deliberately unmutated. */
	if (held || case_id < 0 || case_id >= case_max)
		return len;

	kind = fuzz_case_select(case_id, sizes, &n);

	if (kind == FUZZ_DOMAIN_ELEM || kind == FUZZ_DOMAIN_MULT) {
		size_t which, at, body_len, copies;

		/* Identity varies fastest, so a run cut short has covered
		 * every id before it has covered any id twice. */
		which = (size_t) (n % (s64) fuzz_num_ids());
		n /= (s64) fuzz_num_ids();
		at = (size_t) (n % (s64) npos);
		n /= (s64) npos;

		if (kind == FUZZ_DOMAIN_ELEM) {
			body_len = (size_t) n;
			copies = 1;
		} else {
			body_len = 0;
			copies = FUZZ_MULT_MIN + (size_t) n;
		}

		/* Insertion point 'at': before element at, or -- when at ==
		 * nelem, and always when the region was not a chain -- the
		 * end of the frame. */
		off = nelem && at < nelem ? chain_off + offs[at] : len;
		new_len = fuzz_insert_element(reply, len, capacity, off,
					      which, body_len, copies);

		fuzz_report_elem(target, non_fuzzed_header_size,
				 fuzz_frame_kind(type), len, new_len,
				 which, body_len, at, npos, copies, off,
				 defer_log, reply, case_entry->key, case_id);

		return new_len;
	}

	if (kind == FUZZ_DOMAIN_CHAIN) {
		const char *op = "none";
		size_t oi = 0, oj = 0;

		new_len = fuzz_chain_op(reply + chain_off, len - chain_off,
					capacity - chain_off, offs, nelem,
					(size_t) n, &op, &oi, &oj) + chain_off;

		fuzz_report_chain(target, non_fuzzed_header_size,
				  fuzz_frame_kind(type), len, new_len,
				  op, oi, oj, nelem, defer_log, reply,
				  case_entry->key, case_id);

		return new_len;
	}

	if (kind == FUZZ_DOMAIN_FIELD || kind == FUZZ_DOMAIN_PATTERN) {
		const u16 *v = kind == FUZZ_DOMAIN_FIELD ? fieldv : opaquev;
		size_t nv = kind == FUZZ_DOMAIN_FIELD ? nfield : nopaque;
		s64 per[FUZZ_MAX_FIELDS];
		size_t which;
		s64 k;

		for (idx = 0; idx < nv; idx++)
			per[idx] = kind == FUZZ_DOMAIN_FIELD ?
				fuzz_field_cases(&fuzz_fields[v[idx]]) :
				FUZZ_PATTERN_COUNT;

		/* The same round robin as the outer one, one level down, so
		 * the field's identity varies fastest: a run cut short has
		 * touched every field of the frame before it has touched any
		 * field twice. Which matters here more than anywhere -- a
		 * 65,536-value field would otherwise bury every field after
		 * it. */
		which = fuzz_round_robin(n, per, nv, &k);
		if (which < nv) {
			const struct fuzz_field *f = &fuzz_fields[v[which]];

			if (kind == FUZZ_DOMAIN_FIELD) {
				u64 built = fuzz_field_read(reply, f);
				u64 want = fuzz_field_value(f, built, k);

				fuzz_field_write(reply, f, want);
				fuzz_report_field(target,
						  non_fuzzed_header_size,
						  fuzz_frame_kind(type), len,
						  f, built, want,
						  fuzz_tier_name(
							  fuzz_field_domain(f)),
						  defer_log, reply,
						  case_entry->key, case_id);
			} else {
				fuzz_fill_pattern(reply + f->offset, f->width,
						  (size_t) k);
				fuzz_report_pattern(target,
						    non_fuzzed_header_size,
						    fuzz_frame_kind(type), len,
						    f, (size_t) k, defer_log,
						    reply, case_entry->key,
						    case_id);
			}
		}

		return len;
	}

	if (kind == FUZZ_DOMAIN_LEN) {
		new_len = fuzz_resize_length(n, len);

		/* Growth is filled with a constant rather than with anything
		 * derived from the case, so that this domain is swept
		 * independently of what the new octets say. What they say is a
		 * domain of its own and not this one; mixing the two would
		 * mean neither is enumerated. */
		if (new_len > len)
			os_memset(reply + len, 0, new_len - len);

		fuzz_report_resize(target, non_fuzzed_header_size,
				   fuzz_frame_kind(type), len,
				   new_len, defer_log, reply,
				   case_entry->key, case_id);

		return new_len;
	}

	/* Deterministic (offset, mask) selection: see CASES_PER_OFFSET */
	if (fuzz_sweep_depth_first()) {
		idx = n / CASES_PER_OFFSET;
		rem = n % CASES_PER_OFFSET;
	} else {
		idx = (size_t) (n % (s64) fuzz_len);
		rem = n / (s64) fuzz_len;
	}

	b = relevant_reply + idx;
	mask = fuzz_xor_mask(*b, (size_t) rem);

	/* Sized from len because the frame is hexdumped in full (headers
	 * included) -- wpabuf overflow calls abort(), which would look like a
	 * target crash. */
	json_output = fuzz_report_start("fuzz", 2 * len + os_strlen(target));
	if (!json_output)
		return len;

	fuzz_report_common(json_output, target, non_fuzzed_header_size,
			   fuzz_frame_kind(type));
	json_add_int(json_output, "idx", idx);
	json_value_sep(json_output);

	/* "idx" is relative to the fuzzable region; "hdr", emitted above with
	 * the rest of the prologue, is the offset between it and "data",
	 * which is the whole frame. Undoing the mutation at hdr + idx is how a
	 * consumer recovers the frame as hostapd built it, which is the only
	 * record of what the running configuration actually emits.
	 *
	 * "type" says which kind of mutation this is; there are five. */
	json_add_string(json_output, "type", "MUT_BYTE_XOR");
	json_value_sep(json_output);
	json_add_int(json_output, "mask", mask);
	json_value_sep(json_output);
	json_add_int(json_output, "before", *b);
	json_value_sep(json_output);

	*b ^= mask;

	json_add_int(json_output, "after", *b);
	json_value_sep(json_output);

	if (defer_log) {
		pending_log = json_output;
		pending_target = case_entry->key;
		pending_case_id = case_id;
	} else {
		fuzz_emit(json_output, reply, len);
	}

	return len;
}


void apply_mutation(const char *target, enum fuzz_frame_type type, u8 *reply,
		    size_t len)
{
	apply_mutation_int(target, type, reply, len, len, SIZE_MAX, 0);
}


/*
 * As apply_mutation(), but the caller has room beyond 'len' and is willing to
 * send a frame of a different length, so the length domain is in play.
 * Returns the length to send, which is <= capacity and never anything else.
 *
 * A call site opts in by having the headroom and by using the return value.
 * One that does neither is unchanged, which is why this is a second entry
 * point rather than a wider signature on the first.
 */
size_t apply_mutation_resize(const char *target, enum fuzz_frame_type type,
			     u8 *buf, size_t len, size_t capacity)
{
	return apply_mutation_int(target, type, buf, len, capacity, SIZE_MAX,
				  0);
}


/*
 * As apply_mutation_resize(), and in addition the caller says at what offset
 * the frame's element chain begins, which puts the element domains in play.
 *
 * The offset has to come from the caller because only the caller knows the
 * frame's layout: a management frame's variable part is an element chain for
 * some frames and begins with fixed fields for others, and the octets of a
 * scalar parse as plausible elements. A caller that does not know passes
 * apply_mutation_resize() instead and gets the octet and length domains, which
 * is strictly what it had before.
 */
size_t apply_mutation_elements(const char *target, enum fuzz_frame_type type,
			       u8 *buf, size_t len, size_t capacity,
			       size_t chain_off)
{
	return apply_mutation_int(target, type, buf, len, capacity, chain_off,
				  0);
}


void apply_mutation_defer_log(const char *target, enum fuzz_frame_type type,
			      u8 *reply, size_t len)
{
	apply_mutation_int(target, type, reply, len, len, SIZE_MAX, 1);
}
