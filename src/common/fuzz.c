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


void fuzz_log_sent_frame(const u8 *buf, size_t len)
{
	struct wpabuf *json = pending_log;

	if (!json)
		return;

	pending_log = NULL;
	pending_target = NULL;
	fuzz_emit(json, buf, len);
}


static void apply_mutation_int(const char *target, enum fuzz_frame_type type,
			       u8 *reply, size_t len, int defer_log)
{
	struct fuzz_entry *case_entry;
	size_t non_fuzzed_header_size = 0, fuzz_len, idx;
	struct wpabuf *json_output;
	u8 *relevant_reply, *b, mask;
	s64 case_id, case_max, rem;
	int held;

	if (!fuzz_enabled())
		return;

	if (len == 0)
		return;

	if (!reply)
		return;

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
			return;
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
		return;

	relevant_reply = reply + non_fuzzed_header_size;
	fuzz_len = len - non_fuzzed_header_size;

	/* Total number of distinct cases for a frame of this length. */
	case_max = (s64) fuzz_len * CASES_PER_OFFSET;

	if (case_id > case_max)
		case_id = case_max; /* lock it to max value */

	json_output = fuzz_report_start("progress", os_strlen(target));
	if (!json_output)
		return;

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
	fuzz_report_end(json_output);

	/* A held target is answered correctly, so the frame goes out as built:
	 * announced above, and deliberately unmutated. */
	if (held || case_id < 0 || case_id >= case_max)
		return;

	/* Deterministic (offset, mask) selection: see CASES_PER_OFFSET */
	if (fuzz_sweep_depth_first()) {
		idx = case_id / CASES_PER_OFFSET;
		rem = case_id % CASES_PER_OFFSET;
	} else {
		idx = (size_t) (case_id % (s64) fuzz_len);
		rem = case_id / (s64) fuzz_len;
	}

	b = relevant_reply + idx;
	mask = fuzz_xor_mask(*b, (size_t) rem);

	/* Sized from len because the frame is hexdumped in full (headers
	 * included) -- wpabuf overflow calls abort(), which would look like a
	 * target crash. */
	json_output = fuzz_report_start("fuzz", 2 * len + os_strlen(target));
	if (!json_output)
		return;

	json_value_sep(json_output);
	json_add_string(json_output, "target", target);
	json_value_sep(json_output);
	json_add_string(json_output, "order",
			fuzz_sweep_depth_first() ? "depth" : "breadth");
	json_value_sep(json_output);
	json_add_int(json_output, "idx", idx);
	json_value_sep(json_output);

	/* "type" is carried for the consumers that switch on it, and so that a
	 * kind added later is distinguishable; there is only the one now. */
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
}


void apply_mutation(const char *target, enum fuzz_frame_type type, u8 *reply,
		    size_t len)
{
	apply_mutation_int(target, type, reply, len, 0);
}


void apply_mutation_defer_log(const char *target, enum fuzz_frame_type type,
			      u8 *reply, size_t len)
{
	apply_mutation_int(target, type, reply, len, 1);
}
