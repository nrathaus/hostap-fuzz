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
#include "fuzz_layout.h"
#define FUZZ_CHAINS_TABLES
#include "fuzz_chains.h"
#include "fuzz_targets.h"
#include "fuzz_sources.h"
#include "fuzz_minima.h"
#include "fuzz_config.h"
#include "version.h"

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
/*
 * Room for every field of a report that is not the hexdump.
 *
 * wpabuf ABORTS on overflow rather than growing, so this number is not a
 * tuning parameter: it is the whole margin between a run and a core dump, and
 * every key added to any report below spends some of it. It was 256, which
 * covered the fields of the day with ONE CHARACTER to spare -- lengthening
 * the opset string by a digit was enough to find that out, in the resize
 * report, which had nothing to do with the change. A margin that small is
 * indistinguishable from none.
 */
#define FUZZ_REPORT_SLACK 2048

static struct wpabuf * fuzz_report_start(const char *msg, size_t extra)
{
	struct wpabuf *json = wpabuf_alloc(extra + FUZZ_REPORT_SLACK);

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
 * if the generated header and the tree disagree. Regenerate with:
 *
 *	python3 fuzzing/ledger/targets.py . --emit-c > src/common/fuzz_targets.h
 *
 * The table lives in src/common/fuzz_targets.h because each entry is wrapped
 * in the build condition of its own call site, so what this binary announces
 * is what this binary contains. An entry the build excludes is NULL and keeps
 * its index, which is what lets the roster beside it say why.
 */


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
 *
 * Three things go out, not one, because "this target produced no case" has
 * three causes and only one of them is interesting:
 *
 *   daemon   which binary is speaking. A run with a hooked AP and a hooked
 *            station has two of these and the consumer unions them.
 *   targets  what THIS binary contains, from the guarded table.
 *   roster   every label the tree has, with the condition under which it
 *            exists, so a label missing from every daemon's inventory is
 *            reported as absent from the build rather than as never reached.
 *
 * The guard strings are generated C expressions. They can contain characters
 * JSON cares about, so unlike the labels they are escaped on the way out.
 */
static void fuzz_json_escaped(struct wpabuf *json, const char *s)
{
	const char *p;

	for (p = s; *p; p++) {
		if (*p == '"' || *p == '\\')
			wpabuf_printf(json, "\\%c", *p);
		else if ((unsigned char) *p < 0x20)
			wpabuf_printf(json, "\\u%04x", (unsigned char) *p);
		else
			wpabuf_printf(json, "%c", *p);
	}
}


static void fuzz_report_inventory(void)
{
	struct wpabuf *json;
	size_t i, extra = 0;
	int first;

	for (i = 0; i < ARRAY_SIZE(fuzz_known_targets); i++)
		if (fuzz_known_targets[i])
			extra += os_strlen(fuzz_known_targets[i]) + 4;
	for (i = 0; i < ARRAY_SIZE(fuzz_known_stages); i++)
		extra += os_strlen(fuzz_known_stages[i]) + 4;
	for (i = 0; i < ARRAY_SIZE(fuzz_source_roster); i++) {
		extra += os_strlen(fuzz_source_roster[i].name) + 16;
		if (fuzz_source_roster[i].guard)
			extra += 2 * os_strlen(fuzz_source_roster[i].guard) + 16;
	}
	for (i = 0; i < ARRAY_SIZE(fuzz_target_roster); i++) {
		extra += os_strlen(fuzz_target_roster[i].name) + 16;
		if (fuzz_target_roster[i].guard)
			extra += 2 * os_strlen(fuzz_target_roster[i].guard) + 16;
	}
	extra += os_strlen(VERSION_STR) + 16;
	for (i = 0; fuzz_config_on[i]; i++)
		extra += os_strlen(fuzz_config_on[i]) + 4;
	for (i = 0; i < ARRAY_SIZE(fuzz_config_roster); i++)
		extra += os_strlen(fuzz_config_roster[i].name) + 24;
	for (i = 0; i < ARRAY_SIZE(fuzz_action_layouts); i++)
		extra += os_strlen(fuzz_action_layouts[i].member) + 32;
	for (i = 0; fuzz_action_layouts_refused[i]; i++)
		extra += os_strlen(fuzz_action_layouts_refused[i]) + 4;
	for (i = 0; i < ARRAY_SIZE(fuzz_field_readers); i++) {
		size_t k;

		extra += os_strlen(fuzz_field_readers[i].fn) +
			os_strlen(fuzz_field_readers[i].file) + 32;
		for (k = 0; fuzz_field_readers[i].reads[k]; k++)
			extra += os_strlen(fuzz_field_readers[i].reads[k]) + 4;
	}
	for (i = 0; i < ARRAY_SIZE(fuzz_var_fields); i++)
		extra += os_strlen(fuzz_var_fields[i].name) +
			os_strlen(fuzz_var_fields[i].gap) + 64;
	for (i = 0; i < ARRAY_SIZE(fuzz_chains); i++) {
		extra += os_strlen(fuzz_chains[i].name) +
			os_strlen(fuzz_chains[i].walker) +
			os_strlen(fuzz_chains[i].file) + 64;
		if (fuzz_chains[i].guard)
			extra += 2 * os_strlen(fuzz_chains[i].guard) + 16;
	}

	json = fuzz_report_start("inventory", extra);
	if (!json)
		return;

	json_value_sep(json);
#ifdef HOSTAPD
	wpabuf_printf(json, "\"daemon\":\"hostapd\"");
#else /* HOSTAPD */
	wpabuf_printf(json, "\"daemon\":\"wpa_supplicant\"");
#endif /* HOSTAPD */

	json_value_sep(json);
	json_start_array(json, "targets");
	first = 1;
	for (i = 0; i < ARRAY_SIZE(fuzz_known_targets); i++) {
		if (!fuzz_known_targets[i])
			continue;	/* excluded by this build */
		if (!first)
			json_value_sep(json);
		first = 0;
		wpabuf_printf(json, "\"%s\"", fuzz_known_targets[i]);
	}
	json_end_array(json);

	json_value_sep(json);
	json_start_array(json, "roster");
	for (i = 0; i < ARRAY_SIZE(fuzz_target_roster); i++) {
		if (i)
			json_value_sep(json);
		wpabuf_printf(json, "{\"name\":\"%s\",\"guard\":",
			      fuzz_target_roster[i].name);
		if (fuzz_target_roster[i].guard) {
			wpabuf_printf(json, "\"");
			fuzz_json_escaped(json, fuzz_target_roster[i].guard);
			wpabuf_printf(json, "\"");
		} else {
			wpabuf_printf(json, "null");
		}
		wpabuf_printf(json, "}");
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

	/*
	 * W14. How many distinct source addresses this run was asked for, and
	 * which identities could carry them.
	 *
	 * The number is announced rather than left to be inferred from the
	 * 'source' messages, because the interesting failure is the one where
	 * there are NONE of those: FUZZ_ADDRS was set, nothing in the run
	 * changed an address, and a report that only counted what it saw
	 * would say the same thing it says for a run that never asked.
	 */
	json_value_sep(json);
	json_add_int(json, "addrs", fuzz_env_int("FUZZ_ADDRS", 0));

	json_value_sep(json);
	json_start_array(json, "sources");
	first = 1;
	for (i = 0; i < ARRAY_SIZE(fuzz_sources_present); i++) {
		if (!fuzz_sources_present[i])
			continue;	/* excluded by this build */
		if (!first)
			json_value_sep(json);
		first = 0;
		wpabuf_printf(json, "\"%s\"", fuzz_sources_present[i]);
	}
	json_end_array(json);

	json_value_sep(json);
	json_start_array(json, "source_roster");
	for (i = 0; i < ARRAY_SIZE(fuzz_source_roster); i++) {
		if (i)
			json_value_sep(json);
		wpabuf_printf(json, "{\"name\":\"%s\",\"guard\":",
			      fuzz_source_roster[i].name);
		if (fuzz_source_roster[i].guard) {
			wpabuf_printf(json, "\"");
			fuzz_json_escaped(json, fuzz_source_roster[i].guard);
			wpabuf_printf(json, "\"");
		} else {
			wpabuf_printf(json, "null");
		}
		wpabuf_printf(json, "}");
	}
	json_end_array(json);

	/*
	 * W15. The compile-time axis: what this binary was BUILT with.
	 *
	 * The run-time domains above all say what was swept. This one says
	 * what existed to sweep. A run built without a flag finds nothing in
	 * the code that flag would have compiled in, and reports it in
	 * exactly the words it uses for code it swept and cleared; the two
	 * are opposite results and only this list tells them apart.
	 *
	 * 'version' goes with it because the flags are only half of a build's
	 * identity, and a number from one build is not comparable to a number
	 * from another without both.
	 *
	 * The roster is announced as well as the on-list, for the reason the
	 * target roster is: a flag absent from the on-list may be off, or may
	 * be one of the ones no binary can report -- 'witness' says which,
	 * and off and invisible are not the same answer.
	 */
	json_value_sep(json);
	json_add_string(json, "version", VERSION_STR);

	json_value_sep(json);
	json_start_array(json, "config");
	first = 1;
	for (i = 0; fuzz_config_on[i]; i++) {
		if (!first)
			json_value_sep(json);
		first = 0;
		wpabuf_printf(json, "\"%s\"", fuzz_config_on[i]);
	}
	json_end_array(json);

	/* [name, daemons, witness, stock, value] -- positional, because the
	 * roster is 272 entries long and naming each field five times over
	 * would be most of the message. The encoding is in fuzz_config.h. */
	json_value_sep(json);
	json_start_array(json, "config_roster");
	for (i = 0; i < ARRAY_SIZE(fuzz_config_roster); i++) {
		if (i)
			json_value_sep(json);
		wpabuf_printf(json, "[\"%s\",%u,%u,%u,%u]",
			      fuzz_config_roster[i].name,
			      fuzz_config_roster[i].daemons,
			      fuzz_config_roster[i].witness,
			      fuzz_config_roster[i].stock,
			      fuzz_config_roster[i].value);
	}
	json_end_array(json);

	/*
	 * W16. What the engine knows about the frame past the end of the
	 * struct, announced for the same reason every other roster is: the
	 * ledger subtracts what it saw from what existed, and a layout that
	 * is never named in a run is otherwise indistinguishable from a
	 * layout the tree does not have.
	 *
	 * The refusals go out too. A (category, code) that more than one
	 * union member claims is a key this engine declines to guess at, and
	 * a refusal nobody reports looks exactly like a category nobody uses.
	 */
	json_value_sep(json);
	json_start_array(json, "layouts");
	for (i = 0; i < ARRAY_SIZE(fuzz_action_layouts); i++) {
		if (i)
			json_value_sep(json);
		wpabuf_printf(json, "[\"%s\",%u,%d,%d,%u]",
			      fuzz_action_layouts[i].member,
			      fuzz_action_layouts[i].cat,
			      fuzz_action_layouts[i].code,
			      fuzz_action_layouts[i].chain_at,
			      fuzz_action_layouts[i].nfields);
	}
	json_end_array(json);

	/* The honesty figure, beside the layouts rather than instead of them:
	 * how many of the union's members anything in the tree binds to a
	 * category. A member the dispatch never names is not one this engine
	 * skipped; its frames keep the byte sweep, and a count without this
	 * denominator reads as coverage of the union. */
	json_value_sep(json);
	json_add_int(json, "layout_members", FUZZ_ACTION_UNION_MEMBERS);
	json_value_sep(json);
	json_add_int(json, "layout_bound", FUZZ_ACTION_MEMBERS_BOUND);

	json_value_sep(json);
	json_start_array(json, "layouts_refused");
	first = 1;
	for (i = 0; fuzz_action_layouts_refused[i]; i++) {
		if (!first)
			json_value_sep(json);
		first = 0;
		wpabuf_printf(json, "\"");
		fuzz_json_escaped(json, fuzz_action_layouts_refused[i]);
		wpabuf_printf(json, "\"");
	}
	json_end_array(json);

	/* [name, base, width, gap, [gap widths], exact] -- the field whose
	 * offset the engine solves for, and the candidate set it solves
	 * over. 'exact' 0 says the tree can produce a width this set does
	 * not contain, so a frame the solver cannot place is not
	 * necessarily a malformed one. */
	json_value_sep(json);
	json_start_array(json, "var_fields");
	for (i = 0; i < ARRAY_SIZE(fuzz_var_fields); i++) {
		const struct fuzz_var_field *vf = &fuzz_var_fields[i];
		unsigned int k;

		if (i)
			json_value_sep(json);
		wpabuf_printf(json, "[\"%s\",%u,%u,\"%s\",[",
			      vf->name, vf->base, vf->width, vf->gap);
		for (k = 0; k < vf->ngaps; k++)
			wpabuf_printf(json, "%s%u", k ? "," : "", vf->gaps[k]);
		wpabuf_printf(json, "],%d]", vf->gaps_exact);
	}
	json_end_array(json);

	/*
	 * W16d. The TLV formats this tree has, and the identity space behind
	 * each. Announced for the same reason the targets are: four of the
	 * five are what W9's hooks reach, their parsers are behind flags W15
	 * says are off in both shipped builds, and "no cases in this chain"
	 * has to be distinguishable from "no such chain here".
	 *
	 * [name, walker, hdr, id width, id le, len width, len le, members]
	 */
	json_value_sep(json);
	json_start_array(json, "chains");
	for (i = 0; i < ARRAY_SIZE(fuzz_chains); i++) {
		const struct fuzz_chain_fmt *f = &fuzz_chains[i];

		if (i)
			json_value_sep(json);
		wpabuf_printf(json,
			      "[\"%s\",\"%s\",%u,%u,%u,%u,%u,%u]",
			      f->name, f->walker, f->hdr, f->id_width,
			      f->id_le, f->len_width, f->len_le,
			      f->elem ? (unsigned int)
			      (ARRAY_SIZE(fuzz_elem_ids) +
			       ARRAY_SIZE(fuzz_elem_ext_ids) +
			       ARRAY_SIZE(fuzz_elem_extlen_ids)) :
			      f->nids);
	}
	json_end_array(json);

	/* [frame, role, function, file, [fields it reads]] -- which parser
	 * sees what this binary's opposite number transmits. A field swept
	 * against a receiver that never reads it is not weak coverage, it is
	 * none, and this is what lets the ledger say so. */
	json_value_sep(json);
	json_start_array(json, "readers");
	for (i = 0; i < ARRAY_SIZE(fuzz_field_readers); i++) {
		const struct fuzz_field_reader *r = &fuzz_field_readers[i];
		size_t k;

		if (i)
			json_value_sep(json);
		wpabuf_printf(json, "[\"%s\",\"%s\",\"%s\",\"%s\",[",
			      r->frame, r->role, r->fn, r->file);
		for (k = 0; r->reads[k]; k++)
			wpabuf_printf(json, "%s\"%s\"", k ? "," : "",
				      r->reads[k]);
		wpabuf_printf(json, "]]");
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
 * W14. How many distinct source addresses one peer presents in a run.
 *
 * FUZZ_ADDRS=N, 0 by default -- so a build with this compiled in behaves
 * exactly as it did until someone asks for the domain, the same contract
 * FUZZ_REPEAT_<STAGE> keeps.
 *
 * The cap is a sanity bound, not a property of the encoding: the varying
 * octets hold far more than this, and a run that asked for more identities
 * than this has asked for something other than what it meant.
 */
#define FUZZ_ADDRS_MAX (255 * 256 * 256)

/*
 * THE VALUE IS THE CASE NUMBER, placed in the address's varying octets, and
 * nothing else. No mixing constant, because there is nothing here to mix
 * for: what the state tables behind this domain are keyed on is the address
 * being DIFFERENT, and a counter is different by construction, reproducible
 * across runs, and printable in a repro record.
 *
 * THE LIMIT, stated because the number would otherwise be read as more than
 * it is: this does not claim to exercise how those tables HASH. Adjacent
 * addresses may land in adjacent buckets. The domain is occupancy and
 * eviction, which is what the tables are keyed on; distribution is not swept
 * and is not claimed.
 *
 * The last octet is never zero, and that is load-bearing rather than
 * cosmetic. Every mac80211_hwsim radio in the topologies here is addressed
 * 02:00:00:00:NN:00, so an address this produces cannot collide with one of
 * them -- and a station that took its AP's address would not be a case, it
 * would be a broken rig that looked like one.
 *
 * OCTET 0 IS NOT TOUCHED. It carries the field's structure and the caller's
 * own picker has just set it. Where that picker randomises it -- the style
 * that does not keep the OUI -- the run therefore presents MORE distinct
 * addresses than the domain asked for, and the ledger reports both numbers
 * rather than quietly reconciling them.
 */
static unsigned int fuzz_addr_changes;


int fuzz_source_addr(const char *who, u8 *addr)
{
	int n = fuzz_env_int("FUZZ_ADDRS", 0);
	struct wpabuf *json;
	char buf[20];
	unsigned int k, v;
	size_t i;

	if (!fuzz_enabled() || n <= 0)
		return 0;
	if (n > FUZZ_ADDRS_MAX)
		n = FUZZ_ADDRS_MAX;

	k = fuzz_addr_changes % (unsigned int) n;
	v = k;

	addr[ETH_ALEN - 1] = (u8) (v % 255 + 1);
	v /= 255;
	for (i = ETH_ALEN - 1; i > 1; i--) {
		addr[i - 1] = (u8) (v & 0xff);
		v >>= 8;
	}

	fuzz_addr_changes++;

	json = fuzz_report_start("source", os_strlen(who) + 64);
	if (!json)
		return 1;
	os_snprintf(buf, sizeof(buf), MACSTR, MAC2STR(addr));
	json_value_sep(json);
	json_add_string(json, "who", who);
	json_value_sep(json);
	json_add_string(json, "addr", buf);
	json_value_sep(json);
	json_add_int(json, "k", (int) k);
	json_value_sep(json);
	json_add_int(json, "of", n);
	json_value_sep(json);
	/* How many times an address has changed, against how many distinct
	 * values that was. A run that cycles a domain of four addresses
	 * twenty times has presented four identities, not twenty, and a
	 * report that could not tell those apart would be counting
	 * reconnections. */
	json_add_int(json, "changes", (int) fuzz_addr_changes);
	fuzz_report_end(json);

	return 1;
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
static const u8 *fuzz_claimed_buf;
static size_t fuzz_claimed_len;
static const char *fuzz_claimed_by;

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
 * None of the domains below is filtered to "legal in this frame". An element
 * appearing where it is not legal is a case worth sending; a legality filter is
 * exactly the hand-curation this engine exists to avoid.
 *
 *	identity	every member of the generated registries -- 183
 *			element ids, 57 extension ids and the extended
 *			length ids, read out of src/common/ieee802_11_defs.h
 *			by section, never typed
 *	position	every insertion point in the chain, before the first
 *			element and after the last included
 *	length		the element's declared length, honest -- the body
 *			follows it -- from 0 to what the headroom allows
 *	declared	the declared length ALONE, over the whole domain its
 *			shape's length field can express, with the body held
 *			at nothing. 0..255 for a one-octet length field and
 *			0..65535 for a two-octet one, which is why an element
 *			header needs the reduction tiers
 *	multiplicity	the same element present 2..5 times
 *	fragments	the element continued by Fragment elements, which is
 *			the only route to a body longer than its length field
 *			can say
 *	nesting		the element inside a container element's body, one
 *			and two levels down
 *
 * Identity varies fastest in every one of them, so a run that is cut short --
 * which against a real station is every run -- has covered every id before it
 * has covered any id twice. That ordering is what makes "all 241 ids reached"
 * a property of a short run rather than of a complete sweep.
 *
 * SHAPE IS NOT A PROPERTY OF THIS FILE. An element's header is two octets for
 * most ids, three for the extension id and five -- with a little-endian u16
 * length -- for the extended length id. Which id selects which is read out of
 * element_hdr_size() and the parse loop by fuzzing/ledger/registries.py and
 * arrives here as fuzz_elem_shapes[]. Building an id under the wrong shape is
 * not a weaker case than building it under the right one, it is a different
 * one: the parser takes its length from octets this engine filled with body,
 * the frame still goes out, the ledger still counts the id as reached, and the
 * length domain the run believes it swept is not the field the parser read.
 * Neither half is wrong on its own terms; together they report coverage of
 * something that did not happen.
 */

/* An element chain longer than this is walked up to here and no further. The
 * cap bounds the position domain; it is not a claim about what a chain may
 * contain. */
#define FUZZ_MAX_ELEMS 32

/* The same element, present this many times. Starts at 2 because once is what
 * the identity domain already covers. */
#define FUZZ_MULT_MIN 2
#define FUZZ_MULT_MAX 5

/* How many Fragment elements may continue one element. Bounded by headroom
 * first; this is the cap on top of that. */
#define FUZZ_FRAG_MAX 4

/* How far down the nesting domain goes. Depth 0 -- an element at the top of
 * the chain -- is the identity domain and is not repeated here. */
#define FUZZ_NEST_MAX 2

/* The largest thing this engine stages: the widest header any shape has, plus
 * the largest body a one-octet length field can declare, plus the Fragment
 * elements that may continue it. An extended length element can DECLARE far
 * more than this, and that its declaration and its contents are two different
 * things is the point of its domain, not a limitation of this buffer. */
#define FUZZ_ELEM_MAX (5 + 255 + FUZZ_FRAG_MAX * (2 + FUZZ_FRAG_PARENT_LEN))

/* Just a header, for the containers the nesting domain wraps around one. */
#define FUZZ_ELEM_HDR_MAX 8

/* Element overhead for the headroom test, taken before a shape is chosen:
 * the widest header of any shape, so one bound serves all three. */
#define FUZZ_ELEM_OVERHEAD 5


/*
 * One case's identity: which id, under which shape, carrying which member of
 * which sub-registry.
 *
 * The identity domain walks the three registries end to end -- element ids
 * first, then extension ids, then extended length ids -- because a consumer
 * asking "has every id been emitted" should not have to know which table an id
 * came from. The shape is not part of that choice: it follows from the id, as
 * it does in the tree.
 */
/*
 * W16d. One item's shape, RESOLVED: what the octets of a single item of this
 * chain look like once the element chain's per-id selection has been made.
 *
 * The element chain has three of these and picks between them by the id. The
 * other four formats have one each, and that is not a simplification made
 * here -- it is what their walkers do. Everything downstream reads this
 * struct and not the format, so the builder, the walker and the length
 * domain are one code path for all five.
 */
struct fuzz_shape {
	u8 hdr;
	u8 id_off, id_width, id_le;
	u8 len_off, len_width, len_le;
	u8 extid_off, extid_width, extid_le;
	u8 covers;
};


struct fuzz_ident {
	u16 id;
	u16 sub;		/* the sub-registry member, when the shape
				 * carries one */
	u8 has_sub;		/* the shape carries a sub-registry id */
	enum fuzz_elem_shape shape;
	/* Which chain this identity was drawn from, and what one item of it
	 * looks like. Carried on the identity rather than passed beside it,
	 * because every function below needs both and a pair that can be
	 * separated is a pair that will be. */
	const struct fuzz_chain_fmt *chain;
	struct fuzz_shape sh;
	const char *reg;	/* the registry this identity was drawn from */
	u8 min_reg;		/* ... as the minima table keys it. Set where
				 * the registry is already known rather than
				 * recovered by comparing 'reg' against three
				 * strings, which would be a second place for
				 * the mapping to be wrong. */
	const char *subkey;	/* what to report 'sub' under, or NULL */
	const char *name;	/* what the tree calls this member, so a crash
				 * record reads as a name and not as a number
				 * somebody has to go and look up in a header
				 * that is not in the bug report */
	const char *subname;
};


static enum fuzz_elem_shape fuzz_shape_of(u8 id)
{
	if (id == FUZZ_EID_EXT)
		return FUZZ_SHAPE_EXT;
	if (id == FUZZ_EID_EXTLEN)
		return FUZZ_SHAPE_EXTLEN;

	return FUZZ_SHAPE_BASIC;
}


/* Which of this chain's shapes an item with this id takes. One for every
 * chain but the element chain, where the id selects between three. */
static size_t fuzz_shape_index(const struct fuzz_chain_fmt *fmt, u16 id)
{
	return fmt->elem ? (size_t) fuzz_shape_of((u8) id) : 0;
}


static void fuzz_shape_at(const struct fuzz_chain_fmt *fmt, size_t which,
			  struct fuzz_shape *out)
{
	os_memset(out, 0, sizeof(*out));

	if (!fmt->elem) {
		out->hdr = fmt->hdr;
		out->id_off = fmt->id_off;
		out->id_width = fmt->id_width;
		out->id_le = fmt->id_le;
		out->len_off = fmt->len_off;
		out->len_width = fmt->len_width;
		out->len_le = fmt->len_le;
		return;
	}

	if (which >= FUZZ_NUM_SHAPES)
		which = FUZZ_SHAPE_BASIC;
	out->hdr = fuzz_elem_shapes[which].hdr;
	/* An element id is one octet at offset zero. The shape table says so
	 * by having no id columns at all, which is true of that chain and of
	 * nothing else here. */
	out->id_off = 0;
	out->id_width = 1;
	out->id_le = 0;
	out->len_off = fuzz_elem_shapes[which].len_off;
	out->len_width = fuzz_elem_shapes[which].len_width;
	out->len_le = fuzz_elem_shapes[which].len_le;
	out->extid_off = fuzz_elem_shapes[which].extid_off;
	out->extid_width = fuzz_elem_shapes[which].extid_width;
	out->extid_le = fuzz_elem_shapes[which].extid_le;
	out->covers = fuzz_elem_shapes[which].covers;
}


static const struct fuzz_chain_fmt * fuzz_chain_of(enum fuzz_chain which)
{
	if ((size_t) which >= ARRAY_SIZE(fuzz_chains))
		return &fuzz_chains[FUZZ_CHAIN_ELEM];

	return &fuzz_chains[which];
}


static size_t fuzz_num_ids(const struct fuzz_chain_fmt *fmt)
{
	if (!fmt->elem)
		return fmt->nids;

	return ARRAY_SIZE(fuzz_elem_ids) + ARRAY_SIZE(fuzz_elem_ext_ids) +
		ARRAY_SIZE(fuzz_elem_extlen_ids);
}


static void fuzz_identity(const struct fuzz_chain_fmt *fmt, size_t which,
			  struct fuzz_ident *out)
{
	size_t n1 = ARRAY_SIZE(fuzz_elem_ids);
	size_t n2 = ARRAY_SIZE(fuzz_elem_ext_ids);

	os_memset(out, 0, sizeof(*out));
	out->chain = fmt;

	if (!fmt->elem) {
		/* One registry, one shape, and no sub-registry: a WPS
		 * attribute type is a two-octet identity and nothing is
		 * nested inside it. The minima table is the element parser's
		 * and keys off element ids, so these carry a register number
		 * no entry of it has -- which makes fuzz_min_for() return 0
		 * rather than finding somebody else's row. */
		if (which >= fmt->nids)
			which = 0;
		out->id = fmt->nids ? fmt->ids[which] : 0;
		out->name = fmt->nids ? fmt->names[which] : "unnamed";
		out->reg = fmt->name;
		out->min_reg = 0xff;
		out->shape = 0;
		fuzz_shape_at(fmt, 0, &out->sh);
		return;
	}

	if (which < n1) {
		/* An element id, built under whatever shape its own value
		 * selects. Two of them select a shape with a sub-registry,
		 * and this segment does not choose a member of it -- the
		 * segments below do. The id still goes out, under its real
		 * shape, with a zero where the member would be. */
		out->id = fuzz_elem_ids[which];
		out->name = fuzz_elem_ids_names[which];
		out->reg = "element id";
		out->min_reg = FUZZ_MIN_REG_BASIC;
	} else if (which < n1 + n2) {
		out->id = FUZZ_EID_EXT;
		out->sub = fuzz_elem_ext_ids[which - n1];
		out->subname = fuzz_elem_ext_ids_names[which - n1];
		out->reg = "element id extension";
		out->min_reg = FUZZ_MIN_REG_EXT;
	} else {
		out->id = FUZZ_EID_EXTLEN;
		out->sub = fuzz_elem_extlen_ids[which - n1 - n2];
		out->subname = fuzz_elem_extlen_ids_names[which - n1 - n2];
		out->reg = "extended length element id";
		out->min_reg = FUZZ_MIN_REG_EXTLEN;
	}

	/* Segments two and three choose the sub-registry member and take the
	 * container id as given, so the container's own name is looked up
	 * rather than indexed. 183 comparisons, once per case. */
	if (!out->name) {
		size_t i;

		for (i = 0; i < ARRAY_SIZE(fuzz_elem_ids); i++) {
			if (fuzz_elem_ids[i] == out->id) {
				out->name = fuzz_elem_ids_names[i];
				break;
			}
		}
	}

	out->shape = (enum fuzz_elem_shape) fuzz_shape_index(fmt, out->id);
	fuzz_shape_at(fmt, out->shape, &out->sh);
	out->has_sub = out->sh.extid_width != 0;
	if (out->has_sub)
		out->subkey = out->shape == FUZZ_SHAPE_EXT ? "ext_id" :
			"extlen_id";
}


/* The n'th identity whose id selects this shape, or fuzz_num_ids() when there
 * is no such identity. A linear scan over 241 entries, once per case: the
 * alternative is a second table that has to be kept in step with the first,
 * which is the failure this file generates its tables to avoid. */
static size_t fuzz_nth_of_shape(const struct fuzz_chain_fmt *fmt,
				enum fuzz_elem_shape shape, size_t n)
{
	size_t i, total = fuzz_num_ids(fmt);

	for (i = 0; i < total; i++) {
		struct fuzz_ident id;

		fuzz_identity(fmt, i, &id);
		if (id.shape != shape)
			continue;
		if (n == 0)
			return i;
		n--;
	}

	return total;
}


static size_t fuzz_count_of_shape(const struct fuzz_chain_fmt *fmt,
				  enum fuzz_elem_shape shape)
{
	size_t i, total = fuzz_num_ids(fmt), n = 0;

	for (i = 0; i < total; i++) {
		struct fuzz_ident id;

		fuzz_identity(fmt, i, &id);
		if (id.shape == shape)
			n++;
	}

	return n;
}


static void fuzz_put_int(u8 *buf, size_t off, size_t width, int le, u32 v)
{
	size_t i;

	for (i = 0; i < width; i++) {
		size_t k = le ? i : width - 1 - i;

		buf[off + k] = (u8) (v >> (8 * i));
	}
}


static u32 fuzz_get_int(const u8 *buf, size_t off, size_t width, int le)
{
	u32 v = 0;
	size_t i;

	for (i = 0; i < width; i++) {
		size_t k = le ? width - 1 - i : i;

		v = (v << 8) | buf[off + k];
	}

	return v;
}


/* The domain of this shape's length field: 256 for a one-octet one, 65,536
 * for a two-octet one. The tiers take it from there. */
static s64 fuzz_shape_len_domain(const struct fuzz_shape *sh)
{
	return (s64) 1 << (8 * sh->len_width);
}


/*
 * W11. The ladder is in two halves, and the first of them is the reason this
 * item exists.
 *
 * A sampled domain has a distribution and a uniform one is a decision nobody
 * made. The distribution that earns its place in a LENGTH domain is the window
 * just above the minimum the parser enforces: a fixed-offset read behind a
 * `len >= N` guard is wrong, where it is wrong at all, for lengths in
 * N .. N+k for small k and nowhere else.
 *
 * Stating that as a probability would be wrong, and STRIDE is why. The stride
 * is verified deferral, not sampling -- every value is reached at exactly one
 * of its 251 offsets -- so a four-wide window is not UNLIKELY, it is
 * DEFERRED, deterministically, to one offset out of 251 that nothing orders
 * first. A campaign that completes all 251 covers it; every campaign that does
 * not misses it the same way every time, which is worse than randomness
 * because it is reproducible and so reads as a stable negative result.
 *
 * Which also says where the fix goes: not into the stride, into the LADDER,
 * which is hoisted to the front of every domain's case space and is the same
 * size at every stride offset. The window is reached in run 1.
 *
 * The minimums are generated into fuzz_minima.h from the tree's own parser,
 * for the same reason the element ids are: a hand-written copy of those
 * numbers detunes itself silently the first time upstream moves one, and a
 * detuned sweep reports clean.
 */
#define FUZZ_MIN_LADDER_N 10
#define FUZZ_EDGE_LADDER_N 8
#define FUZZ_LADDER_N (FUZZ_MIN_LADDER_N + FUZZ_EDGE_LADDER_N)

/*
 * The window, in the order a run that is cut short wants it.
 *
 * The plan states the offsets as a set -- {-2,-1,0,0,1,2,3,4,7,8} -- and the
 * order within the ladder is this file's to choose. It matters more than the
 * membership does: identity varies fastest, so an element id that a short run
 * touches once is built at offset 0 of this list and at no other. Taking the
 * list in numeric order would build it at minimum-2, which the guard rejects,
 * and 39 ids would be swept entirely below the lengths they exist to reach.
 * Measured, on the synthesis harness: in numeric order, 1 of the 39 ids with
 * a guard was built at or above it in a 400-case run and 9 of 39 in a
 * 4,000-case one. This way, 22 of 39 and 39 of 39.
 *
 * So: the minimum itself, then the window above it, then the two below that
 * test the guard, then the wider pair. The repeated 0 is the plan's tenth
 * entry and goes last, where a coinciding entry costs least.
 */
static const int fuzz_min_ladder[FUZZ_MIN_LADDER_N] = {
	0, 1, 2, 3, 4, -1, -2, 7, 8, 0
};


/*
 * The declared length this id's parser insists on, and the guard it came
 * from.
 *
 * The table states the guard as the parser sees it, against a variable that
 * is not always the declared length: the extension parser is handed a length
 * already advanced past the extension id, so a guard of N there is a declared
 * length of N + 1. 'past' carries that, generated from the parser's own `--`
 * rather than re-derived here from a header width that would agree by
 * coincidence and part company the day a shape changes.
 *
 * 0 when nothing enforces one, which is 202 of the 241 identities. Not an
 * error and not reported as a gap: most element ids are handed to a handler
 * that takes the length as it finds it.
 */
static u32 fuzz_min_for(const struct fuzz_ident *id,
			const struct fuzz_min_entry **why)
{
	/* The member of the registry this identity was DRAWN from, which is
	 * not the same question as whether its shape carries a sub-registry
	 * id. The two element ids that select a wider shape are themselves
	 * members of the basic registry, and they are built with a zero where
	 * a member of the sub-registry would be -- so keying off has_sub
	 * looks up member 0 of the wrong table and finds whatever is there.
	 * It found SSID_MAX_LEN. */
	u16 want = id->min_reg == FUZZ_MIN_REG_BASIC ? id->id : id->sub;
	size_t i;

	if (why)
		*why = NULL;

	for (i = 0; i < ARRAY_SIZE(fuzz_minima); i++) {
		const struct fuzz_min_entry *e = &fuzz_minima[i];

		if (e->reg != id->min_reg || e->id != want)
			continue;
		if (why)
			*why = e;
		return e->n + e->past;
	}

	return 0;
}


/*
 * The k'th value of an ENUMERATED length axis: a permutation of 0..max that
 * starts at the window around the parser's enforced minimum.
 *
 * The ladder is for domains this engine samples. An axis it enumerates needs
 * the other half of the same idea, because enumeration is not the same as
 * being reached: the element domain's length axis is the slowest of its
 * three, a one-octet declared length is FULL rather than sampled, and no run
 * this engine will have gets to the second value of either. An element id
 * whose parser wants 26 octets was therefore only ever built with 0,
 * rejected at the guard, and counted as sent.
 *
 * Reordering fixes that without costing a case: every value still appears
 * exactly once, so the count does not move, the axis is still a complete
 * enumeration, and a case_id still maps to exactly one frame.
 */
static u32 fuzz_window_first(u32 minimum, u32 max_body, s64 k)
{
	u32 window[FUZZ_MIN_LADDER_N];
	size_t nw = 0, i, j;
	u32 v;

	for (i = 0; i < FUZZ_MIN_LADDER_N; i++) {
		s64 w = (s64) minimum + fuzz_min_ladder[i];

		if (w < 0 || w > (s64) max_body)
			continue;
		for (j = 0; j < nw; j++) {
			if (window[j] == (u32) w)
				break;
		}
		if (j == nw)
			window[nw++] = (u32) w;
	}

	if (k < (s64) nw)
		return window[k];

	/* The k'th value of 0..max_body that the window did not already
	 * take. Linear, over at most 256 values, once per case. */
	k -= (s64) nw;
	for (v = 0; v <= max_body; v++) {
		for (j = 0; j < nw; j++) {
			if (window[j] == v)
				break;
		}
		if (j < nw)
			continue;
		if (!k--)
			return v;
	}

	return max_body;
}


/* The declared length that honestly describes this many octets of body. */
static u32 fuzz_declare_for(const struct fuzz_ident *id, size_t body)
{
	const struct fuzz_shape *sh = &id->sh;
	u64 d = (u64) body + (sh->covers ? sh->extid_width : 0);
	u64 max = (u64) fuzz_shape_len_domain(sh) - 1;

	return (u32) (d > max ? max : d);
}


/* The body a declared length of this size leaves room for, under this shape.
 * Under a shape whose length field covers the sub-registry id, the id eats
 * the first octets of what was declared. */
static size_t fuzz_body_for(const struct fuzz_ident *id, u32 declared)
{
	const struct fuzz_shape *sh = &id->sh;
	u32 sub = sh->covers ? sh->extid_width : 0;

	return declared > sub ? declared - sub : 0;
}


/*
 * Write one synthesised element into 'out', returning its size.
 *
 * 'declared' is what the length field will say. 'body' is how many octets
 * actually follow the header. They are the same thing for an honest element
 * and deliberately different for the declared-length domain, where what an
 * element says about itself is the case under test.
 *
 * The body is a constant fill. What the octets say is a domain of its own and
 * not this one; deriving them from the case would mean neither was enumerated.
 */
static size_t fuzz_build_element(u8 *out, size_t cap,
				 const struct fuzz_ident *id,
				 u32 declared, size_t body, int *sub_in)
{
	const struct fuzz_shape *sh = &id->sh;
	size_t hdr = sh->hdr;
	int have_sub = sh->extid_width != 0;

	/* Under a shape whose length field COVERS the sub-registry id, a
	 * declared length below that width is a real case rather than an
	 * impossible one: it is the element the identity domain just
	 * selected, arriving without the id that made it that element. The
	 * octets are left out rather than written past what was declared, so
	 * the chain still walks and the rest of the frame is still parsed --
	 * the case under test is the id that is not there, not a chain that
	 * stops. The caller is told, so the ledger does not count a member it
	 * did not send. */
	if (have_sub && sh->covers && declared < sh->extid_width) {
		hdr -= sh->extid_width;
		have_sub = 0;
	}

	if (sub_in)
		*sub_in = have_sub;

	if (cap < hdr + body)
		return 0;

	os_memset(out, 0, hdr + body);
	/* The identity is one octet of an element and two of a WPS attribute,
	 * big-endian there and little-endian in DPP's. Written through the
	 * shape for the same reason the length is: a two-octet identity
	 * written as one puts the parser's length where its type should be
	 * and the chain still walks. */
	fuzz_put_int(out, sh->id_off, sh->id_width, sh->id_le, id->id);
	fuzz_put_int(out, sh->len_off, sh->len_width, sh->len_le, declared);
	if (have_sub)
		fuzz_put_int(out, sh->extid_off, sh->extid_width, sh->extid_le,
			     id->sub);

	return hdr + body;
}


/*
 * Walk an element chain. Fills offs[] with each insertion point's offset from
 * 'buf' and returns how many there were, or 0 when the region is not a chain
 * -- a length that runs past the end, or a walk that does not land exactly on
 * it. '*nraw', when asked for, is how many elements were walked, which is not
 * the same number.
 *
 * Refusing a partial walk matters. A management frame's variable part is only
 * an element chain for some frames; for the rest it begins with fixed fields
 * whose octets would parse as plausible elements, and inserting "after element
 * three" of a chain that does not exist puts the element at an offset chosen by
 * misreading a scalar. The caller falls back to appending, which is always a
 * real position.
 *
 * TWO THINGS THE FLAT WALK GOT WRONG, both of them about shape.
 *
 * An element's header is not always two octets. Walking a chain that contains
 * an extended length element two octets at a time takes its id and the low
 * octet of its extension id as a header, and every offset after that point is
 * arithmetic on unrelated bytes. The shape table says which header each id
 * has; element_datalen() is where it came from.
 *
 * A Fragment element is not an element. It is a CONTINUATION of the one before
 * it, and the chain walk's insertion points are therefore between GROUPS, not
 * between elements: inserting between a fragmentable element and its
 * continuation terminates defragmentation and hands the consumer a truncated
 * buffer. The chain still walks afterwards, so nothing reports it -- the
 * position domain would have been quietly destroying the very case it was
 * inserting into. Inside a group is a case worth having, and the nesting and
 * fragment domains below build it deliberately, labelled as what it is.
 */
static size_t fuzz_walk_scan(const struct fuzz_chain_fmt *fmt, const u8 *buf,
			     size_t len, u16 *offs, size_t max, size_t *nraw,
			     int *exact, size_t *endp)
{
	size_t pos = 0, n = 0, raw = 0;
	int group_open = 0;

	if (nraw)
		*nraw = 0;
	if (exact)
		*exact = 0;

	while (pos < len) {
		struct fuzz_shape sh;
		size_t hdr, elen;
		u32 dlen;
		u16 id;
		int cont;

		/* The element chain picks its shape by the id, so the id has
		 * to be readable before the shape is known. Every other
		 * format has one shape and the id is read with the rest of
		 * the header. */
		if (fmt->elem && pos >= len)
			break;
		id = fmt->elem ? buf[pos] : 0;
		fuzz_shape_at(fmt, fuzz_shape_index(fmt, id), &sh);
		/* A shape whose length field covers its sub-registry id has
		 * that id inside the body as far as the walk is concerned. */
		hdr = sh.covers ? (size_t) sh.len_off + sh.len_width : sh.hdr;
		if (pos + hdr > len)
			break;
		dlen = fuzz_get_int(buf + pos, sh.len_off, sh.len_width,
				    sh.len_le);
		elen = hdr + dlen;
		if (elen > len - pos)
			break;

		cont = fmt->elem && id == FUZZ_EID_FRAGMENT && group_open &&
			n > 0;
		if (!cont) {
			if (offs && n < max)
				offs[n] = (u16) pos;
			n++;
		}
		raw++;

		/* Fragments follow an element that declared everything its
		 * length field can say, and the run of them ends at the first
		 * one that declares nothing. Both halves are read out of the
		 * tree, not assumed. */
		if (!fmt->elem)
			group_open = 0;
		else if (cont)
			group_open = dlen != 0;
		else
			group_open = dlen == FUZZ_FRAG_PARENT_LEN;

		pos += elen;
		if (n >= max)
			break;
	}

	if (exact)
		*exact = pos == len;
	if (endp)
		*endp = pos;

	if (nraw)
		*nraw = raw;

	return n;
}


/*
 * How many elements a walker gets through before it has to stop, and whether
 * it landed exactly on the end. Elements, not groups: a consumer's walk yields
 * one item per element and the question here is how far that walk gets.
 *
 * This is the measurement W10 is about. "The chain stays walkable" is not a
 * property of the domain that built a case -- it is a property of the octets
 * that came out -- so it is read back off them.
 */
static size_t fuzz_walk_depth(const struct fuzz_chain_fmt *fmt,
			      const u8 *buf, size_t len, int *exact)
{
	size_t raw = 0;

	fuzz_walk_scan(fmt, buf, len, NULL, (size_t) -1, &raw, exact, NULL);

	return raw;
}


/*
 * The strict walk: every group, or nothing. 0 means "this region is not an
 * element chain", which is a different answer from "it is a chain of zero
 * elements" and the callers below depend on the difference.
 */
static size_t fuzz_walk_elements(const struct fuzz_chain_fmt *fmt,
				 const u8 *buf, size_t len, u16 *offs,
				 size_t max, size_t *nraw)
{
	size_t n;
	int exact;

	n = fuzz_walk_scan(fmt, buf, len, offs, max, nraw, &exact, NULL);
	if (!exact) {
		if (nraw)
			*nraw = 0;
		return 0;
	}

	return n;
}


/*
 * W12. Where the walked item containing 'off' ends, or 0 when nothing in this
 * region contains it.
 *
 * Groups, not elements, for the reason the insertion points are groups: a
 * Fragment element continues the one before it, and a consumer holding the
 * defragmented buffer has a span that runs to the end of the run. Cutting
 * between a parent and its continuation would end the frame in the middle of
 * the very span this is trying to put at the end of it.
 */
static size_t fuzz_group_end(const struct fuzz_chain_fmt *fmt, const u8 *buf,
			     size_t len, size_t off)
{
	u16 offs[FUZZ_MAX_ELEMS];
	size_t n, end = 0, i;

	n = fuzz_walk_scan(fmt, buf, len, offs, FUZZ_MAX_ELEMS, NULL, NULL,
			   &end);
	if (!n || off >= end)
		return 0;

	for (i = n; i > 0; i--) {
		if (offs[i - 1] <= off)
			return i < n ? offs[i] : end;
	}

	return 0;
}


/*
 * Insert 'copies' of a staged element at offset 'at', shifting what follows.
 * Returns the frame's new length, or 'len' when it would not fit -- which
 * cannot happen for a case the domain sizing admitted, and is checked anyway
 * because the alternative is writing past the caller's buffer.
 */
static size_t fuzz_insert_bytes(u8 *buf, size_t len, size_t capacity,
				size_t at, const u8 *src, size_t n,
				size_t copies)
{
	size_t total = n * copies, i;

	if (!n || !copies || at > len || total > capacity - len)
		return len;

	os_memmove(buf + at + total, buf + at, len - at);
	for (i = 0; i < copies; i++)
		os_memcpy(buf + at + i * n, src, n);

	return len + total;
}


/*
 * An element continued by Fragment elements.
 *
 * Defragmentation is the mechanism by which an element exceeds what its length
 * field can say, so the logical length domain is not 0..255 but
 * 0..255 + 255*N -- and those are the lengths a consumer's arithmetic is least
 * likely to have been written for. The parent declares everything its length
 * field can express, because that is what makes the tree look for a
 * continuation at all, and the fragment count is the swept axis.
 *
 * 'zero_tail' ends the run with a fragment that declares nothing, which is the
 * boundary the walk stops at -- a value the 0..255 length domain contains and
 * has no name for.
 */
static size_t fuzz_build_fragmented(u8 *out, size_t cap,
				    const struct fuzz_ident *id,
				    size_t nfrag, int zero_tail,
				    size_t *deflen, int *sub_in)
{
	struct fuzz_ident frag;
	size_t n, i, body = fuzz_body_for(id, FUZZ_FRAG_PARENT_LEN);

	n = fuzz_build_element(out, cap, id, FUZZ_FRAG_PARENT_LEN, body,
			       sub_in);
	if (!n)
		return 0;
	*deflen = body;

	os_memset(&frag, 0, sizeof(frag));
	frag.id = FUZZ_EID_FRAGMENT;
	frag.shape = fuzz_shape_of(frag.id);

	for (i = 0; i < nfrag; i++) {
		u32 flen = zero_tail && i + 1 == nfrag ? 0 :
			FUZZ_FRAG_PARENT_LEN;
		size_t fn = fuzz_build_element(out + n, cap - n, &frag, flen,
					       flen, NULL);

		if (!fn)
			break;
		n += fn;
		/* A fragment that declares nothing ends the walk, so it adds
		 * nothing to the defragmented length. */
		if (!flen)
			break;
		*deflen += flen;
	}

	return n;
}


/*
 * An element inside a container element's body.
 *
 * The chain walk is the same walk one level down; what it needs is the offset
 * of the inner chain, which is exactly what this engine already learned to
 * demand from its callers. There has simply been no caller that supplies one.
 * Here there is: the container is synthesised, so where its body starts is
 * known exactly rather than guessed at.
 *
 * The container's id comes from the same registry as the inner element's. An
 * id whose body is not a chain is a case worth sending for the same reason an
 * element is sent where it is not legal -- and which ids do hold a chain is
 * not something this file is allowed to know.
 */
static size_t fuzz_build_nested(u8 *out, size_t cap,
				const struct fuzz_ident *inner,
				const struct fuzz_ident *outer,
				size_t depth, size_t *at, int *sub_in)
{
	size_t n, d;

	/* Honestly declared, and empty. The nesting domain is about where an
	 * element is, so the one thing it must not also vary is whether the
	 * element is well formed -- a declared length of zero would drop the
	 * sub-registry id of the shapes that carry one, and the case would be
	 * testing that instead. The length domains sweep that deliberately. */
	n = fuzz_build_element(out, cap, inner, fuzz_declare_for(inner, 0), 0,
			       sub_in);
	if (!n)
		return 0;
	*at = 0;

	for (d = 0; d < depth; d++) {
		u8 hdr[FUZZ_ELEM_HDR_MAX];
		size_t hn = fuzz_build_element(hdr, sizeof(hdr), outer,
					       fuzz_declare_for(outer, n), 0,
					       NULL);

		if (!hn || cap < n + hn)
			return 0;
		os_memmove(out + hn, out, n);
		os_memcpy(out, hdr, hn);
		n += hn;
		*at += hn;
	}

	return n;
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
	FUZZ_DOMAIN_ELEN,	/* what that element says its length is */
	FUZZ_DOMAIN_MULT,	/* the same element, present 2..5 times */
	FUZZ_DOMAIN_CHAIN,	/* the chain's shape: delete, duplicate, swap */
	FUZZ_DOMAIN_FIELD,	/* a named field, taken through its own domain */
	FUZZ_DOMAIN_PATTERN,	/* an opaque field, filled with a pattern */
	FUZZ_DOMAIN_FRAG,	/* the element continued by Fragment elements */
	FUZZ_DOMAIN_NEST,	/* the element inside a container's body */
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
 * W16. One collected field, and everything the engine knows about it beyond
 * what the generated row says.
 *
 * The offset is RESOLVED rather than taken from the table, because two of the
 * three sources below do not have one until the frame is in hand: a field
 * past the end of its struct sits behind a gap the negotiated AKM sizes, and
 * an Action frame's fields are at offsets the category selects. The rest of
 * the engine reads f.offset and does not care which it was.
 */
struct fuzz_field_use {
	struct fuzz_field f;
	/* Where the row came from: "struct" for a member the generator could
	 * read, "var" for one declared only by the struct's trailing
	 * comments, "action" for one the category chose. In every message, so
	 * a reader of a crash record knows how much the engine was claiming
	 * when it wrote there. */
	const char *from;
	/* 1 the receiver on the other side of this target reads this field,
	 * 0 it provably does not, -1 nothing here can say. Three states, not
	 * two: "cannot tell" is an answer and reporting it as "not read"
	 * would be the fabrication this whole report exists to avoid. */
	int read;
	/* For a "var" field: the gap width that solved for its offset, which
	 * is what a reader needs to find the field again in the hexdump. */
	unsigned int gap;
};



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


/*
 * W12. The span under test, at the end of the frame.
 *
 * 0.2 keeps the oracle out of scope and the free oracle is a process that
 * died. There is a class of defect that oracle cannot see at any mutation
 * power, and it is the class this product's parsers are built to have: every
 * one of them hands out pointers INTO the caller's buffer and copies nothing
 * -- ieee802_11_parse_elems() alone fills 92 of them. A consumer that reads
 * one octet past the end of its span reads the next element's id. Same
 * allocation, same page, no fault; nothing for a crash oracle to see, and
 * nothing for a sanitizer either.
 *
 * The stimulus-side mitigation needs no oracle and no detection code, which
 * is why it is here rather than outside this plan: put the span under test
 * LAST, so an over-read crosses the frame boundary instead of crossing into
 * a sibling element.
 *
 * STATE THE LIMIT, BECAUSE THIS IS NOT A REDZONE. Whether a read past the
 * frame is observable at all depends on the victim's allocator and on how its
 * driver handed the frame up. This makes the defect REACH past the buffer; it
 * does not make it DETECTABLE. Against a victim built from source -- which
 * both hwsim topologies are -- it is the difference between a sanitizer that
 * can fire and one that cannot, and that is the whole of the claim.
 *
 * IT COSTS A DIMENSION, so it is a separate case space rather than a wider
 * one. Position in the chain is a domain of its own and pinning the span to
 * the end removes it: position swept for reach, last-position for
 * observability, and the opset says which run a case came from so the two can
 * never be confused for each other.
 */
static int fuzz_tail_mode(void)
{
	return fuzz_env_int("FUZZ_TAIL", 0) != 0;
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


/* How many cases a domain of this size contributes, under the tier it
 * selects. Written against the size rather than against a struct fuzz_field,
 * because the field model is not the only thing in this engine with a width:
 * an element's declared length is one or two octets by the same rule, and the
 * shape table says which. */
static s64 fuzz_tier_cases(s64 domain)
{
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


static s64 fuzz_field_domain(const struct fuzz_field *f)
{
	return (s64) 1 << (8 * f->width);
}


/*
 * W16b. The tier a field is swept at, which is where the read claim costs
 * something rather than only being reported.
 *
 * A field the receiver provably never reads still gets the LADDER -- the
 * edges of its domain and the edges of where the frame already was -- because
 * the claim is static and a static claim can be wrong, and eighteen cases is
 * what it costs to keep a wrong one from deleting the field outright. What it
 * does not get is the stride walk, which is 251 runs spent completing a
 * domain nothing on the other side will look at.
 *
 * Only under AUTO. An explicit FUZZ_TIER is the operator saying what to
 * sweep, and a run that quietly did something else would be reporting a
 * sweep it did not perform.
 */
static enum fuzz_tier fuzz_field_tier(const struct fuzz_field_use *u)
{
	if (u->read == 0 && fuzz_tier_setting() == FUZZ_TIER_AUTO)
		return FUZZ_TIER_LADDER;

	return fuzz_tier_for(fuzz_field_domain(&u->f));
}


static const char * fuzz_tier_named(enum fuzz_tier t)
{
	switch (t) {
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


static s64 fuzz_tier_cases_at(enum fuzz_tier t, s64 domain)
{
	switch (t) {
	case FUZZ_TIER_FULL:
		return domain;
	case FUZZ_TIER_LADDER:
		return FUZZ_LADDER_N;
	case FUZZ_TIER_STRIDE:
	default:
		return FUZZ_LADDER_N + (domain + FUZZ_STRIDE - 1) / FUZZ_STRIDE;
	}
}


/* How many cases this field contributes, under the tier it selects. */
static s64 fuzz_field_cases(const struct fuzz_field_use *u)
{
	return fuzz_tier_cases_at(fuzz_field_tier(u),
				  fuzz_field_domain(&u->f));
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


/*
 * The case'th value of this domain, given what the frame was built with and
 * what the parser's own guard insists on.
 *
 * 'minimum' is the length the tree enforces for whatever this domain is the
 * length of, or 0 where nothing enforces one. Zero is not a special case: the
 * window around it collapses onto the domain edges the second half of the
 * ladder already covers, which is coincidence, and coinciding entries are
 * still entries. The count must not move -- a case count that varied with
 * whether a minimum happened to be known would shift every case_id the day
 * the generated table gained a row, and no crash record would replay.
 */
static u64 fuzz_tier_value_at(enum fuzz_tier tier, s64 domain, u64 built,
			      u64 minimum, s64 n)
{
	s64 mask = domain - 1;

	/* A domain small enough to enumerate is still not a domain that gets
	 * REACHED: where it is the slow axis of a product, a run sees its
	 * first few values and no more. So it is enumerated in an order that
	 * starts at the window, which costs nothing and loses nothing. */
	if (tier == FUZZ_TIER_FULL)
		return fuzz_window_first((u32) minimum, (u32) mask, n);

	/* The window above the parser's minimum, first, because it is the
	 * part of a length domain that is worth reaching in run 1. */
	if (n < FUZZ_MIN_LADDER_N)
		return (u64) (((s64) minimum + fuzz_min_ladder[n]) & mask);
	n -= FUZZ_MIN_LADDER_N;

	if (n < FUZZ_EDGE_LADDER_N) {
		/* The edges of the domain, and the edges of where the frame
		 * already is. Entries can coincide -- a built value of 0 makes
		 * four of these the same case -- and they are still eight
		 * cases, for the reason above. */
		static const int ladder[FUZZ_EDGE_LADDER_N] = {
			0, 1, 2, -1, 0, 1, -2, -1
		};
		int d = ladder[n];

		if (n < 3)
			return (u64) (d & mask);
		if (n < 6)
			return (u64) (((s64) built + d) & mask);

		return (u64) ((domain + d) & mask);
	}

	return (u64) ((fuzz_stride_offset() + (n - FUZZ_EDGE_LADDER_N) *
		       FUZZ_STRIDE) % domain);
}


static u64 fuzz_tier_value(s64 domain, u64 built, u64 minimum, s64 n)
{
	return fuzz_tier_value_at(fuzz_tier_for(domain), domain, built,
				  minimum, n);
}


/*
 * A named field has no minimum yet.
 *
 * The minima this engine generates are the element parser's, keyed by element
 * id; a field of struct ieee80211_mgmt is guarded somewhere else entirely and
 * by a different shape of guard. The window it would aim at is W16a's, and
 * until that exists the honest value here is 0 -- which the ladder handles as
 * coincidence rather than as a special case, so the count does not move when
 * the number arrives.
 */
static u64 fuzz_field_value(const struct fuzz_field_use *u, u64 built, s64 n)
{
	return fuzz_tier_value_at(fuzz_field_tier(u),
				  fuzz_field_domain(&u->f), built, 0, n);
}


static const char * fuzz_frame_kind(enum fuzz_frame_type type)
{
	switch (type) {
	case FUZZ_TYPE_IEEE80211_MGMT:
		return "mgmt";
	case FUZZ_TYPE_IEEE802_1X_HDR:
		return "eapol";
	case FUZZ_TYPE_FRAME_BODY:
		return "body";
	case FUZZ_TYPE_ACTION_BODY:
		return "action";
	case FUZZ_TYPE_OCTET_STREAM:
		return "stream";
	}

	return "unknown";
}


/*
 * Where an Action frame's Category octet is in this buffer, or len when the
 * buffer is not one. A whole management frame carries the 802.11 header
 * first; an Action body is handed over at the category itself.
 */
static size_t fuzz_action_body_at(enum fuzz_frame_type type, const u8 *buf,
				  size_t len)
{
	if (type == FUZZ_TYPE_ACTION_BODY)
		return 0;
	if (type != FUZZ_TYPE_IEEE80211_MGMT || len <= IEEE80211_HDRLEN)
		return len;
	if (((buf[0] >> 2) & 0x3) != WLAN_FC_TYPE_MGMT)
		return len;
	if (((buf[0] >> 4) & 0xf) != WLAN_FC_STYPE_ACTION)
		return len;

	return IEEE80211_HDRLEN;
}


/*
 * Which generated layout this Action frame's body selects, or NULL.
 *
 * Most specific first, exactly as the label table is read and for the same
 * reason: a row carrying a code matches only that code, and a row without one
 * is the category's fallback -- which the generator emits only where the
 * whole tree gives that category a single layout.
 */
static const struct fuzz_action_layout *
fuzz_action_layout_of(const u8 *buf, size_t len, size_t at)
{
	size_t i;

	if (at >= len)
		return NULL;

	for (i = 0; i < ARRAY_SIZE(fuzz_action_layouts); i++) {
		const struct fuzz_action_layout *l = &fuzz_action_layouts[i];

		if (l->cat != buf[at])
			continue;
		if (l->code >= 0 &&
		    (at + 1 >= len || buf[at + 1] != (u8) l->code))
			continue;
		return l;
	}

	return NULL;
}


/*
 * W16a. Solve for where a variable-offset field is in THIS frame.
 *
 * The field is the length of everything that follows it, so for each width
 * the gap before it can have, there is one arithmetic test: does the value
 * written there account for exactly the octets after it? Returns how many
 * candidates passed.
 *
 * Exactly one is the case the engine can sweep. Zero and two are both real
 * and are both reported rather than resolved: a frame whose gap width this
 * tree can produce but whose literals the generator could not read gives
 * zero, and a short key data field can give two. Picking one of two would
 * write a 65,536-value domain into octets that are somebody else's.
 */
static int fuzz_var_resolve(const struct fuzz_var_field *vf, const u8 *buf,
			    size_t len, size_t *off, unsigned int *gap)
{
	unsigned int i;
	int found = 0;

	for (i = 0; i < vf->ngaps; i++) {
		size_t at = (size_t) vf->base + vf->gaps[i];
		u64 v = 0;
		unsigned int k;

		if (at + vf->width > len)
			continue;
		for (k = 0; k < vf->width; k++) {
			size_t x = vf->big_endian ? k : vf->width - 1 - k;

			v = (v << 8) | buf[at + x];
		}
		if (at + vf->width + v != len)
			continue;
		if (!found && off)
			*off = at;
		if (!found && gap)
			*gap = vf->gaps[i];
		found++;
	}

	return found;
}


/* Which role this target transmits as, or NULL when the roster does not have
 * it -- a label built by a hook this table has not seen, which is a drift the
 * generator's own --check catches and is answered here as "cannot tell". */
static const char * fuzz_target_role_of(const char *target)
{
	size_t i;

	if (!target)
		return NULL;

	for (i = 0; i < ARRAY_SIZE(fuzz_target_roles); i++) {
		if (os_strcmp(fuzz_target_roles[i].target, target) == 0)
			return fuzz_target_roles[i].role;
	}

	return NULL;
}


/*
 * W16b. Does the receiver on the other side of this target read this field?
 *
 * The receiver is the one whose role is NOT the transmitting target's: a
 * frame hostapd sends is parsed by the station's code and the other way
 * round. Where the target is in shared code, or the frame kind has no
 * receiver rostered, or more than one matches, the answer is -1 -- which the
 * report prints as "cannot tell" and the ledger counts in a column of its
 * own.
 */
static int fuzz_field_read_by(const char *target, enum fuzz_frame_type type,
			      const char *field)
{
	const char *role = fuzz_target_role_of(target);
	const char *kind = fuzz_frame_kind(type);
	const struct fuzz_field_reader *hit = NULL;
	size_t i, n = 0;

	if (!role || os_strcmp(role, "either") == 0)
		return -1;

	for (i = 0; i < ARRAY_SIZE(fuzz_field_readers); i++) {
		const struct fuzz_field_reader *r = &fuzz_field_readers[i];

		if (os_strcmp(r->frame, kind) != 0)
			continue;
		if (os_strcmp(r->role, role) == 0)
			continue;	/* the transmitting side */
		hit = r;
		n++;
	}

	if (n != 1)
		return -1;

	for (i = 0; hit->reads[i]; i++) {
		if (os_strcmp(hit->reads[i], field) == 0)
			return 1;
	}

	return 0;
}


/*
 * The fields that apply to this frame: right frame kind, right management
 * subtype, and wholly inside the octets there are. A field that runs past the
 * end is not clamped -- a shortened frame simply has fewer fields, and
 * clamping would write a different field's octets under this one's name.
 *
 * Three sources, and the order they come out in is the order the round robin
 * below will spend a short run on:
 *
 *   1. the generated member table, for fields at a constant offset
 *   2. the Action layout the frame's own category selects
 *   3. a field past the end of its struct, where the gap before it solved
 *
 * and then, after all of those, the fields the receiver provably does not
 * read. Reordering rather than dropping is deliberate. The claim that a
 * receiver never reads a field is static, and a static claim that is wrong
 * would silently delete coverage; moving those cases to the back of the
 * queue costs a wrong claim nothing and costs a right one nothing either.
 */
static size_t fuzz_collect_fields(enum fuzz_frame_type type, const u8 *buf,
				  size_t len, size_t hdr, const char *target,
				  struct fuzz_field_use *out, size_t max,
				  int opaque)
{
	const struct fuzz_action_layout *layout;
	int stype = -1;
	size_t i, n = 0, at, pass;

	if (type == FUZZ_TYPE_IEEE80211_MGMT) {
		if (len < 1)
			return 0;
		/* The subtype is in the frame's own frame control field, so no
		 * call site has to declare which layout it built. */
		stype = (buf[0] >> 4) & 0xf;
	}

	at = fuzz_action_body_at(type, buf, len);
	layout = fuzz_action_layout_of(buf, len, at);

	/* Live fields first, then the ones nothing on the other side reads. */
	for (pass = 0; pass < 2; pass++) {
		for (i = 0; i < ARRAY_SIZE(fuzz_fields) && n < max; i++) {
			const struct fuzz_field *f = &fuzz_fields[i];
			int rd;

			if (f->frame != type)
				continue;
			if (f->stype >= 0 && f->stype != stype)
				continue;
			if (f->offset < hdr)
				continue;	/* inside the skipped header */
			if (f->offset + f->width > len)
				continue;
			if ((f->kind == FUZZ_FIELD_OPAQUE) != (opaque != 0))
				continue;
			rd = fuzz_field_read_by(target, type, f->name);
			if ((rd == 0) != (pass != 0))
				continue;
			out[n].f = *f;
			out[n].from = "struct";
			out[n].read = rd;
			out[n].gap = 0;
			n++;
		}

		for (i = 0; layout && i < layout->nfields && n < max; i++) {
			const struct fuzz_action_field *af =
				&layout->fields[i];
			size_t off = at + af->off;
			int rd;

			if (off < hdr || off + af->width > len)
				continue;
			if ((af->kind == FUZZ_FIELD_OPAQUE) != (opaque != 0))
				continue;
			rd = fuzz_field_read_by(target, type, af->name);
			if ((rd == 0) != (pass != 0))
				continue;
			os_memset(&out[n].f, 0, sizeof(out[n].f));
			out[n].f.name = af->name;
			out[n].f.frame = type;
			out[n].f.stype = -1;
			out[n].f.offset = (unsigned int) off;
			out[n].f.width = af->width;
			out[n].f.kind = af->kind;
			out[n].f.big_endian = af->big_endian;
			out[n].from = "action";
			out[n].read = rd;
			out[n].gap = 0;
			n++;
		}

		for (i = 0; i < ARRAY_SIZE(fuzz_var_fields) && n < max; i++) {
			const struct fuzz_var_field *vf = &fuzz_var_fields[i];
			size_t off = 0;
			unsigned int gap = 0;
			int rd;

			if (vf->frame != type)
				continue;
			if ((vf->kind == FUZZ_FIELD_OPAQUE) != (opaque != 0))
				continue;
			if (fuzz_var_resolve(vf, buf, len, &off, &gap) != 1)
				continue;
			if (off < hdr)
				continue;
			rd = fuzz_field_read_by(target, type, vf->name);
			if ((rd == 0) != (pass != 0))
				continue;
			os_memset(&out[n].f, 0, sizeof(out[n].f));
			out[n].f.name = vf->name;
			out[n].f.frame = type;
			out[n].f.stype = -1;
			out[n].f.offset = (unsigned int) off;
			out[n].f.width = vf->width;
			out[n].f.kind = vf->kind;
			out[n].f.big_endian = vf->big_endian;
			out[n].from = "var";
			out[n].read = rd;
			out[n].gap = gap;
			n++;
		}
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
#define FUZZ_OPSET_VERSION 6

static void fuzz_add_opset(struct wpabuf *json)
{
	char buf[64];

	/* The tail case space is a different enumeration of the same domains:
	 * the position axis is pinned and the octet sweep cuts the frame. A
	 * case_id means something different in it, so it is named here rather
	 * than left to be remembered -- which is what every other field in
	 * this string is for. */
	os_snprintf(buf, sizeof(buf), "v%d/%dd/%s/%d@%d%s",
		    FUZZ_OPSET_VERSION, (int) FUZZ_NUM_DOMAINS,
		    fuzz_tier_name(1 << 16), FUZZ_STRIDE,
		    (int) fuzz_stride_offset(),
		    fuzz_tail_mode() ? "/tail" : "");
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


/*
 * One synthesised element, as a case.
 *
 * Gathered into a struct rather than passed as fourteen arguments, because
 * six domains report through here and each one fills a different half of it.
 */
struct fuzz_elem_case {
	const char *domain;	/* which of them built this frame */
	struct fuzz_ident id;
	int sub_in;		/* the sub-registry id is inside what was
				 * declared, so it is a member this run
				 * actually sent */
	u32 declared;
	size_t body;
	size_t at;		/* insertion point, as an index */
	size_t npos;
	size_t off;		/* insertion point, as a byte offset */
	size_t copies;
	size_t copies_req;	/* what the multiplicity domain asked for, which
				 * is not always what the headroom allowed */
	int walks;		/* the staged octets are a complete chain of
				 * their own: every length equals the body it
				 * was given, so what follows them is still
				 * parsed. W10's invariant, read off the
				 * octets rather than asserted of the domain
				 * that built them. */
	size_t pre;		/* elements a walker got through before the
				 * mutation ... */
	size_t post;		/* ... and after it. post < pre is a chain
				 * this case stopped the consumer from
				 * reading, which is the failure W10 exists
				 * to make visible. */
	size_t nfrag;
	size_t deflen;		/* the defragmented length, which is the
				 * number no length field in the frame
				 * says */
	size_t depth;
	size_t nest_at;		/* where the innermost element landed */
	struct fuzz_ident outer;
	const char *tier;
	int tail_mode;		/* this case space pins the span under test
				 * to the end of the frame */
	u32 minimum;		/* the declared length this id's parser
				 * insists on, or 0 where nothing does */
	const struct fuzz_min_entry *why;	/* the guard it came from,
						 * in the tree's own words */
};


static void fuzz_report_elem(const char *target, size_t hdr,
			     const char *kind,
			     const struct fuzz_elem_case *c,
			     size_t was, size_t now,
			     int defer_log, const u8 *reply,
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

	/* Which of the element domains built this frame. The consumer used to
	 * infer it from which keys were present, which stopped working the
	 * moment a second length domain existed. */
	json_add_string(json, "dom", c->domain);
	json_value_sep(json);

	/* The id always, and the sub-registry member under its own key. A
	 * consumer counting registry coverage must not have to infer which
	 * registry a number came from, and 93 is a different thing in each. */
	json_add_int(json, "eid", c->id.id);
	json_value_sep(json);
	if (c->id.name) {
		/* The name the tree gives it, generated beside the table the
		 * number came from. A crash record is read by someone who has
		 * the record and not the header. */
		json_add_string(json, "eid_name", c->id.name);
		json_value_sep(json);
	}
	if (c->id.subkey) {
		json_add_int(json, c->id.subkey, c->id.sub);
		json_value_sep(json);
		if (c->id.subname) {
			char key[32];

			os_snprintf(key, sizeof(key), "%s_name",
				    c->id.subkey);
			json_add_string(json, key, c->id.subname);
			json_value_sep(json);
		}
		/* ... and whether it is in the frame at all. A declared length
		 * below the sub id's width leaves it out, which is a case of
		 * the length domain and must not be counted as a case of the
		 * identity domain. */
		json_add_int(json, "present", c->sub_in ? 1 : 0);
		json_value_sep(json);
	}
	json_add_string(json, "reg", c->id.reg);
	json_value_sep(json);
	/* Which TLV format this item was built in. There are five on this
	 * product and the identity spaces behind them overlap -- 0x1001 is a
	 * WPS attribute type and a DPP one -- so a record that named the
	 * number without naming the chain would be unreadable. */
	json_add_string(json, "chain", c->id.chain->name);
	json_value_sep(json);
	json_add_string(json, "shape",
			c->id.chain->elem ?
			fuzz_elem_shapes[c->id.shape].name :
			c->id.chain->name);
	json_value_sep(json);

	/* What the element says about itself, and what actually follows it.
	 * The same number for an honest element and deliberately different
	 * for the declared-length domain, where the gap IS the case. */
	json_add_int(json, "declared", (int) c->declared);
	json_value_sep(json);
	json_add_int(json, "body", c->body);
	json_value_sep(json);
	json_add_int(json, "pos", c->at);
	json_value_sep(json);
	json_add_int(json, "npos", c->npos);
	json_value_sep(json);

	/* The byte offset the element went in at, as well as its index in the
	 * chain. A consumer needs the offset to recover the frame as built --
	 * cut the inserted octets back out -- and the index to know which
	 * insertion point of the domain this case was. Neither gives the
	 * other. */
	json_add_int(json, "at", c->off);
	json_value_sep(json);
	json_add_int(json, "copies", c->copies);
	json_value_sep(json);

	/* What the multiplicity domain asked for, when the headroom would not
	 * hold it. Reported only when the two differ, so a consumer that sees
	 * the key knows a case was clamped rather than having to compare every
	 * case against a constant it would have to keep in step. */
	if (c->copies_req && c->copies_req != c->copies) {
		json_add_int(json, "copies_req", c->copies_req);
		json_value_sep(json);
	}

	/* W10, reported rather than asserted.
	 *
	 * "walks": the staged octets are a chain in their own right -- every
	 * length equal to the body it was given -- so everything behind them
	 * is still parsed. "tail": they went in at the last insertion point,
	 * which is the only place an overrun can leave the buffer instead of
	 * being absorbed by the next element. One of the two must hold, and a
	 * consumer is given both rather than the conclusion.
	 *
	 * "pre" and "post": how far a walker got through the region before and
	 * after. The insertion only adds items, so post < pre is a chain this
	 * case truncated -- the registry member went out and the elements
	 * behind it were never read, which is a frame the ledger would
	 * otherwise count as covering both. */
	json_add_int(json, "walks", c->walks ? 1 : 0);
	json_value_sep(json);
	json_add_int(json, "tail", c->at + 1 == c->npos ? 1 : 0);
	json_value_sep(json);
	json_add_int(json, "pre", c->pre);
	json_value_sep(json);
	json_add_int(json, "post", c->post);
	json_value_sep(json);

	if (c->nfrag) {
		json_add_int(json, "nfrag", c->nfrag);
		json_value_sep(json);
		/* The length the consumer ends up holding, which no length
		 * field in the frame states. */
		json_add_int(json, "deflen", c->deflen);
		json_value_sep(json);
	}

	if (c->depth) {
		json_add_int(json, "depth", c->depth);
		json_value_sep(json);
		json_add_int(json, "outer_eid", c->outer.id);
		json_value_sep(json);
		if (c->outer.name) {
			json_add_string(json, "outer_eid_name", c->outer.name);
			json_value_sep(json);
		}
		json_add_int(json, "nest_at", c->nest_at);
		json_value_sep(json);
	}

	if (c->tier) {
		json_add_string(json, "tier", c->tier);
		json_value_sep(json);
	}

	/* W11. What the tree's own parser insists on for this id, and the
	 * guard it came from -- in the guard's words, not in a number alone.
	 * `sizeof(struct rsn_ftie)` is 82 today and a crash record that says
	 * only 82 has lost the one fact that makes it re-aimable after
	 * upstream changes the struct.
	 *
	 * Reported on every element case, including the ones with no minimum
	 * to aim at, so a consumer can divide: the numerator is the cases
	 * aimed at a guard and the denominator is all of them. A key that
	 * appeared only when there was a minimum would make the two
	 * indistinguishable from a run that did not report the key at all. */
	json_add_int(json, "tail_mode", c->tail_mode ? 1 : 0);
	json_value_sep(json);
	json_add_int(json, "min", (int) c->minimum);
	json_value_sep(json);
	json_add_int(json, "min_known", c->why ? 1 : 0);
	json_value_sep(json);
	if (c->why) {
		json_add_string(json, "min_rel", c->why->rel);
		json_value_sep(json);
		json_add_string(json, "min_expr", c->why->expr);
		json_value_sep(json);
		/* How far past the declared length the guard's own variable
		 * is, so a reader can check the arithmetic rather than take
		 * it. */
		json_add_int(json, "min_past", c->why->past);
		json_value_sep(json);
	}

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
			      const struct fuzz_field_use *u, u64 before,
			      u64 after, const char *tier, int defer_log,
			      const u8 *reply, const char *key, s64 case_id)
{
	const struct fuzz_field *f = &u->f;
	struct wpabuf *json = fuzz_report_start("fuzz",
						2 * len + os_strlen(target) +
						os_strlen(f->name) + 64);

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
	/* Where this row came from, and whether anything on the other side
	 * will read it. A field at a solved offset is a weaker claim about
	 * the frame than a member of a struct, and a sweep against a receiver
	 * that never reads those octets is not coverage at all -- so both
	 * travel with every case rather than being recoverable only by
	 * someone holding this tree. */
	json_add_string(json, "from", u->from);
	json_value_sep(json);
	json_add_int(json, "read", u->read);
	json_value_sep(json);
	if (u->gap) {
		json_add_int(json, "gap", u->gap);
		json_value_sep(json);
	}
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
				const struct fuzz_field_use *u, size_t pattern,
				int defer_log, const u8 *reply,
				const char *key, s64 case_id)
{
	const struct fuzz_field *f = &u->f;
	struct wpabuf *json = fuzz_report_start("fuzz",
						2 * len + os_strlen(target) +
						os_strlen(f->name) + 64);

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
	json_add_string(json, "from", u->from);
	json_value_sep(json);
	json_add_int(json, "read", u->read);
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
				 size_t chain_off, enum fuzz_chain chain,
				 int defer_log)
{
	const struct fuzz_chain_fmt *fmt = fuzz_chain_of(chain);
	struct fuzz_entry *case_entry;
	size_t non_fuzzed_header_size = 0, fuzz_len, idx, new_len;
	size_t nelem = 0, nraw = 0, npos = 1, max_body = 0, room, off = 0;
	size_t nfield = 0, nopaque = 0, nfrag_max = 0;
	size_t nids = fuzz_num_ids(fmt);
	s64 elen_sizes[FUZZ_NUM_SHAPES];
	u8 staged[FUZZ_ELEM_MAX];
	char peerbuf[20];
	const char *peer;
	u16 offs[FUZZ_MAX_ELEMS];
	struct fuzz_field_use fieldv[FUZZ_MAX_FIELDS];
	struct fuzz_field_use opaquev[FUZZ_MAX_FIELDS];
	const struct fuzz_action_layout *layout;
	size_t action_at, var_unplaced = 0;
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

	/*
	 * W16c. Which layout this frame's own category selects, and what it
	 * says about where the element chain begins.
	 *
	 * The caller's chain_off and the layout are two claims about the same
	 * thing, and believing both means taking the LATER: each says the
	 * octets before it are fixed, and a caller that knows more than the
	 * category does -- a mesh peering frame whose fixed part depends on
	 * the peering type -- is not overruled by a table that knows less.
	 *
	 * A layout with no flexible member is the other direction: a positive
	 * statement that this frame has no element chain. Synthesising into
	 * one would put elements in a frame whose format has no place for
	 * them, and the walk would still succeed, so nothing would say so.
	 */
	action_at = fuzz_action_body_at(type, reply, len);
	layout = fuzz_action_layout_of(reply, len, action_at);
	if (layout) {
		if (layout->chain_at < 0) {
			chain_off = SIZE_MAX;
		} else {
			size_t c = action_at + (size_t) layout->chain_at;

			if (chain_off == SIZE_MAX || c > chain_off)
				chain_off = c;
		}
	}

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
	os_memset(elen_sizes, 0, sizeof(elen_sizes));
	if (chain_off < len && room >= FUZZ_ELEM_OVERHEAD) {
		size_t sh;

		nelem = fuzz_walk_elements(fmt, reply + chain_off,
					   len - chain_off, offs,
					   FUZZ_MAX_ELEMS, &nraw);
		/* A region that is not a clean chain still has one real
		 * insertion point: the end of the frame. */
		npos = nelem ? nelem + 1 : 1;

		max_body = room - FUZZ_ELEM_OVERHEAD;
		if (max_body > 255)
			max_body = 255;

		sizes[FUZZ_DOMAIN_ELEM] = (s64) nids * npos * (max_body + 1);
		sizes[FUZZ_DOMAIN_MULT] = (s64) nids * npos *
			(FUZZ_MULT_MAX - FUZZ_MULT_MIN + 1);
		if (nelem)
			sizes[FUZZ_DOMAIN_CHAIN] = (s64) nelem * 2 +
				(s64) nelem * (nelem - 1) / 2;

		/* The declared-length domain, one group per shape. Two
		 * octets of length field is a 65,536-value domain and one
		 * octet is 256, so a single flat product would put the whole
		 * of the wide one after the whole of the narrow one -- past
		 * the end of every real run, which is the arrangement this
		 * engine's round robin exists to avoid. Grouping by shape
		 * puts the wide domain's first case inside the first few
		 * hundred. */
		for (sh = 0; sh < FUZZ_NUM_SHAPES; sh++) {
			struct fuzz_shape info;

			fuzz_shape_at(fmt, sh, &info);
			elen_sizes[sh] = (s64) fuzz_count_of_shape(
				fmt, (enum fuzz_elem_shape) sh) *
				fuzz_tier_cases(fuzz_shape_len_domain(&info));
		}
		for (sh = 0; sh < FUZZ_NUM_SHAPES; sh++)
			sizes[FUZZ_DOMAIN_ELEN] += elen_sizes[sh];

		/* Fragments: a parent that declares everything its length
		 * field can say, plus as many continuations as there is room
		 * for. Two tail shapes -- a full last fragment and one that
		 * declares nothing, which is where the walk stops. */
		/* Fragments and nesting are the element chain's, and this is
		 * not a simplification of the other four -- their walkers
		 * have no continuation of any kind, so a case built that way
		 * would be an item nothing parses rather than a hostile one.
		 */
		if (fmt->elem &&
		    room > FUZZ_ELEM_OVERHEAD + FUZZ_FRAG_PARENT_LEN + 2) {
			nfrag_max = (room - FUZZ_ELEM_OVERHEAD -
				     FUZZ_FRAG_PARENT_LEN) /
				(2 + FUZZ_FRAG_PARENT_LEN);
			if (nfrag_max > FUZZ_FRAG_MAX)
				nfrag_max = FUZZ_FRAG_MAX;
			sizes[FUZZ_DOMAIN_FRAG] = (s64) nids * nfrag_max * 2;
		}

		/* Nesting: the innermost element is empty, so the whole nest
		 * is at most three headers deep. */
		if (fmt->elem &&
		    room >= (FUZZ_NEST_MAX + 1) * FUZZ_ELEM_OVERHEAD)
			sizes[FUZZ_DOMAIN_NEST] = (s64) nids * nids *
				FUZZ_NEST_MAX;
	}

	/* The named fields of this frame, each taken through its own domain
	 * rather than through the octets it occupies. */
	nfield = fuzz_collect_fields(type, reply, len, non_fuzzed_header_size,
				     target, fieldv, FUZZ_MAX_FIELDS, 0);
	for (idx = 0; idx < nfield; idx++)
		sizes[FUZZ_DOMAIN_FIELD] += fuzz_field_cases(&fieldv[idx]);

	nopaque = fuzz_collect_fields(type, reply, len, non_fuzzed_header_size,
				      target, opaquev, FUZZ_MAX_FIELDS, 1);

	/* W16a. How many fields of this frame kind the solver could NOT
	 * place. A field that does not resolve simply is not in the
	 * collection above, and a domain that quietly is not there is the one
	 * thing this report is not allowed to produce -- so the count travels
	 * with the frame. Zero every time is the expected answer and is worth
	 * being able to state. */
	for (idx = 0; idx < ARRAY_SIZE(fuzz_var_fields); idx++) {
		if (fuzz_var_fields[idx].frame != type)
			continue;
		if (fuzz_var_resolve(&fuzz_var_fields[idx], reply, len,
				     NULL, NULL) != 1)
			var_unplaced++;
	}
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
	if (var_unplaced) {
		json_value_sep(json_output);
		json_add_int(json_output, "var_unplaced",
			     (int) var_unplaced);
	}
	if (layout) {
		/* Which of the generated Action layouts this frame matched.
		 * A roster whose members are never named in a run is a
		 * roster nobody can tell from a roster that was never
		 * reached, which is the four-state report one level down. */
		json_value_sep(json_output);
		json_add_string(json_output, "layout", layout->member);
	}
	if (peer) {
		json_value_sep(json_output);
		json_add_string(json_output, "peer", peer);
	}
	fuzz_report_end(json_output);

	/* This frame now belongs to this target, whether or not a case was
	 * applied below: the counter moved and the frame was announced. A
	 * convergence point further down the transmit path will see the claim
	 * and leave it alone. */
	fuzz_claimed_buf = reply;
	fuzz_claimed_len = len;
	fuzz_claimed_by = case_entry->key;

	/* A held target is answered correctly, so the frame goes out as built:
	 * announced above, and deliberately unmutated. */
	if (held || case_id < 0 || case_id >= case_max)
		return len;

	kind = fuzz_case_select(case_id, sizes, &n);

	if (kind == FUZZ_DOMAIN_ELEM || kind == FUZZ_DOMAIN_MULT ||
	    kind == FUZZ_DOMAIN_ELEN || kind == FUZZ_DOMAIN_FRAG ||
	    kind == FUZZ_DOMAIN_NEST) {
		struct fuzz_elem_case c;
		size_t which, at = 0, staged_len = 0;
		int exact = 0;

		os_memset(&c, 0, sizeof(c));
		c.copies = 1;
		c.npos = npos;

		if (kind == FUZZ_DOMAIN_ELEN) {
			/* Grouped by shape, so the two-octet length field's
			 * domain is not queued behind the one-octet one. */
			size_t sh = fuzz_round_robin(n, elen_sizes,
						     FUZZ_NUM_SHAPES, &n);
			s64 count;

			if (sh >= FUZZ_NUM_SHAPES)
				return len;
			count = (s64) fuzz_count_of_shape(
				fmt, (enum fuzz_elem_shape) sh);
			if (count <= 0)
				return len;
			/* Identity fastest here too: every id of this shape
			 * is seen at declared length 0 before any of them is
			 * seen at 1. */
			which = fuzz_nth_of_shape(fmt,
						  (enum fuzz_elem_shape) sh,
						  (size_t) (n % count));
			n /= count;
			if (which >= nids)
				return len;
		} else {
			/* Identity varies fastest, so a run cut short has
			 * covered every id before it has covered any id
			 * twice. */
			which = (size_t) (n % (s64) nids);
			n /= (s64) nids;
		}

		fuzz_identity(fmt, which, &c.id);

		if (kind == FUZZ_DOMAIN_ELEM) {
			/* The swept axis is the DECLARED length, and the body
			 * follows it honestly. One axis, not a product: what
			 * an element says about itself and what it carries
			 * are swept apart, in ELEN. */
			c.domain = "elem";
			at = (size_t) (n % (s64) npos);
			n /= (s64) npos;
			c.minimum = fuzz_min_for(&c.id, &c.why);
			c.declared = fuzz_window_first(c.minimum,
						       (u32) max_body, n);
			c.body = fuzz_body_for(&c.id, c.declared);
			staged_len = fuzz_build_element(staged,
							sizeof(staged), &c.id,
							c.declared, c.body,
							&c.sub_in);
		} else if (kind == FUZZ_DOMAIN_ELEN) {
			/* The declared length alone, over everything its
			 * shape's field can express, with nothing behind it.
			 * Honest at the bottom of the domain and a lie above
			 * it, which for a two-octet length field moves the
			 * rest of the chain by up to 65,535 octets. */
			s64 domain = fuzz_shape_len_domain(&c.id.sh);

			c.domain = "elen";
			c.tier = fuzz_tier_name(domain);
			c.minimum = fuzz_min_for(&c.id, &c.why);
			c.declared = (u32) fuzz_tier_value(
				domain, fuzz_declare_for(&c.id, 0),
				c.minimum, n);
			c.body = 0;
			at = npos - 1;		/* the end of the frame */
			staged_len = fuzz_build_element(staged,
							sizeof(staged), &c.id,
							c.declared, 0,
							&c.sub_in);
		} else if (kind == FUZZ_DOMAIN_MULT) {
			c.domain = "mult";
			at = (size_t) (n % (s64) npos);
			n /= (s64) npos;
			c.copies = FUZZ_MULT_MIN + (size_t) n;
			c.declared = fuzz_declare_for(&c.id, 0);
			staged_len = fuzz_build_element(staged,
							sizeof(staged), &c.id,
							c.declared, 0,
							&c.sub_in);
		} else if (kind == FUZZ_DOMAIN_FRAG) {
			c.domain = "frag";
			c.nfrag = 1 + (size_t) (n % (s64) nfrag_max);
			n /= (s64) nfrag_max;
			at = npos - 1;		/* the end of the frame */
			c.declared = FUZZ_FRAG_PARENT_LEN;
			c.body = fuzz_body_for(&c.id, c.declared);
			staged_len = fuzz_build_fragmented(staged,
							   sizeof(staged),
							   &c.id, c.nfrag,
							   (int) n, &c.deflen,
							   &c.sub_in);
		} else {
			size_t outer;

			/* Depth before the container's identity. Depth is the
			 * cheap axis -- two values -- and the container's is
			 * 241 wide, so taking them the other way round puts
			 * the first depth-2 case 58,081 nest cases in, which
			 * is past the end of every run this engine will have.
			 * The inner element's identity still varies fastest
			 * of the three. */
			c.domain = "nest";
			c.depth = 1 + (size_t) (n % FUZZ_NEST_MAX);
			n /= FUZZ_NEST_MAX;
			outer = (size_t) (n % (s64) nids);
			fuzz_identity(fmt, outer, &c.outer);
			at = npos - 1;		/* the end of the frame */
			c.declared = fuzz_declare_for(&c.id, 0);
			staged_len = fuzz_build_nested(staged, sizeof(staged),
						       &c.id, &c.outer,
						       c.depth, &c.nest_at,
						       &c.sub_in);
		}

		/* Insertion point 'at': before the group starting at 'at', or
		 * -- when at == nelem, and always when the region was not a
		 * chain -- the end of the frame. Groups, not elements: a
		 * Fragment element continues the one before it, and going in
		 * between them removes octets from a third element without
		 * breaking the walk, so nothing would report it.
		 *
		 * A domain with no position axis of its own uses the last
		 * insertion point, which is the end of the frame and is the
		 * one position that is real whether or not the region walked.
		 * It is still a point IN the domain -- npos would be one past
		 * it, and a consumer checking that every insertion point gets
		 * used would see a value the domain does not contain. */
		if (at >= npos)
			at = npos - 1;

		/*
		 * W10. Two rules, both read off the staged octets rather than
		 * known from the domain that built them -- so a domain added
		 * later obeys them without being told.
		 *
		 * 1. An item whose declared length does not match its body is
		 *    absorbed by whatever follows it. The span stays inside
		 *    the buffer, the walker's bound is never tested, and the
		 *    rest of the chain is not hostile -- it is UNREAD.
		 *    `ieee802_11_parse_elems()` stops at the first element
		 *    whose length runs past the end, and its callers discard
		 *    the frame whole. So it goes LAST, which is the one
		 *    position where the overrun can leave the buffer.
		 *
		 * 2. Everything else keeps its position axis, because an
		 *    honest element inserted at index 0 of a chain of twelve
		 *    really has tested twelve elements and one more.
		 */
		fuzz_walk_depth(fmt, staged, staged_len, &exact);
		c.walks = exact && staged_len > 0;
		if (!c.walks)
			at = npos - 1;

		/* W12. In the tail case space the span under test is the last
		 * thing in the frame, whatever the position axis said -- so
		 * a read past the synthesised element's body leaves the
		 * frame instead of landing in the element after it. The axis
		 * is not swept here; it is swept in the other case space, and
		 * the opset says which one this is. */
		c.tail_mode = fuzz_tail_mode();
		if (c.tail_mode)
			at = npos - 1;

		off = nelem && at < nelem ? chain_off + offs[at] : len;
		c.at = at;
		c.off = off;
		if (c.depth)
			c.nest_at += off;

		/* A case the sizing admitted that the headroom will not hold:
		 * the multiplicity domain is 2..5 copies whatever the room,
		 * and fuzz_insert_bytes() refuses rather than clipping -- so
		 * without this the frame goes out unmutated and the ledger
		 * still counts the id as sent at multiplicity 5. Clamping
		 * keeps case_max a function of the frame's length alone, which
		 * is what lets a case_id replay, and the report says what was
		 * actually sent rather than what was asked for. */
		c.copies_req = c.copies;
		if (staged_len && c.copies * staged_len > capacity - len) {
			c.copies = (capacity - len) / staged_len;
			if (!c.copies)
				c.copies = 1;	/* reported; the insert below
						 * refuses it and the frame
						 * goes out as built */
		}

		/* Measured, not assumed: how far a walker gets through the
		 * region before the mutation, and how far after. The insertion
		 * only ever adds items, so post below pre is a chain this case
		 * stopped the consumer from reading. */
		if (chain_off < len)
			c.pre = fuzz_walk_depth(fmt, reply + chain_off,
						len - chain_off, NULL);

		new_len = fuzz_insert_bytes(reply, len, capacity, off, staged,
					    staged_len, c.copies);

		if (chain_off < new_len)
			c.post = fuzz_walk_depth(fmt, reply + chain_off,
						 new_len - chain_off, NULL);

		fuzz_report_elem(target, non_fuzzed_header_size,
				 fuzz_frame_kind(type), &c, len, new_len,
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
		const struct fuzz_field_use *v =
			kind == FUZZ_DOMAIN_FIELD ? fieldv : opaquev;
		size_t nv = kind == FUZZ_DOMAIN_FIELD ? nfield : nopaque;
		s64 per[FUZZ_MAX_FIELDS];
		size_t which;
		s64 k;

		for (idx = 0; idx < nv; idx++)
			per[idx] = kind == FUZZ_DOMAIN_FIELD ?
				fuzz_field_cases(&v[idx]) :
				FUZZ_PATTERN_COUNT;

		/* The same round robin as the outer one, one level down, so
		 * the field's identity varies fastest: a run cut short has
		 * touched every field of the frame before it has touched any
		 * field twice. Which matters here more than anywhere -- a
		 * 65,536-value field would otherwise bury every field after
		 * it. */
		which = fuzz_round_robin(n, per, nv, &k);
		if (which < nv) {
			const struct fuzz_field_use *u = &v[which];
			const struct fuzz_field *f = &u->f;

			if (kind == FUZZ_DOMAIN_FIELD) {
				u64 built = fuzz_field_read(reply, f);
				u64 want = fuzz_field_value(u, built, k);

				fuzz_field_write(reply, f, want);
				fuzz_report_field(target,
						  non_fuzzed_header_size,
						  fuzz_frame_kind(type), len,
						  u, built, want,
						  fuzz_tier_named(
							  fuzz_field_tier(u)),
						  defer_log, reply,
						  case_entry->key, case_id);
			} else {
				fuzz_fill_pattern(reply + f->offset, f->width,
						  (size_t) k);
				fuzz_report_pattern(target,
						    non_fuzzed_header_size,
						    fuzz_frame_kind(type), len,
						    u, (size_t) k, defer_log,
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

	/*
	 * W12, for the octet sweep. The span a consumer reads is not the
	 * octet -- it is the element the octet is in, handed out as a
	 * (pointer, length) pair into this very buffer. So the frame is cut
	 * to end where that element ends, and a read past it leaves the
	 * frame rather than landing in the element after it.
	 *
	 * Only where the region walks and the octet is inside it. An octet in
	 * the fixed part of a frame is read at a known offset and a known
	 * width; there is no span to over-read, and cutting the frame there
	 * would produce something the daemon drops at the header -- a case
	 * space that measures nothing, which is the failure this plan is
	 * about rather than a mitigation of it.
	 */
	new_len = len;
	/* And only where the caller opted into a frame of a different length
	 * -- the same opt-in the length domain uses, which is headroom plus
	 * using the return value. apply_mutation() returns void, so a site
	 * that calls it sends what it built whatever this said, and the
	 * report would be describing a frame nobody transmitted. */
	if (fuzz_tail_mode() && capacity > len && chain_off < len &&
	    non_fuzzed_header_size + idx >= chain_off) {
		size_t end = fuzz_group_end(fmt, reply + chain_off,
					    len - chain_off,
					    non_fuzzed_header_size + idx -
					    chain_off);

		if (end && chain_off + end < len)
			new_len = chain_off + end;
	}
	json_add_int(json_output, "tail_mode", fuzz_tail_mode() ? 1 : 0);
	json_value_sep(json_output);
	json_add_int(json_output, "cut", len - new_len);
	json_value_sep(json_output);
	json_add_int(json_output, "len", new_len);
	json_value_sep(json_output);

	if (defer_log) {
		pending_log = json_output;
		pending_target = case_entry->key;
		pending_case_id = case_id;
	} else {
		fuzz_emit(json_output, reply, new_len);
	}

	return new_len;
}


void apply_mutation(const char *target, enum fuzz_frame_type type, u8 *reply,
		    size_t len)
{
	apply_mutation_int(target, type, reply, len, len, SIZE_MAX,
			   FUZZ_CHAIN_ELEM, 0);
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
				  FUZZ_CHAIN_ELEM, 0);
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
				  FUZZ_CHAIN_ELEM, 0);
}


u8 * apply_mutation_copy(const char *target, enum fuzz_frame_type type,
			 const u8 *buf, size_t *len, size_t headroom,
			 size_t chain_off, enum fuzz_chain chain)
{
	u8 *copy;
	size_t cap;

	if (!fuzz_enabled() || !buf || !len || !*len)
		return NULL;

	cap = *len + headroom;
	copy = os_malloc(cap);
	if (!copy)
		return NULL;

	os_memcpy(copy, buf, *len);
	*len = apply_mutation_int(target, type, copy, *len, cap, chain_off,
				  chain, 0);

	return copy;
}


/*
 * Which parser this Action frame is headed for, read out of the frame.
 *
 * Also how many octets that reading consumed, which is the only offset in an
 * Action frame this engine is entitled to claim as a chain start. What
 * follows a category is keyed by the category through a union that says
 * nothing about which member applies, so anything past the label's own prefix
 * would be a layout this file invented. The chain walk refuses a region it
 * cannot consume exactly and falls back to appending, so claiming the prefix
 * costs nothing when the rest is not a chain and gains the whole position
 * domain when it is.
 */
static const char * fuzz_action_label(const u8 *body, size_t len,
				      size_t *hdr)
{
	int code = -1, otype = -1;
	size_t i;
	u8 cat;

	if (hdr)
		*hdr = 1;
	if (!body || !len)
		return FUZZ_ACTION_OTHER;

	cat = body[0];
	if (len >= 2)
		code = body[1];
	/* The vendor type sits after the three-octet OUI. Whether a vendor
	 * follows at all is stated by the generated table carrying a code on
	 * those rows and not on the others, so it is not decided here. */
	if (len >= 6 && WPA_GET_BE24(body + 2) == FUZZ_ACTION_VENDOR_OUI)
		otype = body[5];

	for (i = 0; i < ARRAY_SIZE(fuzz_action_labels); i++) {
		const struct fuzz_action_label_entry *e =
			&fuzz_action_labels[i];

		if (e->cat != cat)
			continue;
		if (e->code >= 0 && e->code != code)
			continue;
		if (e->oui_type >= 0 && e->oui_type != otype)
			continue;
		if (hdr)
			*hdr = e->hdr > len ? len : e->hdr;
		return e->label;
	}

	return FUZZ_ACTION_OTHER;
}


/*
 * Whether a named hook has already taken this frame.
 *
 * The Action convergence points sit BELOW several hooks that already name
 * their frames -- the WNM transmit paths all build a frame, mutate it under
 * their own label, and then hand it to hostapd_drv_send_action(). Mutating it
 * again there is not a second case, it is one transmitted frame with two
 * cases charged against it: two counters move, the as-built column undoes one
 * of the two mutations and reports the result as what the configuration
 * built, and the repro record replays something that was never sent.
 *
 * So the lower hook yields to the higher one, which is the right way round:
 * a site that named its frame knows more about it than the convergence point
 * does. The claim is scoped to the BUFFER rather than kept as a global flag,
 * because a flag would also suppress the first Action frame after any
 * unrelated mutation anywhere in the process.
 *
 * It is reported rather than done quietly: a label that never fires because
 * something above it always fires first is a fact about the run, and it looks
 * exactly like a label that is never reached.
 */
static int fuzz_claim_held(const u8 *buf, size_t len)
{
	if (!fuzz_claimed_buf || !fuzz_claimed_len || !len)
		return 0;

	/* Overlap, not equality: the named hook is handed the frame its own
	 * builder produced, and the convergence point below is handed a
	 * pointer into the same allocation at whatever offset that frame's
	 * header ended. */
	return buf < fuzz_claimed_buf + fuzz_claimed_len &&
		fuzz_claimed_buf < buf + len;
}


static void fuzz_report_claimed(const char *target, const char *by,
				size_t len)
{
	struct wpabuf *json = fuzz_report_start("claimed",
						os_strlen(target) +
						os_strlen(by ? by : ""));

	if (!json)
		return;

	json_value_sep(json);
	json_add_string(json, "target", target);
	json_value_sep(json);
	json_add_string(json, "by", by ? by : "unknown");
	json_value_sep(json);
	json_add_int(json, "len", len);
	fuzz_report_end(json);
}


u8 * fuzz_action_mutate(const u8 *body, size_t *len)
{
	size_t hdr = 1;
	const char *target;
	int claimed;

	if (!fuzz_enabled() || !body || !len || !*len)
		return NULL;

	target = fuzz_action_label(body, *len, &hdr);

	claimed = fuzz_claim_held(body, *len);
	/* Cleared either way, so a claim left behind by a frame that was
	 * built and then abandoned costs at most the next Action frame and
	 * not every one after it. */
	fuzz_claimed_buf = NULL;
	fuzz_claimed_len = 0;
	if (claimed) {
		fuzz_report_claimed(target, fuzz_claimed_by, *len);
		fuzz_claimed_by = NULL;
		return NULL;
	}
	fuzz_claimed_by = NULL;

	/* The element chain, because that is what an Action frame's variable
	 * part is for every category this engine can name one for. A DPP or
	 * P2P Action frame carries ITS protocol's attributes instead, and
	 * saying which label carries which chain is the same category-keyed
	 * guess the layout table declined to make: the label is read out of
	 * the frame, the chain format is not stated anywhere a reader of the
	 * frame can get at. */
	return apply_mutation_copy(target, FUZZ_TYPE_ACTION_BODY, body, len,
				   FUZZ_HEADROOM, hdr, FUZZ_CHAIN_ELEM);
}


size_t apply_mutation_defer_log(const char *target,
				enum fuzz_frame_type type, u8 *reply,
				size_t len, size_t capacity)
{
	return apply_mutation_int(target, type, reply, len, capacity,
				  SIZE_MAX, FUZZ_CHAIN_ELEM, 1);
}
