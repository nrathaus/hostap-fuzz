/*
 * Frame mutation hooks for fuzzing hostapd's transmit paths
 * Copyright (c) 2025, Noam Rathaus <rathaus@gmail.com>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef FUZZ_H
#define FUZZ_H

#include <stddef.h>
#include <stdint.h>

/* The TLV chain formats this tree has, generated from the walkers that
 * parse them. Only the enum is visible here; the tables come with it
 * where FUZZ_CHAINS_TABLES is defined, which is fuzz.c and nowhere
 * else. */
#include "fuzz_chains.h"

/* Which header the frame starts with, so the mutation can be kept out of the
 * fields that would get it discarded before anything parses it, and so that a
 * consumer can dissect the hexdump without inferring the layout from the
 * target's name. The value is reported as "frame" on every mutation. */
enum fuzz_frame_type {
	FUZZ_TYPE_IEEE80211_MGMT = 1,
	FUZZ_TYPE_IEEE802_1X_HDR = 2,
	/*
	 * A frame body with no header of its own, because something below the
	 * call site builds one: an Action frame's category and fields, or the
	 * algorithm-specific part of an Authentication frame handed to the
	 * driver. There is accordingly nothing to keep the mutation out of --
	 * the first octet is already one the peer parses.
	 */
	FUZZ_TYPE_FRAME_BODY = 3,
	/*
	 * An Action frame body, starting at the Category field. Its own kind
	 * rather than a plain body, because the category and the code after
	 * it are what the receiver dispatches on -- so they are what a
	 * consumer has to read to know which parser a case reached, and
	 * inferring that from the target's name is the mistake "frame" was
	 * added to stop.
	 */
	FUZZ_TYPE_ACTION_BODY = 4,
	/*
	 * Not a frame at all: an octet stream on a socket. The length domain
	 * here is bounded by what the peer will read, not by the maximum
	 * MMPDU, which makes the same resize contract a materially different
	 * sweep. It is the only place on this product where that is true.
	 */
	FUZZ_TYPE_OCTET_STREAM = 5,
};

/*
 * Spare room a call site allocates beyond the frame it built, so that the
 * frame's length is a domain the sweep can move rather than a constant.
 *
 * One maximal element's worth: a 2-octet element header and the 255 octets of
 * body its length field can describe. That is the smallest headroom in which a
 * whole new element can appear, which is the thing this exists to make
 * possible. It is derived from the element format itself, not from any
 * particular element.
 *
 * Zero without CONFIG_FUZZ, so a stock build allocates exactly what it did and
 * apply_mutation_resize() folds to returning the length it was given. The call
 * site then needs no #ifdef of its own and compiles to the same code as before.
 */
#ifdef CONFIG_FUZZ
#define FUZZ_HEADROOM (2 + 255)
#else
#define FUZZ_HEADROOM 0
#endif

/*
 * Headroom for a call site that is not sending an 802.11 frame.
 *
 * Every hooked path but one is capped by what a management frame may be, so
 * the length domain there is 0..2,304 however much room the engine is given.
 * A socket has no such cap: the peer reads a length and then that many
 * octets. 64 KiB is what a two-octet length can ask for, which is the next
 * bound above the MMPDU that anything in this tree actually states.
 */
#ifdef CONFIG_FUZZ
#define FUZZ_STREAM_HEADROOM 65535
#else
#define FUZZ_STREAM_HEADROOM 0
#endif

#ifdef CONFIG_FUZZ

/* False when FUZZ_DISABLE=1, so a fuzzing build can still be run as a normal
 * AP without rebuilding. Always false when built without CONFIG_FUZZ. */
int fuzz_enabled(void);

/* Mutate one byte of 'buf' and log both the mutation and the resulting frame. */
void apply_mutation(const char *target, enum fuzz_frame_type type, uint8_t *buf,
		    size_t len);

/*
 * As apply_mutation(), but the caller has room beyond 'len' and is willing to
 * send a frame of a different length, so the frame's length becomes a domain
 * of its own -- 0 .. capacity -- swept alongside the octet domain rather than
 * after it. Returns the length to send, never more than 'capacity'.
 *
 * A call site opts in by having the headroom and by using the return value.
 * One that does neither is unchanged, which is why this is a second entry
 * point rather than a wider signature on apply_mutation().
 */
size_t apply_mutation_resize(const char *target, enum fuzz_frame_type type,
			     uint8_t *buf, size_t len, size_t capacity);

/*
 * As apply_mutation_resize(), and in addition the caller says at what offset
 * the frame's element chain begins, which puts the element domains in play:
 * every id in the registries, synthesised and inserted at every position in
 * the chain, at every length the headroom allows, and the chain's own shape
 * changed by deleting, duplicating and swapping what is already there.
 *
 * The offset has to come from the caller because only the caller knows the
 * frame's layout. A caller that does not know uses apply_mutation_resize().
 */
size_t apply_mutation_elements(const char *target, enum fuzz_frame_type type,
			       uint8_t *buf, size_t len, size_t capacity,
			       size_t chain_off);

/*
 * Same as apply_mutation_resize(), but the frame hexdump is not emitted yet:
 * the caller must follow up with fuzz_log_sent_frame() once the frame is
 * final. Use this where the frame is integrity-protected after the mutation
 * point (EAPOL-Key MIC), so that the log shows the bytes actually
 * transmitted.
 *
 * It carries a capacity for the same reason apply_mutation_resize() does,
 * and both EAPOL-Key call sites give it one. The receivers on this frame
 * bound its declared length with '>' rather than '==', so a frame longer
 * than it says it is is ACCEPTED on both sides -- which makes the length a
 * domain here rather than a constant. A caller with nothing spare passes
 * capacity == len and the domain is empty, as before.
 */
size_t apply_mutation_defer_log(const char *target, enum fuzz_frame_type type,
				uint8_t *buf, size_t len, size_t capacity);

/*
 * As apply_mutation_elements(), for a call site that holds the frame as
 * const -- which every convergence point below the builders does, because by
 * then the frame is somebody else's.
 *
 * 'chain' is which TLV format the region at 'chain_off' is in. There are five
 * on this product and four of them are not what the element domains walk: a
 * WPS attribute is a big-endian u16 type and a big-endian u16 length against
 * an element's one and one. It comes from the caller for the same reason the
 * offset does -- only the caller knows what it is holding -- and a caller
 * that is handed an element chain passes FUZZ_CHAIN_ELEM, which is what every
 * other entry point here uses.
 *
 * Returns a buffer the caller must os_free(), with '*len' updated to what to
 * send, or NULL when the caller should go on with the frame it already has.
 * NULL is not an error: it is what a stock build, a disabled run and an
 * allocation failure all return, and the call site reads the same in each.
 */
uint8_t * apply_mutation_copy(const char *target, enum fuzz_frame_type type,
			      const uint8_t *buf, size_t *len,
			      size_t headroom, size_t chain_off,
			      enum fuzz_chain chain);

/*
 * As apply_mutation_copy(), for an Action frame whose body starts at the
 * Category field -- and the one entry point that is not given a target name,
 * because it reads one out of the frame.
 *
 * Over a hundred call sites reach the two functions this exists for. Naming
 * them individually would be a hundred hooks to carry across every rebase,
 * and would file each case under whichever caller reached the convergence
 * point rather than under the protocol that parses it. The category, the code
 * after it and the vendor type after that are how the RECEIVER decides what
 * it is holding, so they are how the ledger should.
 */
uint8_t * fuzz_action_mutate(const uint8_t *body, size_t *len);

/* Emit the frame hexdump held back by apply_mutation_defer_log(). Safe to call
 * when no mutation is pending; it is then a no-op. */
void fuzz_log_sent_frame(const uint8_t *buf, size_t len);

/* Read an integer tunable from the environment, or 'fallback' if unset. */
int fuzz_env_int(const char *name, int fallback);

/*
 * The source address the daemon is about to present, as a swept domain.
 *
 * W8 swept concurrent peers with N real peers. Underneath that is a cheaper
 * and larger domain: the number of DISTINCT SOURCE ADDRESSES one peer
 * presents. The state that gates a second attempt on this product is keyed by
 * address, not by radio -- a WPS registrar's device list, a P2P peer table
 * with its own eviction, SAE's comeback slots, a DPP Controller's connection
 * list, and nan_ndp_attr_handle_req(), which refuses a second request from a
 * peer already in progress. One fixed address gets exactly one request
 * through per run, and everything behind the second is unreachable however
 * many cases run.
 *
 * THE DECISION, written down because the two obvious ways are both wrong:
 *
 *   N vifs      is N stations, which is W8 again at N times the cost. It
 *               answers a different question -- concurrent peers, not one
 *               peer with many identities.
 *   injection   cannot be done from here at all. An injected frame whose
 *               addr2 matches no local interface is dropped by mac80211
 *               BEFORE it leaves the radio, silently, because it never
 *               resolves a channel context. A hooked daemon does not have
 *               that problem, its frames going out through its own vif, but
 *               for the same reason it cannot vary addr2 either.
 *
 * So neither. The address a daemon presents is already something this product
 * changes on purpose, and it changes it in one place per identity. This turns
 * that choice into a domain instead of a coin toss, and the frame still
 * leaves through the daemon's own vif -- which is what keeps the mac80211
 * drop above out of reach.
 *
 * Called immediately AFTER the tree's own picker, and it varies octets 1..5
 * only. Octet 0 is where the field's structure lives -- unicast and locally
 * administered -- and the tree has exactly one place that sets those bits.
 * Reaching in to re-apply them here would be a second copy of a rule that
 * already exists, and the first thing to go stale.
 *
 * 'who' is which identity is being changed, from the generated roster: a run
 * has to be able to say WHICH address varied, not only that one did.
 * Returns 1 when the domain is on and the address was replaced, 0 when it is
 * off and the caller keeps what its own picker produced.
 */
int fuzz_source_addr(const char *who, uint8_t *addr);


/*
 * Stage multiplicity. True while this peer still has budget for an extra
 * occurrence of 'stage', spending one unit of it each time it returns true,
 * so a guard evaluated in a loop terminates:
 *
 *	if (normally_once || fuzz_stage_repeat("x", addr))
 *	while (fuzz_stage_repeat("x", addr)) send_it();
 *
 * The budget is FUZZ_REPEAT_<STAGE>, default 0 -- so a build with this
 * compiled in behaves exactly as it did until one is set. 'peer' may be NULL
 * for a stage that is not per-peer.
 */
int fuzz_stage_repeat(const char *stage, const uint8_t *peer);

/* Forget every stage budget held for this peer, so its next session starts
 * over. Call where a station's state is torn down. */
void fuzz_peer_reset(const uint8_t *peer);

/*
 * Say which peer the NEXT mutation is for, where the frame itself does not
 * say. A management frame carries its destination address and needs no hint;
 * an EAPOL-Key body does not, because its addressing is in the ethernet
 * header added below the call site.
 *
 * One-shot: cleared by the next mutation whether or not it used it, so a
 * caller that sets one and then takes an error path cannot have it attached
 * to another peer's frame. Several peers share a target's case counter, so
 * each receives a different case -- a multi-peer run is N times the stimulus
 * rather than N copies of it -- and the record is only readable if it says
 * which peer got which case.
 */
void fuzz_peer_hint(const uint8_t *peer);

#else /* CONFIG_FUZZ */

/*
 * Not a fuzzing build. Every hook compiles away to nothing, so most call sites
 * need no #ifdef of their own and an ordinary build transmits unmodified
 * frames. fuzz_enabled() folding to a constant 0 is what lets a caller's
 * surrounding logic drop out as dead code.
 */

static inline int fuzz_enabled(void)
{
	return 0;
}

static inline void apply_mutation(const char *target,
				  enum fuzz_frame_type type, uint8_t *buf,
				  size_t len)
{
}

static inline size_t apply_mutation_resize(const char *target,
					   enum fuzz_frame_type type,
					   uint8_t *buf, size_t len,
					   size_t capacity)
{
	return len;
}

static inline size_t apply_mutation_elements(const char *target,
					    enum fuzz_frame_type type,
					    uint8_t *buf, size_t len,
					    size_t capacity, size_t chain_off)
{
	return len;
}

static inline uint8_t * apply_mutation_copy(const char *target,
					    enum fuzz_frame_type type,
					    const uint8_t *buf, size_t *len,
					    size_t headroom, size_t chain_off,
					    enum fuzz_chain chain)
{
	(void) target;
	(void) type;
	(void) buf;
	(void) len;
	(void) headroom;
	(void) chain_off;
	(void) chain;
	return NULL;
}

static inline uint8_t * fuzz_action_mutate(const uint8_t *body, size_t *len)
{
	(void) body;
	(void) len;
	return NULL;
}

static inline size_t apply_mutation_defer_log(const char *target,
					     enum fuzz_frame_type type,
					     uint8_t *buf, size_t len,
					     size_t capacity)
{
	(void) capacity;
	return len;
}

static inline void fuzz_log_sent_frame(const uint8_t *buf, size_t len)
{
}

static inline int fuzz_env_int(const char *name, int fallback)
{
	return fallback;
}


static inline int fuzz_source_addr(const char *who, uint8_t *addr)
{
	(void) who;
	(void) addr;
	return 0;
}

static inline int fuzz_stage_repeat(const char *stage, const uint8_t *peer)
{
	return 0;
}

static inline void fuzz_peer_reset(const uint8_t *peer)
{
}

static inline void fuzz_peer_hint(const uint8_t *peer)
{
}

#endif /* CONFIG_FUZZ */

#endif /* FUZZ_H */
