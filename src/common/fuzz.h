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
 * Same as apply_mutation(), but the frame hexdump is not emitted yet: the
 * caller must follow up with fuzz_log_sent_frame() once the frame is final.
 * Use this where the frame is integrity-protected after the mutation point
 * (EAPOL-Key MIC), so that the log shows the bytes actually transmitted.
 */
void apply_mutation_defer_log(const char *target, enum fuzz_frame_type type,
			      uint8_t *buf, size_t len);

/* Emit the frame hexdump held back by apply_mutation_defer_log(). Safe to call
 * when no mutation is pending; it is then a no-op. */
void fuzz_log_sent_frame(const uint8_t *buf, size_t len);

/* Read an integer tunable from the environment, or 'fallback' if unset. */
int fuzz_env_int(const char *name, int fallback);

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

static inline void apply_mutation_defer_log(const char *target,
					    enum fuzz_frame_type type,
					    uint8_t *buf, size_t len)
{
}

static inline void fuzz_log_sent_frame(const uint8_t *buf, size_t len)
{
}

static inline int fuzz_env_int(const char *name, int fallback)
{
	return fallback;
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
