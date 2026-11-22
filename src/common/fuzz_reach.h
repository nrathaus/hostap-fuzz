/*
 * Reach instrumentation: what the receiving parser actually read
 * Copyright (c) 2026, Noam Rathaus <rathaus@gmail.com>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef FUZZ_REACH_H
#define FUZZ_REACH_H

#include <stddef.h>
#include <stdint.h>

/*
 * fuzz.c reports what LEFT the radio. It cannot report what was READ, and the
 * gap between the two is where a case space goes quietly dead: the walker
 * stopped at item two, the frame was discarded at the door, the daemon never
 * dispatched it. The run stays green and fast and measures nothing.
 *
 * This is the other half. It lives in the RECEIVER -- in both hwsim
 * topologies the victim is built from this tree -- and reports one fact per
 * parse:
 *
 *	a named walker was handed a span of 'len' octets and got through 'got'
 *	of them.
 *
 * That is reach, not correctness, and the distinction is the whole argument
 * for its being here at all. It is a position, not a judgement: nothing in
 * this file decides whether a frame was interesting, whether a parse result
 * was wrong, or whether anything should be reported to a human. The oracle
 * is still, and only, a process that died.
 *
 * It is a SEPARATE build flag from CONFIG_FUZZ on purpose. The victim in the
 * inverted topology must not mutate -- a run with both ends mutating has no
 * reference -- so it cannot be a CONFIG_FUZZ build, and until there was a
 * second flag there was no build that could both be a victim and say what it
 * read. A reach build transmits exactly what a stock build transmits; it
 * counts and it prints, and it changes no parse decision anywhere.
 *
 * THE LIMIT, stated here because the number travels without it otherwise:
 * 'got' is measured where the hook was put, which is the walker's own exits.
 * A frame that reached the walker and was then discarded by the handler
 * behind it counts here as read. This says the octets were parsed. It does
 * not say they were acted on.
 */

#ifdef CONFIG_FUZZ_REACH

/*
 * One parse, as it returns.
 *
 * 'parser' is a label from the generated roster -- see
 * fuzzing/reach/reach.py, which extracts the labels from these call sites
 * and refuses a build where a rostered walker has a return that does not
 * pass through here. That check is what makes "never reached" mean never
 * reached rather than "someone added an early return in a rebase".
 *
 * 'buf'/'len' are the span the walker was handed, and 'got' is how far into
 * it the walker got. got == len is a completed walk. got < len is a walk
 * that stopped, and where it stopped is the number that matters: it is the
 * receive-side counterpart of the pre/post depth every element case already
 * reports from the transmit side.
 */
void fuzz_reach(const char *parser, const uint8_t *buf, size_t len,
		size_t got);

/* False when FUZZ_REACH_DISABLE=1, so one binary can be a measured victim
 * and an unmeasured one without being rebuilt. */
int fuzz_reach_enabled(void);

#else /* CONFIG_FUZZ_REACH */

/*
 * Not a reach build. Every hook compiles away, so a parser carrying one is
 * byte-for-byte the function it was -- which is the property that lets these
 * hooks sit in the middle of shared parsing code at all.
 */

static inline void fuzz_reach(const char *parser, const uint8_t *buf,
			      size_t len, size_t got)
{
	(void) parser;
	(void) buf;
	(void) len;
	(void) got;
}

static inline int fuzz_reach_enabled(void)
{
	return 0;
}

#endif /* CONFIG_FUZZ_REACH */

#endif /* FUZZ_REACH_H */
