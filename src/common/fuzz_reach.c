/*
 * Reach instrumentation: what the receiving parser actually read
 * Copyright (c) 2026, Noam Rathaus <rathaus@gmail.com>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "includes.h"

#include "common.h"
#include "fuzz_reach.h"
#include "fuzz_reach_targets.h"

/*
 * Output contract, the same one fuzz.c keeps: every line under the "[fuzz] "
 * prefix is a JSON object with a "msg" key, and a consumer may ignore a "msg"
 * it does not recognise. A reach build therefore drops into any existing
 * consumer without one line of change -- it simply has more to say.
 *
 * Written with os_snprintf into a fixed buffer rather than through the JSON
 * helpers, because this file is linked into the VICTIM. Pulling NEED_JSON and
 * NEED_BASE64 into a build whose only job is to be read from would make the
 * instrument a reason to link code the measurement is not about.
 */

/*
 * How many octets of the parsed span are quoted, so that a consumer can say
 * WHICH frame this parse was of.
 *
 * The receiver cannot know anything about cases: it has no case counter, no
 * target label, and no way to be told one without the harness putting
 * something on the air that a real peer would not send. So the correlation is
 * done on the octets themselves -- the consumer looks for the span in the
 * frames it knows it transmitted.
 *
 * It is the WHOLE span rather than a sample of it, and that was learned from
 * a live run. A station's association request is not the buffer the station
 * built: wpa_supplicant hands the driver its elements, and mac80211 builds
 * the frame with its own elements in front of them AND a WMM element after
 * them. Quoting the head matched nothing. Quoting the head and the tail
 * matched nothing either. What this run sent was 85 octets in the MIDDLE of
 * the 143 the AP walked, and nothing short of the span itself finds that.
 *
 * 2,304 is the cap on every span a walker on this product gets except one:
 * the maximum MMPDU. The DPP socket is the exception and is truncated, which
 * the message says rather than leaving the consumer to assume.
 */
#define FUZZ_REACH_DUMP 2304

static int reach_disabled = -1;


int fuzz_reach_enabled(void)
{
	const char *val;

	if (reach_disabled < 0) {
		val = getenv("FUZZ_REACH_DISABLE");
		reach_disabled = val && *val && *val != '0';
	}

	return !reach_disabled;
}


/* Append to a bounded buffer, returning the new offset. Never writes past
 * 'buflen'; a line that would overflow is truncated rather than growing a
 * buffer in the victim's receive path. */
static size_t reach_add(char *buf, size_t buflen, size_t off,
			const char *fmt, ...)
{
	va_list ap;
	int n;

	if (off >= buflen)
		return off;
	va_start(ap, fmt);
	n = vsnprintf(buf + off, buflen - off, fmt, ap);
	va_end(ap);
	if (n < 0)
		return off;
	if ((size_t) n >= buflen - off)
		return buflen;

	return off + (size_t) n;
}


/* A build condition is C source, so it can hold the characters JSON cares
 * about. Same escaper as fuzz.c's, for the same reason. */
static size_t reach_add_escaped(char *buf, size_t buflen, size_t off,
				const char *s)
{
	const char *p;

	for (p = s; *p; p++) {
		if (*p == '"' || *p == '\\')
			off = reach_add(buf, buflen, off, "\\%c", *p);
		else if ((unsigned char) *p < 0x20)
			off = reach_add(buf, buflen, off, "\\u%04x",
					(unsigned char) *p);
		else
			off = reach_add(buf, buflen, off, "%c", *p);
	}

	return off;
}


static const char * reach_daemon(void)
{
#ifdef HOSTAPD
	return "hostapd";
#else /* HOSTAPD */
	return "wpa_supplicant";
#endif /* HOSTAPD */
}


/*
 * Announced once, before any reach line, for the same reason fuzz.c announces
 * its targets: a parser that is not in this binary and a parser nothing
 * reached look identical in a report that only counts what it saw, and they
 * mean opposite things. One is a measurement; the other is a build.
 */
static void fuzz_reach_report_inventory(void)
{
	char line[4096];
	size_t off = 0, i;
	int first;

	off = reach_add(line, sizeof(line), off,
			"{\"msg\":\"reach_inventory\",\"daemon\":\"%s\"",
			reach_daemon());

	/*
	 * How many element walkers this tree has, against how many report.
	 * Announced by the RUN rather than left in a document, because a
	 * reach figure quoted without it reads as a statement about the
	 * product when it is a statement about one parser.
	 */
	off = reach_add(line, sizeof(line), off, ",\"walkers\":[%d,%d]",
			FUZZ_REACH_WALKERS, FUZZ_REACH_WALKERS_HOOKED);

	off = reach_add(line, sizeof(line), off, ",\"parsers\":[");
	first = 1;
	for (i = 0; i < ARRAY_SIZE(fuzz_reach_present); i++) {
		if (!fuzz_reach_present[i])
			continue;	/* excluded by this build */
		off = reach_add(line, sizeof(line), off, "%s\"%s\"",
				first ? "" : ",", fuzz_reach_present[i]);
		first = 0;
	}
	off = reach_add(line, sizeof(line), off, "]");

	off = reach_add(line, sizeof(line), off, ",\"roster\":[");
	for (i = 0; i < ARRAY_SIZE(fuzz_reach_roster); i++) {
		off = reach_add(line, sizeof(line), off,
				"%s{\"name\":\"%s\",\"fn\":\"%s\",\"guard\":",
				i ? "," : "", fuzz_reach_roster[i].name,
				fuzz_reach_roster[i].fn);
		if (fuzz_reach_roster[i].guard) {
			off = reach_add(line, sizeof(line), off, "\"");
			off = reach_add_escaped(line, sizeof(line), off,
						fuzz_reach_roster[i].guard);
			off = reach_add(line, sizeof(line), off, "\"");
		} else {
			off = reach_add(line, sizeof(line), off, "null");
		}
		off = reach_add(line, sizeof(line), off, "}");
	}
	off = reach_add(line, sizeof(line), off, "]}");

	wpa_printf(MSG_INFO, "[fuzz] %s", line);
}


void fuzz_reach(const char *parser, const uint8_t *buf, size_t len,
		size_t got)
{
	/* Static, not on the stack: 4.9 KiB in a receive path that every
	 * frame goes through. Safe because nothing here can re-enter -- the
	 * only call out of this function is wpa_printf(). */
	static char line[256 + 2 * FUZZ_REACH_DUMP];
	static int inventory_done = 0;
	static unsigned int seq = 0;
	size_t off = 0, i, n, dump;

	if (!fuzz_reach_enabled())
		return;

	/* Announced from here rather than from an init hook, so that this file
	 * keeps its single entry point and a parser carrying a hook needs to
	 * know nothing else. */
	if (!inventory_done) {
		inventory_done = 1;
		fuzz_reach_report_inventory();
	}

	/*
	 * A walker cannot get through more than it was given, and one that
	 * reports that it did is a bug in the hook rather than a finding. It
	 * is clamped AND reported, because silently clamping would turn a
	 * miscounted hook into a run that looks perfect.
	 */
	n = got > len ? len : got;

	dump = len > FUZZ_REACH_DUMP ? FUZZ_REACH_DUMP : len;

	off = reach_add(line, sizeof(line), off,
			"{\"msg\":\"reach\",\"daemon\":\"%s\",\"parser\":\"%s\"",
			reach_daemon(), parser);
	off = reach_add(line, sizeof(line), off,
			",\"seq\":%u,\"n\":%u,\"got\":%u,\"whole\":%d",
			seq++, (unsigned int) len, (unsigned int) n,
			len && n == len ? 1 : 0);
	if (n != got)
		off = reach_add(line, sizeof(line), off, ",\"overrun\":%u",
				(unsigned int) got);
	if (dump != len)
		off = reach_add(line, sizeof(line), off, ",\"trunc\":%u",
				(unsigned int) dump);
	off = reach_add(line, sizeof(line), off, ",\"span\":\"");
	/* By hand rather than through reach_add(): this is the receive path,
	 * and 2,304 calls into vsnprintf() to print two characters each is a
	 * cost the thing being measured would feel. */
	for (i = 0; i < dump && off + 2 < sizeof(line); i++) {
		line[off++] = "0123456789abcdef"[buf[i] >> 4];
		line[off++] = "0123456789abcdef"[buf[i] & 0xf];
	}
	line[off] = '\0';
	off = reach_add(line, sizeof(line), off, "\"}");

	wpa_printf(MSG_INFO, "[fuzz] %s", line);
}
