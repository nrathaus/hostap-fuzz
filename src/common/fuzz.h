
#ifndef FUZZ_H
#define FUZZ_H

#ifdef CONFIG_FUZZ

/* False when FUZZ_DISABLE=1, so a fuzzing build can still be run as a normal
 * AP without rebuilding. Always false when built without CONFIG_FUZZ. */
int fuzz_enabled(void);

/* Mutate one byte of 'buf' and log both the mutation and the resulting frame. */
void apply_mutation(const char *target, int type, uint8_t *buf, size_t len);

/*
 * Same as apply_mutation(), but the frame hexdump is not emitted yet: the
 * caller must follow up with fuzz_log_sent_frame() once the frame is final.
 * Use this where the frame is integrity-protected after the mutation point
 * (EAPOL-Key MIC), so that the log shows the bytes actually transmitted.
 */
void apply_mutation_defer_log(const char *target, int type, uint8_t *buf,
			      size_t len);

/* Emit the frame hexdump held back by apply_mutation_defer_log(). Safe to call
 * when no mutation is pending; it is then a no-op. */
void fuzz_log_sent_frame(const uint8_t *buf, size_t len);

/* Read an integer tunable from the environment, or 'fallback' if unset. */
int fuzz_env_int(const char *name, int fallback);

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

static inline void apply_mutation(const char *target, int type, uint8_t *buf,
				  size_t len)
{
}

static inline void apply_mutation_defer_log(const char *target, int type,
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

#endif /* CONFIG_FUZZ */

#endif
