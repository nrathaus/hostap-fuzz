
#ifndef FUZZ_H
#define FUZZ_H

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

#endif
