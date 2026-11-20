# Make every `[fuzz] ` line machine-readable, and report an abandoned frame

The `[fuzz] ` prefix carries two kinds of line: JSON objects meant for a
program, and prose meant for a person. A consumer cannot tell them apart
without sniffing for `{`, and one of the prose lines reports an event the
consumer needs to *count* - so the one line with real semantics is the one
shape that cannot be parsed.

```
python3 fuzz_output_contract.py /path/to/checkout
```

Needs no radio, no interface and no root: it compiles a 15-line harness
against `src/common/fuzz.o` and drives the mutation hook directly. It exits
non-zero until the change lands. Measured against `258661420`.

## The gap, measured

The harness mutates an EAPOL-shaped frame twice with the log deferred and
never flushes it, which is what an error path between mutation and
transmission does:

```
$ FUZZ_DISABLE=notanumber FUZZ_START_EAPOL=100 ./harness
[fuzz] ignoring malformed FUZZ_DISABLE='notanumber'
[fuzz] resuming target 'eapol' at case 100
[fuzz] {"msg":"progress","case_id":100,"case_max":17152,"target":"eapol"}
[fuzz] previous frame was never sent, dropping its log
[fuzz] {"msg":"progress","case_id":101,"case_max":17152,"target":"eapol"}
```

Three of the five lines are prose. `json.loads()` on the text after the prefix
raises `Expecting value: line 1 column 1 (char 0)` for each, so a consumer
either reports three parse errors per occurrence or has to sniff the first
character to decide whether a line is for it.

Every emission site, at `258661420`:

| | line | shape |
| --- | --- | --- |
| `fuzz.c:95` | `ignoring malformed %s='%s'` | prose |
| `fuzz.c:207` | the deferred frame hexdump | JSON |
| `fuzz.c:251` | `previous frame was never sent, dropping its log` | prose |
| `fuzz.c:267` | `resuming target '%s' at case %d` | prose |
| `fuzz.c:308` | the progress report | JSON |
| `wpa_auth.c:5488` | `{"msg":"disconnect"}` | JSON |

## Why the abandoned frame is the one that matters

It is not a cosmetic parse failure there. Following the order in
`apply_mutation_int()`:

```
271  case_id is incremented
308  {"msg":"progress", ...}      emitted
340  {"msg":"fuzz", ...}          built
400  ...stashed in pending_log rather than emitted, when deferred
249  the NEXT call drops it, with a prose note
```

So an abandoned frame consumes a case, announces that case through
`progress`, never emits its `fuzz` line, and puts nothing on the air. A
consumer tracking delivery from `progress` - which is the only per-case
message that always arrives - counts a case that was never transmitted, and
**there is no machine-readable record of the abandonment with which to correct
the count.** In the transcript above, case 100 is announced and lost, and
nothing a parser can read says so.

The reachable abandonments are the two early returns between
`apply_mutation_defer_log()` and `fuzz_log_sent_frame()` in
`wpa_auth_send_eapol()`: `!sm->PTK_valid || !mic_len`, and
`wpa_eapol_key_mic() < 0`. Both are abnormal, so the over-count is plausibly
zero in a healthy run - but it errs toward claiming coverage that was not
delivered, which is the direction worth closing.

## What is asked for

**One rule: every line prefixed `[fuzz] ` is a JSON object with a `msg` key.**
That is what makes the prefix mean "this line is for the consumer", and it
needs no `{` sniffing at the far end. Unknown `msg` values are then ignorable
by construction, so a later addition breaks nobody.

1. **`fuzz.c:251` becomes a message, not a note**, carrying enough to correct
   the count and to replay what was lost:

   ```json
   {"msg":"abandoned","target":"eapol","case_id":100}
   ```

   `target` because each target keeps its own counter, so the correction has
   to be applied per target. `case_id` because it names the case that was
   lost, which is what makes it replayable through the existing
   `FUZZ_START_<TARGET>` path - and it is not currently recoverable, since
   `pending_log` holds the built JSON but not the id. That wants a companion
   static beside `pending_log`, set where it is set and cleared where it is
   cleared.

2. **`fuzz.c:95` and `fuzz.c:267` become messages too**, e.g.
   `{"msg":"bad_env","name":"FUZZ_DISABLE","value":"notanumber"}` and
   `{"msg":"resume","target":"eapol","case_id":100}`. Neither has a consumer
   today, so the shape is free to choose; what matters is that the prefix
   stops being ambiguous.

   The alternative is to drop the `[fuzz] ` prefix from these two and leave
   them as diagnostics, since a consumer reading the process's output sees
   every line anyway. That works, and it gives up something: `grep '\[fuzz\]'`
   over a log stops showing all fuzzing activity. Making them JSON keeps both
   properties, which is why it is the recommendation rather than the prefix
   removal.

Nothing else changes: `progress`, `fuzz` and `disconnect` keep their current
shapes, so an existing consumer keeps working and simply gains a message.

**Measured against a reference implementation**, so the shape above is known
to be reachable rather than only proposed - the same harness and environment
as the transcript further up:

```
[fuzz] {"msg":"bad_env","name":"FUZZ_DISABLE","value":"notanumber"}
[fuzz] {"msg":"resume","target":"eapol","case_id":100}
[fuzz] {"msg":"progress","case_id":100,"case_max":17152,"target":"eapol"}
[fuzz] {"msg":"abandoned","target":"eapol","case_id":100}
[fuzz] {"msg":"progress","case_id":101,"case_max":17152,"target":"eapol"}
```

Case 100 is announced, then reported lost, and the count is correctable. It
came to about 70 lines in `fuzz.c`: three small reporters over one shared
`json_start_object`/`json_end_object` helper, and two statics beside
`pending_log` holding the deferred frame's target and case id. The build is
unchanged - `json` and `base64` are already declared by `CONFIG_FUZZ` - and it
compiles warning-free.

## Acceptance

```
python3 fuzz_output_contract.py /path/to/checkout
```

Four checks, all against the harness's own output:

- every `[fuzz] ` line parses as JSON and carries a `msg`;
- the abandoned frame produces `msg` `abandoned`;
- that message names the `target` and the `case_id` that was lost, and the
  `case_id` is the one the preceding `progress` announced;
- `progress` and `fuzz` are unchanged in shape, so the change is additive.

The last one is the regression guard: it is what fails if the contract is
unified by renaming the messages a consumer already reads.

Verified to answer in both directions, which is the only thing that makes it
worth shipping: **1 of 3 against `258661420`**, naming the three prose lines
and the missing `abandoned` message, and **4 of 4** against the reference
implementation above.
