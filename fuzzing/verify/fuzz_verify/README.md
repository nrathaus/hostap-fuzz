# Behavioural checks for the mutation hook

```sh
python3 fuzz_verify.py /path/to/checkout
```

Needs no radio, no interface and no root: it compiles two small harnesses
against the checkout's own `fuzz.o` and drives `apply_mutation()` directly. The
checkout must be built with `CONFIG_FUZZ=y` first, since the harnesses link the
objects the build produces:

```sh
cd hostapd && cp defconfig-fuzz .config && make
```

42 checks, four groups:

| group | what it pins down |
| --- | --- |
| the sweep | 2550 cases for a 34-byte frame, zero duplicate `(offset, mask)`, 255 per offset, each offset getting the XOR masks 1..255 exactly once and so leaving the byte at all 255 other values with none repeated and none unchanged, the interesting values still leading every offset and the 8 single-bit flips still within its first 13 cases, the whole 24-byte header skipped, 9 warm-up frames, locking at `case_max`, and `state` partitioning the range into `warmup`/`mutating`/`done` |
| `FUZZ_HOLD_<TARGET>` | held frames byte-identical to the frame as built, `progress` still emitted with `"state":"held"`, no case consumed, no `fuzz` message, per-target rather than global, `…=0` is not a hold, parking at a `FUZZ_START_` point, and the name-folding rule over all 12 reachable targets |
| abandoned frames | two abandonments then a delivery, each naming its own `target` and `case_id`, and a flushed frame never reported as abandoned |
| `FUZZ_DISABLE` | `=1` emits nothing and mutates nothing; a malformed value is reported as `bad_env` and then *ignored*, rather than silently disabling fuzzing |

Every group also asserts the output contract over its own transcript: each
`[fuzz] ` line parses as a JSON object with a `msg`.

## Why this exists beside the other two

`../fuzz_output_contract/` and `../fuzz_target_phasing/` each check that their
own ask landed. This one covers what those do not: that the sweep is *unchanged*
by the work — the regression guard — and that the hold and the states behave
across the cases a consumer will actually meet. Run all three after touching
`src/common/fuzz.c`.

The one thing none of them can check is whether holding an early stage makes a
real station reach a later one. That is a property of the exchange rather than
of the binary; `../fuzz_target_phasing/phase_starvation.py --live` is the check
for it, and it needs root (two `mac80211_hwsim` radios, no hardware).

## Verified to answer in both directions

A check that cannot fail is not worth running. Measured against two deliberate
regressions, each reverted afterwards:

| regression | result |
| --- | --- |
| `fuzz_hold_target()` returns 0, ignoring the environment | **31 of 38**, naming the six hold behaviours and the name-folding check |
| the abandoned case goes back to being a prose note | **36 of 38**, naming the ordering check and the contract check |
| unmodified | **38 of 38** |
