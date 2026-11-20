# Hold a fuzzing target unmutated, so the stages behind it stay reachable

With the fuzzing hooks compiled in, mutating an early-stage frame stops a
station ever reaching the later stages, so most of the declared case space is
unreachable. There is no way to say "fuzz this target, answer that one
honestly", which is the control the problem needs.

```
python3 phase_starvation.py            # static: reports the gap, exits non-zero
sudo python3 phase_starvation.py --live <path-to-hostapd>
```

The live mode needs no radio and no second machine: it brings up two
`mac80211_hwsim` interfaces, runs the build under test on one and
`wpa_supplicant` with SAE on the other, and reports which targets advanced.

## The gap, measured

`hostapd v2.12-devel-fuzz`, WPA3-SAE (`wpa_key_mgmt=SAE`, `ieee80211w=2`,
`sae_pwe=2`), one ESP32-C6 station, about ten minutes:

| target | case_max | highest case reached |
| --- | --- | --- |
| `probe_resp` | 22,244 | 105 |
| `sae-send-commit` | 27,872 | 26 |
| `eapol` | 50,116 | **8** |
| `sae-send-confirm` | 10,720 | **never left the warm-up range** |
| `assoc_resp` | 9,380 | **never left the warm-up range** |

**70,216 of 120,332 cases, 58% of the declared space, cannot be reached at
all.** Over the same period the station logged 1,423 disconnections against 19
associations, reporting `NO_AP_W_COMPATIBLE_SECURITY` continuously: a mutated
probe response breaks security negotiation, so the station rescans instead of
proceeding to SAE. `eapol` needs a station that completed the four-way
handshake and `sae-send-confirm` needs one that got past commit, so neither can
advance while `probe_resp` is being mutated.

This is not a pacing problem. Every case is delivered as a REPLY to a station
action, so the rate is the station's retry cadence - about 2.6s per attempt -
and the deeper targets are not slow, they are unreachable.

## Why `FUZZ_START_<TARGET>` does not solve it

It is a resume offset rather than a hold, and using it as a skip has two
consequences:

- **the frame stops being sent as a fuzz case at all**, rather than being sent
  correctly. What the later stages need is a WELL-FORMED probe response, not
  the absence of one.
- **the target announces once and then goes quiet.** Parking `probe_resp` at
  22,244 produced exactly one progress message, `case_id` equal to `case_max`,
  and nothing further. A consumer that computes completion by summing
  `case_max - case_id` over the targets it has heard from concludes the run is
  finished - and since a target only announces when it is first exercised, the
  targets behind it never get to announce themselves. The session ended within
  seconds of the interface coming up.

## The ask

**`FUZZ_HOLD_<TARGET>=1`**: the target's frames are transmitted UNMUTATED, and
the target still emits its progress message so a consumer can see it is
deliberately held rather than missing.

Naming follows the existing `FUZZ_START_<TARGET>` convention - the target name
uppercased with `-` as `_`, so `FUZZ_HOLD_PROBE_RESP`,
`FUZZ_HOLD_SAE_SEND_COMMIT`.

Emitting the progress message while held is the half that is easy to leave out
and the half that makes it usable: a held target and an absent one must not
look the same from the outside.

**Why this shape.** It is the phasing primitive. Fuzz the latest stage while
every earlier stage is answered correctly, then work backwards:

```
FUZZ_HOLD_PROBE_RESP=1 FUZZ_HOLD_SAE_SEND_COMMIT=1 \
FUZZ_HOLD_SAE_SEND_CONFIRM=1 FUZZ_HOLD_ASSOC_RESP=1   # -> eapol reachable
FUZZ_HOLD_PROBE_RESP=1 FUZZ_HOLD_SAE_SEND_COMMIT=1    # -> sae-send-confirm
FUZZ_HOLD_PROBE_RESP=1                                # -> sae-send-commit
```

A `FUZZ_ONLY=<comma-separated>` spelling would express the same thing more
briefly and is equally acceptable; the requirement is that everything not
selected is answered CORRECTLY rather than skipped.

## Acceptance

With `FUZZ_HOLD_PROBE_RESP=1` and an SAE station:

- the station associates and completes the four-way handshake repeatedly,
  rather than looping on a security mismatch;
- `sae-send-commit` advances past 100 cases within a few minutes;
- `probe_resp` still emits a progress message, so it is visibly held;
- with no `FUZZ_HOLD_*` set, behaviour is unchanged.

`phase_starvation.py --live` checks all four.

## Two smaller things found alongside

**The `[fuzz] ` prefix carries both JSON and prose.** A consumer parsing each
`[fuzz] ` line as JSON hits:

```
[fuzz] resuming target 'probe_resp' at case 22244
```

Either wrap it - `{"msg":"info","text":"resuming target ..."}` - or use a
different prefix for human-readable lines. The mixed form makes every consumer
carry a try/except that silently swallows real parse failures too.

**`case_id` starts negative and climbs to zero.** The first progress message
for every target reports `case_id: -9`, rising through `-8`, `-7` and so on
before the first real case. Nothing says what the negative range means, so a
consumer cannot distinguish a warm-up from a case that has run, and the obvious
handling - clamping to zero - reports several cases as complete before any has
been sent. Documenting it is enough; a distinct `"msg"` would be better.
