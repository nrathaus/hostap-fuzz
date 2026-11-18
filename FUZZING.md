# WPA3/SAE frame fuzzing for hostapd

This branch adds a mutation hook to hostapd's frame transmit paths. hostapd runs as a
normal WPA3-SAE access point, but flips one byte of each outgoing frame according to a
deterministic sweep, so a client (or the kernel driver behind it) is fed malformed
management and EAPOL frames. `monitor_fuzzing.py` runs hostapd, decodes what it mutated,
and records the case in flight if hostapd dies.

Deterministic is the point: every case has an integer id, and re-running with that id
reproduces the exact same mutation.

Two things make it usable from a program rather than by reading a log: every `[fuzz] `
line is a JSON object with a `msg` key, and any target can be **held** — answered
correctly — so the stages behind it stay reachable. If you are returning to this document,
[What changed most recently](#what-changed-most-recently) is the delta.

This tree tracks hostap upstream directly. It was moved onto `320eb1e09a` (2026-11-18)
after the fork it grew on had fallen 2127 commits behind. The history before that point
lives on another branch, so read [Upstream lineage](#upstream-lineage) before trying to
make sense of `git log`.

---

## Build

```sh
cd hostapd
cp defconfig-fuzz .config      # or add CONFIG_FUZZ=y to your own .config
make
```

> **Upstream 320eb1e09a does not build with its own `defconfig`.** `he_oper_chwidth`
> and `eht_oper_chwidth` are declared under `CONFIG_IEEE80211AX` / `CONFIG_IEEE80211BE`
> in `src/ap/ap_config.h` but used unguarded in `src/ap/ctrl_iface_ap.c` and
> `hostapd/ctrl_iface.c`; without `CONFIG_IEEE80211AC` the link then fails because
> `ieee80211_ml_build_assoc_resp()` calls `hostapd_eid_vht_capabilities()`.
> `defconfig-fuzz` therefore forces AC + AX + BE. This is an upstream bug, not a
> property of the harness — a stock `cp defconfig .config && make` fails the same way.
> Drop the forced options once it is fixed upstream.

`CONFIG_FUZZ=y` is **required**. Without it every hook compiles away and you get a stock
AP that fuzzes nothing — silently. Check which one you built:

```sh
./hostapd -v          # "hostapd v2.13-devel-fuzz" => hooks compiled in
```

Worth asserting in CI or a Dockerfile, since the failure mode is silence:

```sh
./hostapd/hostapd -v 2>&1 | grep -q -- -fuzz || { echo "NOT a fuzzing build"; exit 1; }
```

Build with ASan. The whole point is catching memory errors, and without it you only see
the ones that happen to segfault on their own:

```sh
make clean
make CFLAGS="-fsanitize=address -fno-omit-frame-pointer -g -O1" LDFLAGS="-fsanitize=address"
```

`fuzz.c` needs `json.o` and `base64.o`; `CONFIG_FUZZ` declares `NEED_JSON` and
`NEED_BASE64` for you. `wpa_supplicant` also compiles `src/ap`, so it picks up `fuzz.o`
under `CONFIG_AP` — it links with or without `CONFIG_FUZZ`.

## Run

Set `interface=` in `hostapd/hostapd-wpa3.conf` first; it ships as `wlan0`, a placeholder.

```sh
./monitor_fuzzing.py                                   # defaults below
./monitor_fuzzing.py --config hostapd/my.conf --quiet
```

| flag | meaning |
| --- | --- |
| `--hostapd` | binary, default `./hostapd/hostapd` |
| `--config` | config file, default `hostapd/hostapd-wpa3.conf` |
| `--repro-dir` | where crashing cases are recorded, default `fuzz-repro/` |
| `--quiet` | show only fuzzing activity, not all hostapd output |

Exit codes: `0` clean, `1` hostapd died, `2` bad invocation, `130` interrupted.

The monitor passes its environment through to hostapd, so the tunables below go on the
same command line: `FUZZ_HOLD_PROBE_RESP=1 ./monitor_fuzzing.py`.

scapy is optional. With it, each mutated frame is dissected and printed; without it you get
raw hex and one warning. Crash detection does not depend on it.

scapy lives in a project-local venv rather than being installed system-wide, so run the
monitor with that interpreter:

```sh
claude/venv/bin/python3 monitor_fuzzing.py            # dissected frames
python3 -m venv claude/venv && claude/venv/bin/pip install scapy   # to recreate it
```

`claude/live_run/run_live.sh` prefers that interpreter automatically, which matters under
`sudo` — root's bare `python3` would not see it and every frame would come back as raw hex.

## Tunables

All environment variables — there is no `hostapd.conf` option, because `apply_mutation()`
has no `hapd` pointer at its call sites.

| variable | default | meaning |
| --- | --- | --- |
| `FUZZ_DISABLE=1` | off | Run a fuzzing build as a stock AP. Use this to prove a failure comes from the mutation and not the configuration. |
| `FUZZ_DISCONNECT_MS` | `1000` | Delay before forcing the STA off so the next frame gets the next case. **`0` leaves the STA connected**, which is what you need to fuzz anything past the 4-way handshake (group rekey, data path). |
| `FUZZ_START_CASE` | `0` | Resume every target at this case, skipping the warm-up. |
| `FUZZ_START_<TARGET>` | — | Resume one target. Takes precedence over `FUZZ_START_CASE`. |
| `FUZZ_HOLD_<TARGET>=1` | off | Answer one target **correctly**: its frames go out unmutated and it consumes no cases. This is how you reach a later stage — see [Phasing](#phasing). |
| `FUZZ_SWEEP_DEPTH_FIRST=1` | off | Sweep every mutation at one byte offset before moving to the next, instead of the breadth-first default. Use it to localise a crash you have already seen — see [How the sweep works](#how-the-sweep-works). |

Target names fold into variable names by uppercasing and replacing every non-alphanumeric
character with `_`, so `auth-sae` is `FUZZ_START_AUTH_SAE` or `FUZZ_HOLD_AUTH_SAE`. The
monitor prints the exact variable to use, so you never have to derive one by hand.

`FUZZ_HOLD_<TARGET>` and `FUZZ_START_<TARGET>` are independent: hold a target at a resume
point and it parks there, reporting that case rather than the warm-up.

A hold is resolved once per target, when the target is first exercised, so it is a property
of the run — there is no way to lift it under a station mid-exchange, which is deliberate.
Since a held target consumes no cases, the next run without the hold sweeps its case space
from the start rather than from wherever the held run left off.

## Targets

| target | where | frame |
| --- | --- | --- |
| `probe_resp` | `src/ap/beacon.c` | probe response |
| `assoc_resp` | `src/ap/ieee802_11.c` | association response |
| `deauth` | `src/ap/ieee802_11.c` | deauthentication |
| `eapol` | `src/ap/wpa_auth.c` | EAPOL-Key |
| `auth-sae`, `sae-send-commit`, `sae-send-confirm`, `handle-auth`, `auth-ft-finish`, … | `src/ap/ieee802_11.c` | authentication; the name is the caller's own debug label, so SAE commit and confirm sweep independently |

Each target keeps its own case counter, so a slow-moving target is not starved by a busy
one.

## Phasing

Separate counters are not enough, because the targets are **stages of one exchange**.
Whichever stage first breaks the exchange starves every stage behind it: the station never
gets far enough for those frames to be sent, so their case space is unreachable no matter
how long the run goes.

Measured over ten-minute runs against two unrelated stations (full data in
`claude/live_run/RESULTS.md`). A MikroTik hAP ax² in station mode, RouterOS 7, on
2026-11-18:

| | nothing held | all four earlier stages held |
| --- | --- | --- |
| `probe_resp` | 300 of 44,220 | held |
| `sae-send-commit` | 266 of 27,872 | held |
| `sae-send-confirm` | warm-up only | held |
| `assoc_resp` | warm-up only | held |
| **`eapol`** | **13** | **596** |
| four-way handshakes | 7 | **92** |
| associations | 7 | **174** |

An ESP32-C6 on 2026-09-05, which additionally measured `probe_resp` held on its own:

| | nothing held | `probe_resp` held | all four earlier stages held |
| --- | --- | --- | --- |
| `sae-send-commit` | 40 of 27,872 | 40 of 27,872 | held |
| `sae-send-confirm` | warm-up only | warm-up only | held |
| `assoc_resp` | warm-up only | warm-up only | held |
| **`eapol`** | **8** (warm-up only) | **8** (warm-up only) | **66 of 50,116** |
| EAPOL frames mutated | 0 | 0 | **67** |
| four-way handshakes | 9 | 9 | **38** |

`FUZZ_HOLD_<TARGET>=1` is the fix, and the last column of each is it working: a target that
had barely been reached took 596 mutations (46x) on one station and 67 on the other once
the stages ahead of it were answered correctly, with the station completing the handshake
throughout. A held target transmits
the frame **as built**. Fuzz the latest stage first and work backwards:

```sh
# eapol reachable: every earlier stage answered correctly
FUZZ_HOLD_PROBE_RESP=1 FUZZ_HOLD_SAE_SEND_COMMIT=1 \
FUZZ_HOLD_SAE_SEND_CONFIRM=1 FUZZ_HOLD_ASSOC_RESP=1 ./monitor_fuzzing.py

FUZZ_HOLD_PROBE_RESP=1 FUZZ_HOLD_SAE_SEND_COMMIT=1 ./monitor_fuzzing.py  # sae-send-confirm
FUZZ_HOLD_PROBE_RESP=1 ./monitor_fuzzing.py                              # sae-send-commit
```

Two properties make it usable rather than merely present:

- **A held target still announces itself** through `progress`, with `"state":"held"`. A
  held target and a missing one must not look the same from the outside.
- **A held target consumes no cases.** Its counter does not move, so its case space is
  still there for a run that fuzzes it, rather than having been skipped.

`FUZZ_START_<TARGET>` parked at `case_max` is **not** a substitute. It removes the mutation
by *skipping the case*, not by sending a well-formed reply, and a target parked that way
announces once and then goes quiet — a consumer that sums `case_max - case_id` over the
targets it has heard from then concludes the run is finished.

**Which stage blocks is station-specific — measure, do not assume.** The ESP32's middle
column is the caution: holding `probe_resp` alone changed nothing, because on that station
probe-response mutation was harmless. The sweep is depth-first, so in ten minutes it never
got past byte offset 0, and offset 0 of a probe response is the timestamp.

Both stations then blocked at the same place, `sae-send-commit`, whose offset 0 breaks
authentication outright. Every handshake in either control phase happened during that
target's warm-up, and associations stopped once it began mutating — on the ax² the
counter still climbed to 266, because the station kept retrying authentication and each
retry drew another mutated reply, while not one of those attempts reached association.
**A target's counter advancing does not mean the exchange behind it is reachable.** Read
the `state` field per target, and read it against the handshake count.

### Throughput is the binding constraint

Every case is delivered as a reply to a station action, so the ceiling is the station's
reconnect cadence, and that cadence varies by an order of magnitude between stations:
**6.7** `eapol` cases a minute on the ESP32-C6, **59.6** on the hAP ax². Sweeping
`eapol` outright is therefore 125 hours on the first and about 9 on the second. Pick the
station with that in mind; it costs nothing and buys a factor of nine. The sweep is
exhaustive by design, so against a slow station plan on choosing offsets deliberately with
`FUZZ_START_<TARGET>` rather than expecting a target to be swept.

This is why the sweep is [breadth-first by default](#order-breadth-first-by-default). A run
that cannot finish should at least have touched every byte of the frame; depth-first, a
ten-minute run touches three.

## Output

**Every line prefixed `[fuzz] ` is a JSON object with a `msg` key.** That is the contract:
the prefix means "this line is for the consumer", so nothing has to sniff for `{`, and a
`msg` a consumer does not recognise is ignorable by construction — a message added later
breaks nobody. A `[fuzz] ` line that does not parse is therefore a real fault, and the
monitor reports it instead of silently swallowing it.

Two lines per mutated frame:

```
[fuzz] {"msg":"progress","case_id":1234,"case_max":2680,"target":"auth-sae","state":"mutating"}
[fuzz] {"msg":"fuzz","target":"auth-sae","idx":4,"type":"MUT_BYTE_XOR","mask":150,
        "before":0,"after":150,"data":"b0003a01..."}
```

`idx` is the offset **within the fuzzable region**, not the frame — add the skipped header
to get a frame offset. `data` is the whole frame, headers included, as transmitted.

| `msg` | when | fields |
| --- | --- | --- |
| `progress` | once per frame, per target, always | `case_id`, `case_max`, `target`, `state`, `order` |
| `fuzz` | the mutation that was applied | `target`, `order`, `idx`, `type`, the kind's parameter, `before`, `after`, `data` |
| `abandoned` | a case was announced but its frame was never sent | `target`, `case_id` |
| `resume` | a target started at `FUZZ_START_…` rather than the warm-up | `target`, `case_id` |
| `bad_env` | a `FUZZ_*` value was not an integer and was ignored | `name`, `value` |
| `disconnect` | the forced disconnect fired (`src/ap/wpa_auth.c`) | — |

`state` says what the target did with the case it just announced, because `case_id` alone
does not:

| `state` | meaning |
| --- | --- |
| `warmup` | `case_id < 0`: an unmutated frame, so a client can associate before anything is corrupted. Nine of these per target. |
| `mutating` | the case ran; a `fuzz` message follows |
| `held` | `FUZZ_HOLD_<TARGET>` is set: unmutated on purpose, and no case consumed |
| `done` | the sweep reached `case_max` and stopped, reporting a constant `case_id` |

### The abandoned case

`progress` is the only per-case message that always arrives, so a consumer counts delivery
from it. That over-counts by itself: a frame can be mutated and then dropped on an error
path before transmission (`!sm->PTK_valid || !mic_len`, or a `wpa_eapol_key_mic()` failure
in `wpa_auth_send_eapol()`), which consumes a case, announces it, and puts nothing on the
air.

`{"msg":"abandoned","target":"eapol","case_id":100}` is the correction. `target` because
each target counts separately, and `case_id` so the lost case can be replayed through
`FUZZ_START_EAPOL=100`. Both error paths are abnormal, so in a healthy run the count is
plausibly zero — but the error was in the direction of claiming coverage that was never
delivered, which is the direction worth closing. The monitor reports the count per target:

```
Last case per target:
  eapol: case 100 of 17152 (1 announced but never sent)
  probe_resp: case 0 of 48252 [held]
```

## Reproducing a crash

On an abnormal exit the monitor prints the in-flight case and a ready-to-run replay
command, and writes a record to `--repro-dir`:

```json
{
  "exit": "killed by signal 11 (SIGSEGV)",
  "returncode": -11,
  "replay_env": { "FUZZ_START_AUTH_SAE": 1235 },
  "case": { "msg": "fuzz", "target": "auth-sae", "idx": 4, ... }
}
```

Then `FUZZ_START_AUTH_SAE=1235 ./monitor_fuzzing.py` re-runs that exact mutation on the
first frame of that target.

---

## How the sweep works

For a fuzzable region of `L` bytes:

```
268 = 5 interesting values + 8 bit flips + 255 XOR masks
case_max = L * 268
```

`case_id` maps onto `(offset, kind, param)` exactly once: no duplicates, and no kind is
cut short by another's range. XOR masks run 1..255 rather than 0..255 because mask 0 is a
no-op. The first 9 frames per target are left unmutated as a warm-up (`case_id` counts up
from -9), so a client can associate before anything is corrupted. Once `case_id` reaches
`case_max` that target stops mutating and reports a constant `case_id`.

### Order: breadth-first by default

**Breadth-first** applies one mutation at every byte offset before trying the next
mutation anywhere. **Depth-first** (`FUZZ_SWEEP_DEPTH_FIRST=1`) runs all 268 mutations at
offset 0, then all 268 at offset 1.

Depth-first localises a crash to one field, which is what you want *after* a crash. It is
the wrong default, because every run against a real station is bounded by the station's
re-join rate rather than by `case_max`:

| cases delivered | offsets reached, depth-first | offsets reached, breadth-first |
| ---: | --- | --- |
| 105 | **1** | all |
| 596 | **3** | all, 4.9 times over |

Those are not estimates. A ten-minute live run delivered 596 `eapol` cases and reached
three byte offsets — EAPOL version, type, and the high byte of the body length. 268 of
those cases said "this frame is not an EAPOL-Key", which a supplicant is required to
reject. The key data, the nonce and the RSN IE begin at offset 11 and were never reached.
Full data in `claude/sweep_ordering/README.md`.

Because `rem` advances slowest under breadth-first, the five interesting values are still
what every offset sees first.

**The orders renumber every case**, so a `case_id` recorded under one does not replay
under the other. Both `progress` and `fuzz` carry an `order` field (`"breadth"` or
`"depth"`) for exactly that reason, and `monitor_fuzzing.py` writes
`FUZZ_SWEEP_DEPTH_FIRST` into a repro record's `replay_env` when it applies.

## Three design decisions worth knowing

**The whole 802.11 header is skipped** (`IEEE80211_HDRLEN`, 24 bytes), not just the address
fields. Mutating `bssid` or `seq_ctrl` just gets the frame dropped by the peer before
anything parses it, which burns cases without testing anything.

**EAPOL frames are mutated before the MIC is computed**, so hostapd MICs the mutated frame
and the supplicant actually parses it. Mutating afterwards means the supplicant rejects it
on MIC failure having parsed nothing. A consequence: because key data is AES-wrapped before
that point, mutations land on *encrypted* key data, and the supplicant decrypts it to
garbage and parses that — which is the deep path.

Since the frame changes after the mutation, the hexdump is deferred:
`apply_mutation_defer_log()` holds it and `fuzz_log_sent_frame()` emits it once the frame
is final, so the log shows the bytes actually transmitted. If a frame is abandoned between
the two (a MIC error path), the stale log is dropped and the lost case is reported as
`{"msg":"abandoned",…}` rather than being attached to the next frame.

**The forced disconnect runs from the event loop**, not a sleep inside `SM_STEP`. A sleep
there stalls every other STA and every timer in the process, and caps throughput at one
handshake per second. The timeout is cancelled in `wpa_auth_sta_deinit()` with the other
per-sm timeouts, so a freed state machine cannot be reached through a pending callback.

## Prior art in hostap you may want instead

hostap already ships fault injection, maintained upstream and immune to rebase rot:
`ext_mgmt_frame_handling=1` routes management frames through the control interface for
external handling, `ext_eapol_frame_io` does the same for EAPOL, and `sae_commit_override`
substitutes SAE commit contents outright. Together they allow full frame mutation from
Python with no C changes. The in-process hook here exists for throughput and for paths
those knobs do not cover; `CONFIG_FUZZ` keeps the two approaches independent.

---

## State of verification

> **Re-verified on the current base, 2026-11-18.** The behavioural claims below were
> first established against the pre-move tree (`archive/sae-fuzzing-old`, tip `88cf1848f`).
> The hooks have since been re-applied onto hostap `320eb1e09a`, across 2127 upstream
> commits that reworked `src/ap/wpa_auth.c` by ~944 lines and `src/ap/ieee802_11.c` by
> ~4591. The live run was repeated on this branch against a second, unrelated station --
> see [Verified against a real station](#verified-against-a-real-station). The one claim
> most at risk, `FUZZ_DISCONNECT_MS` firing at `PTKINITDONE`, came through: 92 disconnects
> against 92 completed handshakes.

Everything below is verified by build, static inspection, ASan/UBSan unit harnesses, and
two live runs against real WPA3-SAE stations.
The behavioural half is re-runnable — no radio, no root — and should be run after any change
to `src/common/fuzz.c`:

```sh
python3 claude/fuzz_verify/fuzz_verify.py .                    # 38 checks: sweep, hold, contract
python3 claude/fuzz_output_contract/fuzz_output_contract.py .  # 4 checks: the output contract
python3 claude/fuzz_target_phasing/phase_starvation.py ./hostapd/hostapd
python3 claude/sweep_ordering/verify_ordering.py .             # 19 checks: sweep order
```


- 2680 cases for a 34-byte frame = 10 offsets x 268, **zero duplicates**, each offset
  getting exactly 5/8/255, masks 1..255, lowest mutated byte 24, locking at `case_max`.
- Sweep order: breadth-first is the default and the first 10 cases of a 10-offset frame
  touch all 10 offsets, each applying `0x00`; a budget of 105 reaches every offset where
  depth-first reaches one; `FUZZ_SWEEP_DEPTH_FIRST=1` puts the first 268 cases at offset 0
  and `=0` does not; both orders sweep exactly 2680 cases with no duplicates and cover the
  **identical** case space in a different sequence; `order` is reported on every `progress`
  and `fuzz` message; and case 300 is a different mutation under each order but replays
  identically within one.
- 60000 mutations of a 900-byte frame with no abort (frames over ~435 bytes used to abort
  hostapd inside the logging itself).
- `len <= header_size` leaves the buffer byte-identical; one dict entry per target after
  60000 calls.
- Deferred logging shows post-mutation bytes; an abandoned frame drops its stale log and
  reports the lost case as `abandoned`.
- `FUZZ_START_CASE=1234` replays byte-identically; C and Python env-name mappings agree on
  all 10 reachable target names.
- The monitor was driven end-to-end against a stub through clean exit, SIGABRT, SIGSEGV,
  non-zero status, and missing binary/config.
- All five build combinations link: hostapd ±`CONFIG_FUZZ`, wpa_supplicant with
  `CONFIG_AP` ±`CONFIG_FUZZ`, and `CONFIG_FUZZ` without `CONFIG_AP`. A non-fuzz binary
  contains zero fuzz symbols and no `FUZZ_HOLD`. It does carry two strings,
  `FUZZ_TYPE_IEEE80211_MGMT` and `FUZZ_TYPE_IEEE802_1X_HDR`: `enum fuzz_frame_type`
  has to stay outside the `#ifdef CONFIG_FUZZ` in `fuzz.h` or the call sites would
  not compile, so the names reach `.debug_str`. They are debug info only and `strip`
  removes them; nothing is emitted at runtime.
- The output contract: 20000-iteration sweeps under ASan+UBSan+LSan (plain, deferred, held,
  `FUZZ_DISABLE=1`, `len == 0`, `len == header`) are sanitizer-clean, and **every** emitted
  `[fuzz] ` line across them parses as JSON with a `msg`. Two abandonments in a row each
  name their own case (`abandoned` 100, `abandoned` 101, then a delivered 102).
- `FUZZ_HOLD_<TARGET>`: 5000 held frames are byte-identical to the frame as built, all
  5000 announce `progress` with `"state":"held"`, `case_id` never moves off `-9`, and no
  `fuzz` message is emitted. Holding one target leaves another sweeping; `…=0` is not a
  hold; with nothing held, behaviour is byte-identical to before the change (2680 cases for
  a 34-byte frame, zero duplicates, 268 per offset, 5/8/255 per kind, masks 1..255, lowest
  mutated byte 24, locking at `case_max`). A target held at `FUZZ_START_EAPOL=500` parks at
  500 rather than at the warm-up. C and Python agree on the `FUZZ_HOLD_` spelling for all
  12 target names.
- The monitor was driven against a stub emitting the full contract: it warns on `bad_env`,
  warns on a genuinely unparsable line, ignores an unknown `msg`, counts the abandonment,
  marks the held target, and still writes the same replay record.
- The scapy dissection branch: a mutated probe response dissects to
  `Dot11/Dot11ProbeResp/SSID/rates` and an EAPOL-Key frame to `EAPOL/EAPOL-Key`, under the
  venv interpreter above.

### Verified against a real station

Run twice, against two unrelated WPA3-SAE stations; full data in
`claude/live_run/RESULTS.md`, reproduce with `claude/live_run/run_live.sh`.

**2026-11-18, on this branch** (`102638c2f`), against a MikroTik hAP ax² in station
mode (RouterOS 7), three phases:

- **Sanity, `FUZZ_DISABLE=1`**: the station associates and completes the four-way handshake
  against a `CONFIG_FUZZ` build with the hooks off, and the logs contain **zero** `[fuzz] `
  lines. Configuration is therefore not what any later phase is measuring.
- **The phasing primitive works on the rebased hooks**: `eapol` went from 13 cases to
  **596**, and handshakes from 7 to **92**, when the four stages ahead of it were held. All
  four reported `"state":"held"` on every frame and consumed no cases.
- **`FUZZ_DISCONNECT_MS` survived the `wpa_auth.c` rework**: 92 disconnects against 92
  completed handshakes, exactly 1:1.
- **EAPOL mutation still precedes MIC computation**: msg-3 dumps carry a valid MIC over the
  already-mutated body, so the station parses the frame instead of dropping it.
- **The output contract holds against real traffic**: **3,537 `[fuzz] ` lines** across the
  three retained logs, every one a JSON object with a `msg`, zero parse failures.
- **Observed, not yet explained**: 174 associations produced only 92 completed handshakes.
  `eapol` was the only mutating target, so roughly half of the attempts were broken by
  EAPOL-Key mutation at byte offset 0 — the EAPOL version field. No crash, no hang.

**2026-09-05**, against an ESP32-C6, four phases, on the pre-move tree:

- **The phasing primitive works end to end.** Holding the four stages ahead of `eapol` took
  it from 8 (warm-up only, never a single mutation) to 66 cases and 67 mutated frames, with
  38 four-way handshakes against 9.
- **The output contract holds against real traffic**: **1,090 `[fuzz] ` lines** in the
  retained logs, every one a JSON object with a `msg`, zero parse failures — re-checkable
  from `claude/live_run/logs/`. A further 364 lines were checked at the time in a run whose
  log was later overwritten. This is the one claim no offline harness can make.
- **A held target on live frames** announced itself on every frame, consumed no cases, and
  emitted no `fuzz` message.
- **The forced disconnect cycles a real client**: 38 disconnects against 38 handshakes and
  38 re-associations. It had never driven one before.
- **The SAE paths end to end**, including `FUZZ_DISABLE=1` as the configuration-vs-mutation
  control: the station associates and completes the handshake against a `CONFIG_FUZZ` build
  with the hooks off.

Still unexercised:

- the group rekey and data path (`FUZZ_DISCONNECT_MS=0`), which is where a station that
  stays connected would take the sweep
- any target past byte offset 2 **on hardware**. The breadth-first default is verified
  offline (19 checks, `claude/sweep_ordering/verify_ordering.py`) but has not yet had a
  live run; the measured numbers above all predate it.
- `interface=wlan0` in `hostapd-wpa3.conf` is a placeholder. On a machine where `wlan0` is
  the uplink, it is a dangerous one — `claude/live_run/run_live.sh` generates its own config
  rather than using it, refuses any interface holding the default route or an association,
  and refuses a built-in radio outright.

**Running it live:** `claude/live_run/run_live.sh` does the whole sequence — sanity
(`FUZZ_DISABLE=1`, so a failure here is configuration, not mutation), then a control with
nothing held, then a held phase — and prints a per-target table after each. It picks an
external AP-capable adapter, never a built-in radio, and hands the interface back to
NetworkManager on exit.

```sh
sudo ./claude/live_run/run_live.sh --ssid <what your station seeks> --password <its psk> \
     --phase held --hold probe_resp,sae-send-commit,sae-send-confirm,assoc_resp
```

Moving the AP to the station's SSID is usually easier than reflashing the station.

## What changed most recently

Two changes, both about a program being able to act on what the hooks report. Neither
touches a mutation: with no `FUZZ_HOLD_*` set, the sweep is byte-identical to before.

### Every `[fuzz] ` line is JSON

The prefix used to carry both JSON records and prose meant for a person, so a consumer
could not tell them apart without sniffing for `{` — and the one prose line with real
semantics was the one it needed to *count*:

```
[fuzz] ignoring malformed FUZZ_DISABLE='notanumber'
[fuzz] resuming target 'eapol' at case 100
[fuzz] {"msg":"progress","case_id":100,"case_max":17152,"target":"eapol"}
[fuzz] previous frame was never sent, dropping its log
[fuzz] {"msg":"progress","case_id":101,"case_max":17152,"target":"eapol"}
```

Three of those five lines raise `Expecting value: line 1 column 1` from `json.loads()`. Now
every line is an object with a `msg`, and the lost case is named rather than noted:

```
[fuzz] {"msg":"bad_env","name":"FUZZ_DISABLE","value":"notanumber"}
[fuzz] {"msg":"resume","target":"eapol","case_id":100}
[fuzz] {"msg":"progress","case_id":100,"case_max":17152,"target":"eapol","state":"mutating"}
[fuzz] {"msg":"abandoned","target":"eapol","case_id":100}
[fuzz] {"msg":"progress","case_id":101,"case_max":17152,"target":"eapol","state":"mutating"}
```

Case 100 is announced, then reported lost, so a delivery count taken from `progress` can be
corrected and the case can be replayed — see [The abandoned case](#the-abandoned-case).
In `fuzz.c` this is three small reporters over one shared
`fuzz_report_start()`/`fuzz_report_end()` envelope, which `progress` and `fuzz` now use too,
plus two statics beside `pending_log` holding the deferred frame's target and case id.

### A target can be held unmutated

`FUZZ_HOLD_<TARGET>=1` transmits that target's frames as built. Before it there was no way
to say "fuzz this stage, answer that one honestly", and 58% of the declared case space was
unreachable behind a mutated probe response — see [Phasing](#phasing) for the measurement
and the working recipe. `progress` gained a `state` alongside it, so a held target does not
look like a missing one, and a warm-up frame does not look like a case that ran.

### If you wrote a consumer against the old output

Nothing was renamed and no field was removed — `progress`, `fuzz` and `disconnect` keep
their existing fields, so a consumer that ignores what it does not recognise keeps working
and simply gains messages. What is worth revisiting:

| you did | now |
| --- | --- |
| skipped `[fuzz] ` lines not starting with `{` | harmless, but nothing is skipped any more |
| tolerated an unparsable `[fuzz] ` line | it is a real fault — report it rather than swallowing it |
| counted delivery from `progress` | subtract `abandoned`, per target |
| read `case_id` and clamped negatives to zero | read `state`: `warmup` is not a case that ran |
| had nothing to do with the prose lines | `bad_env` and `resume` are messages you can act on |

`monitor_fuzzing.py` is the worked example of all five.

## Upstream lineage

This tree's history is discontinuous and `git log` alone will not explain the jump.

```
hostap (git.w1.fi)
  |
  |  f747ae0d13  2025-09-12  "Add QCA vendor attribute to allow SCC with
  |                           STA connected indoor channel"
  |              <- HansBlackCat/hostap forked here
  |
  +--> HansBlackCat/hostap        19 commits: Group Resumption Key, resumption
  |      |                        tickets, custom vendor IE, hwsim testbed
  |      |  5ef4d7c821  2025-11-18
  |      |
  |      +--> the harness         37 commits, to 88cf1848fa  (2026-09-04)
  |
  |  ... 2127 upstream commits ...
  |
  |  320eb1e09a  2026-11-18  "IEEE 802.1X auth: Add Supported Groups element
  |                           to last frame"
  v
main  <- mirror of upstream, re-applied onto here 2026-11-18
  |
  +--> fuzz  <- the harness: 4 commits, this branch
```

### Repository layout

| branch | what it is |
| --- | --- |
| `main` | a plain mirror of hostap upstream. No harness code. Fast-forwarded from `w1fi/main`, never committed to directly. |
| `fuzz` | the harness: `main` plus the four commits below. This is the working branch. |
| `archive/hansblackcat-grk` | frozen: the HansBlackCat research tree, tip `5ef4d7c821` |
| `archive/sae-fuzzing-old` | frozen: the harness before the move, tip `88cf1848fa` |

`fuzz` against `main` is therefore always exactly the harness, which makes it
reviewable as a pull request and makes "how far behind upstream are we" a question
`git log fuzz..main` answers directly.

### Why the move

The harness grew on a tree that forked from hostap on 2025-09-12. By 2026-11-18 upstream
was 2127 commits ahead, and that window closed a run of memory-safety bugs in precisely
the paths this harness drives frames into — `check_valid_he_mcs()` and
`get_max_nss_capability()` out-of-bounds reads, the NAN USD action frame off-by-one, the
FT RDIE off-by-2 bounds check, WNM sleep mode subelement length checks, the Multi-Link
element Common Info off-by-one, among others.

That made every crash suspect: before it could be called a finding it had to be triaged
against 14 months of fixes it might simply predate. The harness is ~120 lines of in-tree
change and every one of its hook points still existed upstream, so the harness moved rather
than the fixes being backported.

### What was dropped

The HansBlackCat research work — Group Resumption Key, resumption tickets, the custom
vendor-specific IE, the hwsim local testbed; roughly 5086 lines across 47 files — was not
carried forward. It rewrote 4-way handshake and association paths that upstream has since
changed substantially, parts of it were explicitly work in progress, and the harness never
depended on any of it.

One hunk was deliberately left behind: a fix removing an unused `u8 data[ETH_ALEN + 8]` in
`wpa_rtk_init()`. That function is part of the GRK work and does not exist upstream.

Both lineages are preserved unmodified:

| branch | tip | what |
| --- | --- | --- |
| `archive/hansblackcat-grk` | `5ef4d7c821` | the research tree as it stood |
| `archive/sae-fuzzing-old` | `88cf1848fa` | the harness as it stood on it |

### Keeping current

```sh
# once, if the remote is not configured:
git remote add w1fi https://w1.fi/hostap.git   # redirects to git.w1.fi/hostap.git

git fetch w1fi
git checkout main && git merge --ff-only w1fi/main && git push origin main
git checkout fuzz && git rebase main
# the rebase rewrites fuzz, so publishing it needs:
git push --force-with-lease origin fuzz
```

Then rebuild before trusting anything — `build/` holds dependency files naming
headers that may no longer exist upstream, and a stale one fails the build in a way
that looks unrelated:

```sh
rm -rf build && cd hostapd && cp defconfig-fuzz .config && make -j"$(nproc)"
python3 claude/fuzz_verify/fuzz_verify.py .          # from the repo root
```

Keep `main` tracking `origin/main`, not `w1fi/main`: upstream is read-only, and a
bare `git push` from a branch tracking it aims at w1.fi.

Rebase roughly monthly. The whole cost of the 2026-11-18 move was letting 14 months
accumulate; the commit split below exists so that repeating it stays cheap.

The cgit UI at `git.w1.fi/cgit/hostap/` sits behind bot protection and cannot be fetched
by tooling — use git, not the web view.

## Commit history

This branch re-applies the harness in four commits, deliberately split so that a rebase
conflict can only land in one of them:

| commit | what | can conflict? |
| --- | --- | --- |
| 1 | this document — the transition marker, so `git log` explains itself | no |
| 2 | the mutation engine and tooling: files upstream does not have | no |
| 3 | the in-tree hook call sites, ~80 lines over four files | **yes — and a conflict here names the hook point upstream moved** |
| 4 | `CONFIG_FUZZ` build integration | rarely |

The harness's own 37-commit development history is **not** replayed here — rebasing it
across 2127 upstream commits would have meant resolving conflicts in `src/ap/ieee802_11.c`,
which upstream grew by ~4591 lines, 37 times over. It is on `archive/sae-fuzzing-old`, and
it remains the record of why the code looks the way it does:

| commit | what |
| --- | --- |
| `e750781c2` | probe response was mutated through the address of a pointer, smashing `handle_probe_req`'s stack and never touching the frame |
| `e0c5f9a69` | fixed-size log buffers overflowing on real frames, a per-call dict leak, a `size_t` underflow, and a `switch` with no `break`s |
| `c55923b6b` | complete non-duplicating sweep, full header skip, EAPOL mutated pre-MIC, disconnect moved off the event loop |
| `877b0e13e` | crash detection, per-target resume, and the SAE config the harness had always referenced but which was never committed |
| `a1c2c4273` | `CONFIG_FUZZ` gate, `wpa_supplicant` link fix, undeclared `json`/`base64` dependencies, version marker |
| `258661420` | tree conventions: static symbols, `os_*` wrappers, typed frame-type enum, hostap formatting |
| `88cf1848f` | the `[fuzz] ` output contract and `FUZZ_HOLD_<TARGET>` — see [What changed most recently](#what-changed-most-recently) |

Each of those commit messages states the problem it fixes and why. A longer
problem-by-problem working record lives in `claude/fix_plan.md`, which is local and not
committed — if you do not have it, those commit messages are the record.
