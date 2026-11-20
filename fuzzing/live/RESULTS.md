# Live runs

Newest first. Each run is reproducible with `fuzzing/live/run_live.sh`; the raw logs for the most
recent run only are kept under `logs/` (a later run overwrites them).

---

# Live run against a MikroTik hAP ax², 2026-11-18

The first run on the rebased tree, and the first against a station that is not the
ESP32-C6. Two ten-minute phases plus a two-minute sanity check.

| | |
| --- | --- |
| AP | `hostapd v2.13-devel-fuzz-hostap_2_11-3141-g102638c2f`, rt2800usb USB adapter `wlx00c0ca9958fb`, channel 6, `hw_mode=g` |
| station | MikroTik hAP ax² (RouterOS 7, `/interface/wifi` station mode), radio `wifi2`, `d0:ea:11:83:af:61` |
| security | WPA3-SAE, `ieee80211w=2`, `sae_require_mfp=1`, `sae_pwe=2`, `sae_groups=19` |
| station behaviour | holds a stable association when not disturbed; re-associates promptly after a forced disconnect |
| build | non-ASan |

## What happened

| | control (nothing held) | all four earlier stages held |
| --- | --- | --- |
| `probe_resp` | 300 of 44,220 | held |
| `sae-send-commit` | 266 of 27,872 | held |
| `sae-send-confirm` | warm-up only | held |
| `assoc_resp` | warm-up only | held |
| `auth-sae` | warm-up only | warm-up only |
| **`eapol`** | **13** | **596** of 32,428 |
| four-way handshakes | 7 | **92** |
| associations | 7 | **174** |
| disconnects | 7 | **92** |

`[fuzz] ` lines across the three logs: **3,537**, every one a JSON object with a `msg`,
**zero** parse failures. No crash, no hang, no repro record written.

## What this run established

- **The rebased hooks behave.** 2127 upstream commits reworked `src/ap/wpa_auth.c` by ~944
  lines and `src/ap/ieee802_11.c` by ~4591. Nothing in the harness's observable behaviour
  changed: the contract parses, holds hold, and the disconnect still fires at
  `PTKINITDONE` exactly once per completed handshake (92 of 92).
- **EAPOL mutation still precedes MIC computation.** msg-3 dumps carry a valid MIC over the
  already-mutated body, so the station parses the frame rather than dropping it on MIC
  failure. This was the single most fragile hook across the rebase.
- **Phasing is worth 46x on this station.** `eapol` 13 cases to 596.
- **The sanity phase is clean.** `FUZZ_DISABLE=1` produced **zero** `[fuzz] ` lines and a
  normal association and handshake, so nothing in the later phases is a configuration
  artefact.

## Two things that differ from the ESP32 run

- **Throughput is 8.9x higher.** 59.6 `eapol` cases a minute against 6.7. Sweeping
  `eapol`'s 32,428 cases is about **9 hours** here, against 125 hours on the ESP32. The
  binding constraint on this harness is the station, and stations differ by an order of
  magnitude. This contradicts the expectation that a RouterOS station would be the slower
  of the two.
- **A counter can climb while nothing gets through.** In the control phase
  `sae-send-commit` reached 266 cases, yet there were only 7 associations in the whole ten
  minutes. The station kept retrying authentication and each retry drew another mutated
  reply; not one attempt reached association. On the ESP32 the same stage blocked, but its
  counter stalled at 40 because it retried far less. **Read a target's case count against
  the handshake count, never on its own.**

## Why 174 associations gave only 92 handshakes

Answered, and it is not a finding about the station. `eapol` was the only mutating target,
and its 596 cases covered exactly three byte offsets:

| offset | cases | field |
| ---: | ---: | --- |
| 0 | 268 | EAPOL version |
| 1 | 268 | EAPOL type (`0x03` = EAPOL-Key) |
| 2 | 60 | body length, high byte |

Offset 1 is the whole explanation: for 268 consecutive cases the frame claimed to be some
EAPOL type other than EAPOL-Key, which a supplicant is required to reject. The sweep spent
a quarter of the phase confirming correct behaviour.

That is the depth-first sweep ordering, not the station — see
`fuzzing/verify/sweep_ordering/README.md`, whose model predicted the reached offsets of this run
exactly. The key data, nonce and RSN IE begin at offset 11 and were never reached.

---

# Live run against an ESP32-C6, 2026-09-05

Three ten-minute phases plus a two-minute sanity check, on this hardware:

| | |
| --- | --- |
| AP | `hostapd v2.12-devel-fuzz`, rt2800usb USB adapter (phy1), channel 8 |
| station | ESP32-C6 running Penzzer `wifi_target.c`, SSID `penzzer-test` |
| security | WPA3-SAE, `ieee80211w=2`, `sae_require_mfp=1`, `sae_pwe=2` |
| station behaviour | rejoins every 1000 ms, **alternating PSK and open** credentials |

## What happened

| | control (nothing held) | `probe_resp` held | all four earlier stages held |
| --- | --- | --- | --- |
| `probe_resp` | 229 of 43,148 | held, 219 frames | held, 181 frames |
| `sae-send-commit` | 40 of 27,872 | 40 of 27,872 | held, 38 frames |
| `sae-send-confirm` | warm-up only | warm-up only | held, 38 frames |
| `assoc_resp` | warm-up only | warm-up only | held, 38 frames |
| **`eapol`** | **8** (warm-up only) | **8** (warm-up only) | **66 of 50,116** |
| EAPOL frames mutated | 0 | 0 | **67** |
| four-way handshakes | 9 | 9 | **38** |
| associations | 9 | 9 | 38 |

The last column is the ask, working: with every earlier stage answered
correctly, a stage that had never been reached at all took 67 mutations in ten
minutes, and the station kept completing the handshake throughout.

## The handoff's diagnosis was wrong on this station

`fuzzing/phasing/README.md` attributes the starvation to `probe_resp`:
a mutated probe response breaks security negotiation, the station rescans, and
nothing behind it advances. On this station that is **not** what happens.
Holding `probe_resp` alone changed nothing measurable - the first two columns
above are identical for every deeper target.

Two measurements say why:

- **Every mutation in both phases landed on byte offset 0.** The sweep is
  depth-first, 268 cases per offset, and in ten minutes no target got past its
  first fuzzable byte. Offset 0 of a probe response is the timestamp, which is
  harmless - so mutating probe responses never broke anything here.
- **All nine handshakes happened during `sae-send-commit`'s warm-up.** The log
  interleaves `warmup -> handshake` exactly nine times, and associations stop
  the moment that target starts mutating. Byte 0 of the SAE commit frame breaks
  authentication outright.

So the blocking stage was one later than the handoff describes. The primitive
is right and the recipe is right - *hold every earlier stage* - but the claim
that `probe_resp` is the culprit is station-specific, and the 58% figure with
it. What is general is the shape: whichever stage first breaks the exchange
starves everything behind it, and only a hold gets past it.

## Throughput, which is the real limit

Every case is delivered as a reply to a station action, so the ceiling is the
station's reconnect cadence:

| phase | cases delivered | per minute |
| --- | --- | --- |
| control | 280 mutations across 3 targets | 28 |
| all four held | 67 `eapol` mutations | 6.7 |

At 6.7 cases a minute, `eapol`'s 50,116 cases would take **125 hours**. The
sweep is exhaustive by design, and against a real station that is the binding
constraint - not reachability. Anyone planning a campaign should pick offsets
deliberately (`FUZZ_START_<TARGET>`) rather than expect a target to be swept.

## Verified here that no offline harness can show

- The output contract against real traffic: **1,090 `[fuzz] ` lines** in the retained
  logs, every one a JSON object with a `msg`, zero parse failures. (A further 364 were
  checked at the time in the `probe_resp`-only run, whose log the later runs overwrote —
  each phase writes `logs/<phase>.log`, so re-running a phase replaces it.)
- `FUZZ_HOLD_<TARGET>` on live frames: held targets announced themselves on
  every frame, consumed no cases, and emitted no `fuzz` message.
- The forced disconnect cycling a real client: 38 disconnect messages against
  38 handshakes and 38 re-associations.
- The station completing SAE against a `CONFIG_FUZZ` build with the hooks
  disabled (`FUZZ_DISABLE=1`), which is the configuration-vs-mutation control.
