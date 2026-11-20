# Live run against a real SAE station

What no offline harness can answer: whether holding an early stage actually
lets a station reach a later one. That is a property of the exchange, not of
the binary.

```sh
sudo ./fuzzing/live/run_live.sh              # ~22 min: 2 + 10 + 10
sudo ./fuzzing/live/run_live.sh --minutes 5  # ~12 min
sudo ./fuzzing/live/run_live.sh --phase held # one phase only
```

scapy is optional: with it each mutated frame is dissected, without it you get raw hex.
It is usually in a venv rather than installed system-wide, and `sudo` runs root's bare
`python3`, which would not see one in your home directory. Point `FUZZ_PYTHON` at the
interpreter that has it:

```sh
python3 -m venv ~/.venv/hostap-fuzz && ~/.venv/hostap-fuzz/bin/pip install scapy
sudo FUZZ_PYTHON=~/.venv/hostap-fuzz/bin/python3 ./fuzzing/live/run_live.sh
```

Logs, the generated config and any repro records go to `$FUZZ_LOGDIR/live/`, default
`$TMPDIR/hostap-fuzz/live/`, outside the checkout.

## Before starting

The station must be powered on and **trying to join throughout** — every case
is delivered as a reply to a station action, so a station that gives up stops
the run dead. Point it at:

| | |
| --- | --- |
| SSID | `hostapd-fuzz` |
| password | `fuzzfuzzfuzz` |
| security | WPA3-Personal (SAE), MFP required |
| channel | 6, 2.4 GHz |

## The radio

```sh
./fuzzing/live/run_live.sh --list   # no root needed: what it sees, and why
```


**The built-in radio is never used**, whether or not it happens to be idle:
it is the machine's own link, and "idle at this instant" is not a property
worth betting an uplink on. Only an external USB adapter is eligible, and
`--iface` does not override that — the rule is one `case` in
`interface_is_builtin()` if it ever has to change.

Beyond that the script refuses any interface holding the default route or an
association, and reports its reasoning per interface. Override the choice among
eligible adapters with `--iface NAME`.

It takes the interface out of NetworkManager's hands for the duration and hands
it back on exit, including on Ctrl-C.

## The three phases

| phase | environment | what it settles |
| --- | --- | --- |
| `sanity` | `FUZZ_DISABLE=1` | the station associates against this build at all. No `[fuzz] ` lines here is correct. If this fails, nothing after it means anything. |
| `control` | nothing held | reproduces the starvation: `probe_resp` advances, the stages behind it do not |
| `held` | `FUZZ_HOLD_PROBE_RESP=1` | the ask: handshakes complete repeatedly and `sae-send-commit` advances past 100 |

Running the control *before* the held phase is what makes the held result mean
something — otherwise a station that simply cannot connect looks the same as a
starved one.

## Reading the result

Each phase prints a table and writes its full output to `logs/<phase>.log`.
`summarise.py <log>` reproduces the table from a saved log:

```
   target             reached         of   frames  states
   probe_resp              -9      22244      400  held:400
   sae-send-commit        124      27872      134  mutating:125,warmup:9 0.4%

   SAE frames sent        134
   associations           268
   four-way handshakes    134
   disconnections         0

   contract: all 1852 '[fuzz] ' lines parsed as JSON with a msg
```

That last line is worth its own mention: it is the output contract checked
against **real traffic**, which no offline harness can do.

If hostapd dies, the monitor records the case in flight under `repro/` and the
phase reports it — that is the whole point of the exercise, not a failure of it.
