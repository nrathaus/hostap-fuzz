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
`NEED_BASE64` for you.

### The victim build: `CONFIG_FUZZ_REACH=y`

A second flag, and a different build. `CONFIG_FUZZ` mutates what the binary transmits;
`CONFIG_FUZZ_REACH` reports what its own parsers read and mutates nothing. The victim
in a two-process topology must be the second kind — both ends mutating is a run with no
reference in it — and before there were two flags there was no build that could be a
victim *and* say what it read.

```sh
cd hostapd
cp defconfig .config && echo CONFIG_FUZZ_REACH=y >> .config && make
./hostapd -v          # "Reach instrumentation is COMPILED IN"
```

It costs the stock build nothing, and that is checked rather than claimed: see
[What the victim read](#what-the-victim-read). `fuzz_reach.c` writes its own JSON and
pulls in no object a stock build does not already have.

### The station and mesh build

The harness also hooks `wpa_supplicant`'s own transmit paths, which is a separate build:

```sh
cd wpa_supplicant
cp defconfig-fuzz .config
make
./wpa_supplicant -v        # "v2.13-devel-fuzz" plus a COMPILED IN warning
```

`wpa_supplicant/defconfig-fuzz` turns on `CONFIG_MESH`, which upstream `defconfig` leaves
off. Without it `mesh_mpm.c` is not compiled and the peering hooks have no call site at
all — the mesh topology would run and send nothing.

> The `CONFIG_FUZZ` block in `wpa_supplicant/Makefile` sits **outside** `ifdef CONFIG_AP`.
> It used to be inside it, which was correct while the only hooks were in `src/ap`. The
> station and mesh hooks are not, so a nested block would build a binary that reports its
> hooks in `-v` and mutates nothing. `fuzzing/direction/verify_direction.py` checks the nesting.

## Run

There are two ways to run this, and which one you want depends on whether you have a
radio to spare.

### The direct way — what this was originally

Build hostapd with `CONFIG_FUZZ=y`, write a config, run it. The binary is a normal
hostapd that happens to mutate what it transmits, so anything you already do with
hostapd still applies:

```sh
cd hostapd && cp defconfig-fuzz .config && make
vi hostapd-wpa3.conf          # set interface= ; it ships as wlan0, a placeholder
./hostapd hostapd-wpa3.conf
```

Wrapping it in the monitor gets you crash detection, frame dissection and a coverage
ledger, but the invocation is the same shape:

```sh
./monitor_fuzzing.py                                   # defaults below
./monitor_fuzzing.py --config hostapd/my.conf --quiet
```

| flag | meaning |
| --- | --- |
| `--hostapd` | binary, default `./hostapd/hostapd` |
| `--config` | config file, default `hostapd/hostapd-wpa3.conf` |
| `--subject` | run something other than hostapd — a fuzzing wpa_supplicant, say |
| `--victim` | a second process to launch and watch for death (repeatable) |
| `--repro-dir` | where crashing cases are recorded, default `fuzz-repro/` |
| `--ledger-json` | write the coverage tally as JSON as well as printing it |
| `--quiet` | show only fuzzing activity, not all of the subject's output |

Exit codes: `0` clean, `1` the subject died, `2` bad invocation, `130` interrupted.

The monitor passes its environment through, so the tunables below go on the same command
line: `FUZZ_HOLD_PROBE_RESP=1 ./monitor_fuzzing.py`.

**This needs a real interface you can own**, and it gives you one half of the picture:
hostapd transmitting at whatever happens to be listening. You supply the peer, you supply
the radio, and if the peer is a phone you learn nothing when it silently drops a frame.

### The scripted way — what to use now

Each topology script builds its own world: a network namespace, its own hwsim radios, the
subject, the peers, the monitor, and a ledger at the end. One command, no interface of
yours involved, nothing left behind.

```sh
sudo modprobe mac80211_hwsim radios=0     # once per boot, the only privileged step

./fuzzing/topology/sta-vs-ap.sh 10        # 10 minutes
```

`radios=0` because each run creates its own radios *inside its own namespace*, where they
belong to the run and vanish with it. There is no teardown step to forget.

Prefer this unless you specifically need to drive a particular piece of hardware. It is
reproducible, it needs no hardware, it gives you a victim process whose death is a signal
rather than a guess, and it is the only way to reach the transmit paths that a lone
hostapd cannot exercise at all.

### scapy

Optional. With it each mutated frame is dissected and printed; without it you get raw hex
and one warning. Crash detection does not depend on it, and neither does the ledger.

It is not installed system-wide here, so if you want dissection, run the monitor with an
interpreter that has it:

```sh
python3 -m venv ~/.venv/hostap-fuzz && ~/.venv/hostap-fuzz/bin/pip install scapy
~/.venv/hostap-fuzz/bin/python3 monitor_fuzzing.py
```

Under `sudo` this matters: root's bare `python3` will not see a venv in your home
directory, and every frame comes back as raw hex.

## Handing it to someone else

The binary is self-contained. The element registries and the field table are
**compiled into it**, so a `hostapd` built here fuzzes on a machine with none of this
repository on it. What you hand over depends on what you want back.

| you give them | they get | they do not get |
| --- | --- | --- |
| the binary + a `.conf` | a working fuzzing AP. Every case printed as a `[fuzz] ` JSON line on stdout | crash detection, repro records, any coverage summary |
| + `monitor_fuzzing.py` | the subject relaunched and watched, a repro record written when it dies, frames dissected if they have scapy | the coverage tally |
| + `fuzzing/ledger/` | the full report: targets reached, fields, per-peer split | the registry denominators, unless they also have a hostap source tree |
| the repository | all of it | |

**The binary alone is a real answer, not a degraded one.** It mutates, it sweeps
deterministically, and it prints every case as JSON. If they redirect stdout to a file
and send it back, you can run the ledger over it here and get the whole report, because
the log is the record and the tooling only reads it.

```sh
# on their machine
./hostapd their.conf > run.log 2>&1

# on yours
python3 fuzzing/ledger/ledger.py . run.log
```

That round trip is usually the right shape: they need a binary and a config, you keep
the analysis.

### What travels and what does not

`monitor_fuzzing.py` looks for the ledger at `fuzzing/ledger/ledger.py` **relative to
itself**, so the two travel together with that directory structure intact, or the monitor
runs without coverage and says so on stderr.

The ledger reads `src/common/ieee802_11_defs.h` for the registry denominators, which is
the one thing in the report that cannot come from a log: how many members a family has.
Without a checkout it reports every numerator it recorded and says the denominators are
unavailable, rather than printing a table of zeros that would read as "nothing was sent".

Reproducing one of their crashes needs the **same binary**, since a case id only means
something within one case space. The `opset` on every line (`v6/10d/STRIDE/251@0`) is what
tells you whether their build and yours agree; if it differs, the same id is a different
mutation. Send the binary, not the branch name.

## Topologies

Four scripts, each setting up a whole run in a network namespace of its own.

```sh
./fuzzing/topology/sta-vs-ap.sh 10        # a fuzzing station vs a stock hostapd
./fuzzing/topology/mesh.sh 10             # two fuzzing supplicants in a mesh
./fuzzing/topology/multi-sta.sh 10 3      # 3 fuzzing stations vs a stock hostapd
./fuzzing/topology/multi-peer-ap.sh 10 3  # a fuzzing hostapd vs 3 stock stations
```

First argument is minutes, second (where it takes one) is the number of stations. Both
have defaults — `10` and `3` — so a bare `./fuzzing/topology/mesh.sh` is a ten-minute run.

### Which one do you want

| script | who mutates | who might die | reaches |
| --- | --- | --- | --- |
| `sta-vs-ap.sh` | the station | the AP | hostapd's Authentication, Association Request and EAPOL-Key parsers — unreachable from a fuzzing hostapd, which only ever transmits the other way |
| `mesh.sh` | both ends | either | the mesh peering path: Mesh Peering Open/Confirm/Close and AMPE. Neither end is a reference, so a crash says one of two mutations did it and not which |
| `multi-sta.sh` | N stations | the AP | code that only runs when sessions overlap — N concurrent sessions live inside one victim at once |
| `multi-peer-ap.sh` | the AP | any station | the per-peer split: one subject talking to N peers, so "which peer got which case" has more than one answer |

If you are migrating from running hostapd directly, **`multi-peer-ap.sh` is the closest
thing** — it is a fuzzing hostapd with peers attached. The other three reach transmit
paths that a fuzzing hostapd does not have.

### None of these touch a real device

hwsim radios are simulated: frames move between them through kernel memory, nothing is
transmitted, and no device in the room can hear them. The victim is always a process on
this machine. That is what buys the precise oracle — a stack trace instead of a device
that stopped answering — and it is also the limit.

**To fuzz actual hardware you still need a real adapter**, and that is
`fuzzing/live/run_live.sh`: a fuzzing hostapd on an AP-capable USB radio, against whatever
station you point at it. It picks an external adapter and refuses a built-in one, refuses
any interface holding the default route or an association, generates its own config rather
than using the placeholder in `hostapd-wpa3.conf`, and hands the interface back to
NetworkManager on exit. [Verified against a real station](#verified-against-a-real-station)
records what it has measured.

The two are complementary, and the division is worth stating: **hwsim finds bugs in the
implementation with an oracle you can trust; a real adapter finds out whether a device is
affected.** A crash on hwsim is a stack trace. A device that stops answering is a question.

### What each one needs

Three things, and the third is the one that catches people.

**1. `mac80211_hwsim`.** The only privileged step, once per boot:

```sh
sudo modprobe mac80211_hwsim radios=0
```

`radios=0` because each run creates its own radios *inside its own namespace*, where they
belong to the run and vanish with it. There is no teardown step to forget.

**2. Nothing else privileged.** Each script re-executes itself under `unshare -r -m -n`.
`-r` maps you to root inside, which is what makes `CAP_NET_ADMIN` over the new namespaces
available without being root outside them; creating a hwsim radio needs that and nothing
else. You do not run these with `sudo`.

**3. Two builds — and not the same two for every script.** Every run has a subject that
carries the hooks and a peer that is a stock build, because the point of the peer is to be
a reference that crashes honestly. Which binary is which **inverts** between the scripts:

| script | `hostapd/hostapd` | `wpa_supplicant/wpa_supplicant` |
| --- | --- | --- |
| `sta-vs-ap.sh` | stock | **fuzz** |
| `mesh.sh` | not used | **fuzz** |
| `multi-sta.sh` | stock | **fuzz** |
| `multi-peer-ap.sh` | **fuzz** | stock |

So one pair of binaries in the tree cannot satisfy all four. Each script checks `-v` on
both and refuses with a message naming the build it wanted, rather than running a session
in which both ends mutate and nothing is a reference.

**If you have been building both from `defconfig-fuzz`, every script will refuse** — that
pair is subject-and-subject, which satisfies none of the four rows. This is the expected
first encounter, and the refusal names which one is wrong:

```
error: .../hostapd is a fuzzing build; the victim must be a stock one
```

Build all four once, out of the way, and point the scripts at them:

A stock build is `defconfig-fuzz` **with `CONFIG_FUZZ` commented out**, not the upstream
`defconfig`. Two reasons: upstream's own `defconfig` does not currently build (see
[Build](#build)), and the victim needs the same feature set as the subject or the parsers
you are aiming at are not compiled in. Same config, one line different, is the whole
difference between a subject and a reference.

```sh
B=~/hostap-fuzz-bin && mkdir -p $B

mk() {  # mk <dir> <fuzz|stock> <output-name>
  ( cd "$1" || exit 1
    if [ "$2" = fuzz ]; then cp defconfig-fuzz .config
    else sed 's/^CONFIG_FUZZ=y/#&/' defconfig-fuzz > .config
    fi
    make clean >/dev/null && make -j"$(nproc)" >/dev/null && cp "$1" "$B/$3" )
}

mk wpa_supplicant fuzz  wpa_s-fuzz       # sta-vs-ap, mesh, multi-sta
mk hostapd        stock hostapd-stock    #   their victim
mk hostapd        fuzz  hostapd-fuzz     # multi-peer-ap
mk wpa_supplicant stock wpa_s-stock      #   its victims
```

```sh
AP=$B/hostapd-stock STA=$B/wpa_s-fuzz  ./fuzzing/topology/sta-vs-ap.sh 10
AP=$B/hostapd-stock STA=$B/wpa_s-fuzz  ./fuzzing/topology/multi-sta.sh 10 3
                    STA=$B/wpa_s-fuzz  ./fuzzing/topology/mesh.sh 10
AP=$B/hostapd-fuzz  STA=$B/wpa_s-stock ./fuzzing/topology/multi-peer-ap.sh 10 3
```

`AP=` and `STA=` override the in-tree defaults (`$ROOT/hostapd/hostapd` and
`$ROOT/wpa_supplicant/wpa_supplicant`). Without them the scripts use whatever is in the
tree, which is fine if you only ever run one direction.

Build the **victim** with ASan. It is the process whose death is the finding, and without
ASan you only see the crashes that happen to segfault on their own:

```sh
make CFLAGS="-fsanitize=address -fno-omit-frame-pointer -g -O1" LDFLAGS="-fsanitize=address"
```

The configs the scripts generate — `ap-stock.conf`, `sta-fuzz.conf`, `mesh-fuzz.conf` —
are templates in `fuzzing/topology/`. You do not edit them per run; the script fills in
the interface, the SAE group and the SSID into a copy under `$FUZZ_LOGDIR`.

Everything a run produces — logs, ledgers, repro records — goes to `$FUZZ_LOGDIR`,
default `$TMPDIR/hostap-fuzz`, **outside the checkout**. A log written next to the source
is one `git add -A` from being committed.

Each re-executes itself under `unshare -r -m -n`. `-r` maps you to root inside, which is
what makes `CAP_NET_ADMIN` over the new namespaces available without being root outside
them; creating a hwsim radio needs that and nothing else.

### The free oracle

In `sta-vs-ap.sh` the thing that sends and the thing that might die are **different
processes**. The station carries the hooks; the AP is an ordinary build that transmits
nothing mutated and is there to parse and, if a frame finds something, to crash.
`monitor_fuzzing.py --victim` launches it and watches it on a thread — a subject that
stalls would otherwise leave a dead victim unnoticed for as long as it stayed quiet. The
flag is repeatable: a run with several peers has several processes that might die.

That is the whole detection in this harness and all it wants. A process that died is not a
judgement call; anything softer is a filter over what counts as interesting, written by
whoever wrote the filter. The repro record gained a `who` field for the same reason: the
process that sent the frame and the process that died are no longer the same one, and a
record that does not say which is a record of nothing.

Both scripts refuse the obvious mistakes. A fuzzing victim would mean both ends mutating
and nothing in the run being a reference; a subject with no hooks would send nothing and
the run would look like a clean pass of a sweep that never happened. Both are checked
against the `-v` banner before anything starts.

The mesh topology has no stock side by construction — both ends run the same program and
each mutates what it sends. A crash there says one of the two mutations caused it and not
which. That is the price of the only topology from which mesh peering is reachable at all:
an AP never sends a Mesh Peering Open and neither does a station. Node B's own ledger is
printed separately rather than merged into node A's, because a merged tally is true of the
pair and false of each.

### More than one peer

A one-peer run cannot produce concurrent-session stimulus at all: whatever the single peer
negotiated is the only thing live, and every path that needs two overlapping sessions is
unreachable because there is only ever one.

The two multi-peer scripts point in opposite directions and each is worth having:

| script | subject | peers | what it is for |
| --- | --- | --- | --- |
| `multi-sta.sh` | N fuzzing stations | one stock AP | N concurrent sessions **inside the victim**, so whatever state its subsystems share is under all of them at once |
| `multi-peer-ap.sh` | a fuzzing hostapd | N stock stations | the subject talks to N peers, so "which peer received which case" has N answers |

Each peer negotiates a **different finite cyclic group**, picked by
`fuzzing/topology/peers.py` out of the registry `fuzzing/axes/families.py` derives from
the tree — 20 the tree can instantiate, ordered so the ones a stock build completes come
first. The generated station configs differ in exactly that one negotiated line, so
whatever a run finds attributes to it. The AP is then configured to accept exactly the
groups its stations chose.

**N peers is N times the stimulus, not N copies of it.** Peers share a target's case
counter, so each receives a *different* case; per-peer counters would mean every peer
sweeping the same cases. The ledger prints the split rather than leaving it to be assumed:

```
PEERS -- which peer received which cases
  02:00:00:00:90:00        41 case(s)  assoc_resp 2, eapol 17, handle-auth 12, probe_resp 10
  02:00:00:00:91:00        41 case(s)  assoc_resp 2, eapol 11, handle-auth 17, probe_resp 11
  02:00:00:00:92:00        61 case(s)  assoc_resp 7, eapol 29, handle-auth 15, probe_resp 10
```

Which peer, not whether it minded. Record, not verdict.

**Where the peer comes from.** A management frame carries its destination address, so the
engine reads it out of the frame and no call site says anything — and it cannot disagree
with what went on the air. A frame with no address of its own (an EAPOL-Key body, whose
addressing is in the ethernet header added below the hook) gets one from
`fuzz_peer_hint()`, which is **one-shot**: cleared by the next mutation whether or not it
was used, so a site that sets a hint and then takes an error path cannot have it attached
to another peer's frame.

`--victim` is repeatable, because a run with several peers has several processes that
might die and watching only the first would miss the others.

### One case per association

A station sends roughly one frame per target per session and then stays connected. Without
cycling the association, a run of any length covers four cases — and the first nine per
target are the warm-up, so it covers none. `FUZZ_RECONNECT_MS` schedules the cycle when
the association completes; it mirrors `FUZZ_DISCONNECT_MS` on the AP side, including `0`
meaning "stay connected", which is what you want for anything past the handshake.

It is deliberately not conditional on how the session ended. Reconnecting only after a
successful association would stop the sweep at the first mutation the AP refused — which
is to say, at the first interesting one.

Measured on hwsim: about 30 mutated frames a minute in `sta-vs-ap.sh`, spread over four
station targets, and about 160 a minute per node in `mesh.sh`, where peering retries far
faster than a full SAE and four-way does. The mesh run also drives `auth-sae`,
`sae-send-commit`, `sae-send-confirm` and `handle-auth`, because mesh SAE goes through the
same `src/ap` code the AP topology exercises.

## Tunables

All environment variables — there is no `hostapd.conf` option, because `apply_mutation()`
has no `hapd` pointer at its call sites.

| variable | default | meaning |
| --- | --- | --- |
| `FUZZ_DISABLE=1` | off | Run a fuzzing build as a stock AP. Use this to prove a failure comes from the mutation and not the configuration. |
| `FUZZ_DISCONNECT_MS` | `1000` | Delay before forcing the STA off so the next frame gets the next case. **`0` leaves the STA connected**, which is what you need to fuzz anything past the 4-way handshake (group rekey, data path). AP side. |
| `FUZZ_RECONNECT_MS` | `1000` | The same thing on the station side: delay before cycling the association once it completes. **`0` leaves the station connected.** |
| `FUZZ_TIER` | auto | `FULL`, `LADDER` or `STRIDE` for every field domain. Unset means `FULL` for a domain of 256 or fewer and `STRIDE` above it. |
| `FUZZ_STRIDE_OFFSET` | `0` | Which run of the stride set this is. The union over `0..250` is the whole domain, so this says what the run defers rather than what it skips. |
| `FUZZ_START_CASE` | `0` | Resume every target at this case, skipping the warm-up. |
| `FUZZ_START_<TARGET>` | — | Resume one target. Takes precedence over `FUZZ_START_CASE`. |
| `FUZZ_HOLD_<TARGET>=1` | off | Answer one target **correctly**: its frames go out unmutated and it consumes no cases. This is how you reach a later stage — see [Phasing](#phasing). |
| `FUZZ_SWEEP_DEPTH_FIRST=1` | off | Sweep every mutation at one byte offset before moving to the next, instead of the breadth-first default. Use it to localise a crash you have already seen — see [How the sweep works](#how-the-sweep-works). |
| `FUZZ_REPEAT_<STAGE>` | `0` | Deliver a one-shot stage this many **extra** times per peer, so a stage the state machine produces once gets more than one case per session — see [Stage multiplicity](#stage-multiplicity). Clamped to 32. |
| `FUZZ_ADDRS` | `0` | How many **distinct source addresses** one peer presents, cycling. The station's configuration has to ask for the change as well; the run script adds that when this is set — see [How many identities one peer presents](#how-many-identities-one-peer-presents). Each change costs an interface bounce. |
| `FUZZ_TAIL=1` | off | Pin the span under test to the end of the frame. A second case space, told apart by the opset — see [Two case spaces](#two-case-spaces-fuzz_tail1). |
| `FUZZ_REACH_DISABLE=1` | off | Silence a reach-instrumented build, so one binary can be a measured victim and an unmeasured one without being rebuilt. |

Target names fold into variable names by uppercasing and replacing every non-alphanumeric
character with `_`, so `auth-sae` is `FUZZ_START_AUTH_SAE` or `FUZZ_HOLD_AUTH_SAE`. The
monitor prints the exact variable to use, so you never have to derive one by hand.

`FUZZ_HOLD_<TARGET>` and `FUZZ_START_<TARGET>` are independent: hold a target at a resume
point and it parks there, reporting that case rather than the warm-up.

A hold is resolved once per target, when the target is first exercised, so it is a property
of the run — there is no way to lift it under a station mid-exchange, which is deliberate.
Since a held target consumes no cases, the next run without the hold sweeps its case space
from the start rather than from wherever the held run left off.

## The field model

A byte-offset sweep knows a frame as a run of octets. It will put all 255 other values
through the low octet of a status code and all 255 through the high one, and **never once
send the pair that makes the field 300**. Two octets is 65,536 values; octet-wise reaches
511 of them. That gap is not a tuning parameter — it is the difference between sweeping a
field and sweeping the bytes it happens to occupy.

So each frame's named fields are a domain of their own, swept as units:

| field | domain |
| --- | --- |
| one or two octets wide | every value — 256 or 65,536, which for a field that narrow *is* its whole content space |
| wider — a nonce, a timestamp, a MAC address | a fill from a six-shape pattern set, because 2^256 is not a domain anyone finishes and content is not what is under test there |

### The table is generated

`src/common/fuzz_fields.h` is produced by `fuzzing/ledger/fields.py` from `struct
ieee80211_mgmt`, `struct ieee802_1x_hdr` and `struct wpa_eapol_key`. Nothing in it is
typed. A field upstream adds, moves or widens arrives with the next rebase:

```sh
python3 fuzzing/ledger/fields.py .            # 34 fields, 26 integer, 8 opaque
python3 fuzzing/ledger/fields.py . --emit-c > src/common/fuzz_fields.h
python3 fuzzing/ledger/fields.py . --check    # fails when the header has gone stale
```

**Which layout applies is read from the frame, not declared by the caller.** The engine
takes the management subtype out of the frame control field, so the same call site that
sends an Authentication frame and a Deauthentication frame gets each one's fields without
being told. A subtype with no fixed fields — a Probe Request — gets no field cases rather
than another subtype's, and a frame that ends mid-field gets only the fields that fit;
clamping would write one field's octets under another's name.

An Action frame used to contribute only its category octet, because what follows is keyed
by category through a second union and nothing in the struct says which category selects
which member. That mapping is still not invented. It is now read off the tree's own
dispatch, which is the next section. Where it cannot be read, everything past the category
still falls back to the octet sweep, and the same applies anywhere the model is silent,
which is why adding to it cannot cost coverage.

### Reduction is declared, not quietly applied

A two-octet field at `FULL` is 65,536 cases. Three of them in one frame is 196,608, and a
measured live run reaches case 596 in ten minutes. So the reduction is named in every
message rather than left implicit:

| tier | rule | a `u16` field costs |
| --- | --- | --- |
| `FULL` | the entire domain | 65,536 |
| `LADDER` | `0, 1, 2, n-1, n, n+1, max-1, max`, where `n` is the value the frame was built with | 8 |
| `STRIDE` | the ladder, then the rest at a fixed prime stride from this run's offset | 270 |

Default (`FUZZ_TIER` unset) is `FULL` for a domain of 256 or fewer and `STRIDE` above it —
so **every one-octet field is swept entire** and every two-octet field costs 270 cases a
run.

**`STRIDE` is deferral, not sampling.** Case *k* is `(offset + k × 251) mod domain`; every
value *v* is reached at offset `v % 251`, step `v / 251`, so the union over the 251 offsets
is the whole domain. `fuzzing/fields/verify_fields.py` runs all 251 and checks the union is
exactly `0..65535` — nothing is silently skipped, it is deferred to a named future run, and
the offset is in every message so any case replays.

The ladder's eight entries can coincide — a built value of 0 makes four of them the same
case — and they are still eight. A case count that moved with the frame would move
`case_max` with it, and then no `case_id` would replay.

### What it bought

The three registries element synthesis could not reach, because they are fields and not
elements. Measured by the ledger, under `FUZZ_TIER=FULL`:

| registry | before | now |
| --- | --- | --- |
| status code | 1 of 123 | **123 of 123** |
| authentication algorithm | 1 of 11 | **11 of 11** |
| reason code | 0 of 61 | **61 of 61** |

Under the default tier those are a measured fraction per run instead, complete over 251.
The ledger prints which, per field, with the denominator.

## The frame past the struct

The field table above is derived from three structs and refuses to invent anything they do
not say. That is the right rule, and it means the model ends where each struct ends,
which on this product is not where the frame ends. Three things live out there, and
`src/common/fuzz_layout.h` is all three, generated by `fuzzing/layout/layout.py`.

### A field whose offset is solved for, not tabled

`struct wpa_eapol_key` ends at `key_id`, offset 81. What follows it in the header is three
*comments*:

```c
	/* variable length Key MIC field */
	/* big endian 2-octet Key Data Length field */
	/* followed by Key Data Length bytes of Key Data */
```

`key_data_length` is **the** length field on an EAPOL-Key frame and it was the one field of
that frame nothing swept as a field. It cannot be another constant-offset row, because it
sits at `sizeof(struct wpa_eapol_key) + mic_len` and `mic_len` comes from the negotiated
AKM. A configuration axis moving a field offset is something no other row in the table
does.

So the generator reads those three comments as the declaration they are, takes the widths
the gap can have out of `wpa_mic_len()` and the function it delegates to (`{0, 16, 24,
32}`), and the engine solves for the offset in each frame from a value it already has:

```
base + gap + width + value == the frame's length
```

**Three answers, and they stay three.** One candidate is the case that gets swept. Zero and
several are both real, since a short key data field can make two gaps fit, and both are
reported as *unplaced* rather than resolved, because picking one of two writes a
65,536-value domain into octets that belong to another field. Every run says how many
frames the solver could not place; a domain that quietly is not there is the one thing this
report may not produce.

> **This guarantee is weaker than the table's, and the header says so.** A struct member has
> a type and a name, and `--check` fails when it moves. These three lines are matched as
> text, so a rewording fails the check, which is wanted, and a deletion upstream would
> take the field out of the model. The candidate set also declares itself INCOMPLETE,
> because two of `wpa_mic_len()`'s returns are not literals, so a frame the solver cannot
> place is not necessarily a malformed one.

### Whether the receiver reads it at all

A field's domain is per **target**, not per frame layout. The 802.1X header's `length`
field is a `u16`: 65,536 values, 270 of them a run. Measured in this tree:

| | reads `hdr->length`? | |
| --- | --- | --- |
| station, `wpa_sm_rx_eapol()` | **yes** | reads all twelve named fields |
| AP, `wpa_receive()` | **no** | and not `version`, `key_length` or `key_rsc` either |

At `eapol`, where hostapd transmits and the station parses, that domain is live. At
**`sta-eapol`, where the station transmits and the AP parses, four of the twelve named
fields go to a receiver that never reads them**, two of them full `u16` domains. That is
not weak coverage; it is none, and it reads exactly like coverage unless something says so.

Every target carries the role it transmits as, from the directory its hook is in. The
receiver is the rostered parser whose role is the other one, and every field case reports
`read`:

| `read` | means |
| --- | --- |
| `1` | the receiver on the other side reads this field |
| `0` | it provably does not |
| `-1` | **nothing here can say**: shared code, or a frame kind with no receiver rostered |

The claim costs something as well as being reported. A dead field is swept at `LADDER`,
the edges of its domain and of where the frame already was, and not at `STRIDE`, which is
251 runs spent completing a domain nothing will look at. Eighteen cases is what it costs to
keep a wrong claim from deleting a field outright, and setting `FUZZ_TIER` explicitly
overrules it. Measured at `sta-eapol`: **189 cases down to 60**, the rest returned to fields
something reads.

**The read set is scoped to the FILE that holds the receive path, not to the function.** A
receiver hands the frame to helpers beside it, and a claim scoped to one function would
call a field dead that a helper three lines down reads. Over-claiming a read costs a
finding; under-claiming one states a falsehood, so every rule errs the first way: an
assignment, a `WPA_PUT_*` of the member and a copy *into* it are writes, and anything else
counts as a read.

The complement is a reachability gain rather than a saving. Both receivers bound the
declared length with `>` and not `==`, so **trailing octets are accepted on both sides**:
both EAPOL hooks now carry headroom and return a length, and the frame-length domain runs
there, 379 distinct lengths where there had been one.

### The Action payload, keyed by its own category

`action.category` is one octet, and every surface in this harness's Action roster is behind
it. The mapping from category to union member is not invented and not hand-written: a scope
in the tree that tests or sets `u.action.category` against one constant, and the first
member of `u.action.u.M` against another, has named the pair. The dispatch is split at its
`case` labels, so hostapd's `handle_action()` is five scopes and not one.

```sh
python3 fuzzing/layout/layout.py .          # 14 layouts, 2 keys refused, 2 receivers
python3 fuzzing/layout/layout.py . --check
```

**A key that more than one member claims is refused, not guessed at.** The wrong layout is
worse than none: it writes real values at the wrong offsets *under the right names*. Both
refusals are announced in the inventory and printed by the ledger, because a refusal nobody
reports looks exactly like a category nobody uses.

The layouts travel with their denominator: **14 of them, over 10 of the union's 21
members**. The other eleven are members the tree's dispatch never names, and their frames
keep the byte sweep. That is a figure, not a gap somebody forgot.

What it bought, at one target:

| `wnm-bss-tm-req` | before | now |
| --- | --- | --- |
| named fields | 0 | **5**, one of them a `le16` |
| element chain starts at | whatever the walk could find | **7**, stated by the layout and by the hook, independently |

A layout with no flexible array member is a positive statement that the frame has **no**
element chain. `coloc_intf_req` is one, and its own hook had already said the same thing by
using the resize entry point rather than the element one.

Four hooked sites were declaring a frame kind that said less than they knew:
`wnm-sleep-resp`, `wnm-bss-tm-req`, `mesh-plink` and `mesh-plink-ampe` each hand over a
buffer that begins at the Category octet and each called it `FUZZ_TYPE_FRAME_BODY`. They
are `FUZZ_TYPE_ACTION_BODY` now, which is what lets the layout table name their fields.

## Element synthesis

Rewriting an existing element's id octet in place — which the octet sweep already does, for
all 255 values of it — selects a different parse helper, but the length and the body still
belong to the element that was there. Most helpers reject on length within a line or two.
The reach is wide and the depth is nil.

Reaching a helper's **body** means constructing an element: chosen id, chosen length,
inserted into the chain. Four domains, all enumerated:

| domain | size | varies |
| --- | --- | --- |
| identity | 179 element ids + 62 extension ids | fastest |
| position | every insertion point in the chain, before first and after last | next |
| length | the element's body, `0 ..` what the headroom allows | next |
| multiplicity | the same element present `2..5` times | slowest |

**Identity varies fastest on purpose.** A run that is cut short — which against a real
station is every run — has covered every id before it has covered any id twice. All 241
arrive within about 1,450 cases, roughly 25 minutes at the hAP ax²'s measured cadence. A
domain that is complete but unreachable is the same as a domain that is missing.

None of this is filtered to "legal in this frame". An element appearing where it is not
legal is a case worth sending, and a legality filter is exactly the hand-curation that
would put the spotlight back.

### The chain's own shape

Three operators that invent nothing, sweeping the structure rather than the contents:
**delete** element *i* for every *i*, **duplicate** element *i* for every *i*, **swap**
*i* and *j* for every pair. These are the changes no in-place octet mutation can express.
A parser that walks a chain positionally, or re-reads an offset a prior step should have
advanced, misbehaves when the chain's **shape** differs from the one it expected — and
shape is exactly what a length-preserving byte sweep leaves alone.

### Where the chain is

The call site says, because only the call site knows:

```c
rlen = apply_mutation_elements(dbg, FUZZ_TYPE_IEEE80211_MGMT, reply, rlen, capacity,
                               IEEE80211_HDRLEN + sizeof(reply->u.auth));
```

A management frame's variable part is an element chain for some frames and begins with
fixed fields for others, and the octets of an SAE scalar parse as perfectly plausible
elements. So the hook walks the region and **refuses a partial walk**: a length that runs
past the end, or a walk that does not land exactly on it, means there is no chain. It then
falls back to the one insertion point that is always real — the end of the frame — and says
so with `"npos":1`. Inserting "after element three" of a chain that does not exist would put
the element at an offset chosen by misreading a scalar.

`apply_mutation_resize()` and `apply_mutation()` pass no chain offset and get no element
cases at all, so every other call site is exactly what it was.

### Which chain it is

An element is `u8 id, u8 len, body`. **That is one of five TLV formats on this product**,
and emitting an attribute under the wrong one is not a weaker case but a different one: the
parser takes its length out of octets the engine filled with body, the chain still walks,
and the run reports a length domain it did not sweep. Read out of the walkers themselves by
`fuzzing/chain/chain.py`:

| chain | walker | id | length | header |
| --- | --- | --- | --- | --- |
| `elem` | `__ieee802_11_parse_elems` | `u8` | `u8` | 2 |
| `wps` | `wps_parse_msg` | `u16` **big endian** | `u16` **big endian** | 4 |
| `dpp` | `dpp_get_attr` | `u16` little endian | `u16` little endian | 4 |
| `p2p` | `p2p_parse_p2p_ie` | `u8` | `u16` little endian | 3 |
| `nan` | `nan_de_get_attr` | `u8` | `u16` little endian | 3 |

Each header size is **stated twice by its own walker**, by the reads it makes and by the
minimum number of octets it refuses to walk below, and the generator fails on a
disagreement rather than choosing between two readings. WPS and DPP differ in nothing but
byte order, which is exactly the kind of difference a hand-written table loses.

```sh
python3 fuzzing/chain/chain.py .          # 4 formats beside the element chain, 211 members
python3 fuzzing/chain/chain.py . --check
```

Each of the four carries a generated identity registry from its own enum, synthesised the
way element ids are. That matters because **a sparse 16-bit identity is the stride problem
again**: swept as a `u16` field, every defined WPS attribute type is reached in one run out
of 251. Synthesised from the registry, all **88 of 88 arrive in run 1**.

The chain travels in every message, because the identity spaces overlap: `0x1001` is
`ATTR_AP_CHANNEL`, and `DPP_ATTR_I_BOOTSTRAP_KEY_HASH`, and is not an element id at all.
The ledger keeps a tally per chain for the same reason.

**Which chain a buffer holds comes from the call site**, like the offset and for the same
reason. `wps-msg` names `FUZZ_CHAIN_WPS` with an offset of 0, because the whole message is
that chain. The other three do not have a caller that can say: DPP over TCP multiplexes
encapsulations whose prefixes differ on one socket, and the Action convergence point reads
a *label* out of the frame but not a chain, and saying which protocol's attributes follow
which label is the category-keyed guess the layout table declines to make. Naming a chain
with the wrong offset would be worse than naming none.

> `CONFIG_WPS`, `CONFIG_DPP`, `CONFIG_P2P` and `CONFIG_NAN_USD` are **off in both shipped
> configurations**, so four of these five formats are mechanism for a build that turns them
> on. The chain roster goes out in the inventory and the BUILD section says why the count is
> zero, which is the whole point of reporting both.

### The registry tables are generated

`src/common/fuzz_registries.h` is extracted from `src/common/ieee802_11_defs.h`, never
typed:

```sh
python3 fuzzing/ledger/registries.py . --emit-c > src/common/fuzz_registries.h
python3 fuzzing/ledger/registries.py . --check     # fails when the header has gained a member
```

The check is the point of generating it. Upstream adds members regularly, and a table that
quietly falls behind re-narrows the very spotlight the synthesis exists to widen —
silently, because a registry member that is never emitted looks exactly like one that is.

### The lengths the parser enforces are generated too

`src/common/fuzz_minima.h` is extracted from the three parse functions in
`src/common/ieee802_11_common.c`:

```sh
python3 fuzzing/ledger/minima.py .                 # 39 guards over 39 element ids
python3 fuzzing/ledger/minima.py . --emit-c        # writes src/common/fuzz_minima.h
python3 fuzzing/ledger/minima.py . --check         # fails when a minimum has moved
```

Each guard's value is evaluated by **the compiler**, against the same headers and include
paths the daemon is built with — 17 of the 39 are `sizeof(struct …)`, `2 * ETH_ALEN` or a
named constant, and re-implementing C constant arithmetic in Python would be a second
opinion about a number that has only one. The header carries the expression beside the
value, so a crash record says `sizeof(struct rsn_ftie)` and not only `82`.

The engine uses them to aim every length domain: the first length an element id is built
with is the one its own parser insists on, rather than zero. A uniform sweep reaches that
window in one run of 251; aimed, it reaches it in run 1.

### Two case spaces: `FUZZ_TAIL=1`

Every parser on this product hands out pointers *into* the frame and copies nothing —
`ieee802_11_parse_elems()` alone fills 92 `(pointer, length)` pairs. A consumer that reads
one octet past the end of its span reads the next element's id: same allocation, same
page, no fault. Nothing for a crash oracle to see, and nothing for a sanitizer either.

`FUZZ_TAIL=1` selects a second case space in which **the span under test is the last thing
in the frame**:

```sh
FUZZ_TAIL=1 ./fuzzing/topology/sta-vs-ap.sh 30
```

A synthesised element goes in at the end whatever the position axis said, and an octet
case cuts the frame to end where the element containing that octet ends — at the end of
the span *the mutation produced*, not the one the builder wrote. An over-read then crosses
the frame boundary instead of crossing into a sibling element.

**This makes the defect reach past the buffer. It does not make it detectable.** Whether a
read past the frame is observable depends on the victim's allocator and on how its driver
handed the frame up. Against a victim built from source — which both hwsim topologies are
— it is the difference between a sanitizer that can fire and one that cannot, and that is
the whole of the claim. The ledger says so in the report rather than leaving it to be
remembered.

It costs a dimension: position in the chain is a domain, and pinning the span removes it.
So the two run as separate campaigns — position swept for reach, last-position for
observability — and the opset carries `/tail`, so a `case_id` from one never replays as
the other. The cut also shortens the chain on purpose, which is why the ledger's "one
hostile field" section reports a shortened chain here as the point rather than as a broken
case space.

Only where the call site opted into a frame of a different length, which is the same
opt-in the length domain uses: `apply_mutation()` returns `void`, so a site that calls it
sends what it built whatever the engine said.

A synthesised element reports `"type":"MUT_ELEM"` with the id under `eid` or `ext_id`
(never both — a consumer counting coverage must not have to infer which registry a number
came from, and 93 is a different thing in each), the body length, the insertion point as
both a chain index (`pos`) and a byte offset (`at`), and the lengths before and after. A
chain operator reports `"type":"MUT_CHAIN"` with `op`, `i`, `j` and `nelem`.

## Frame length

The hook was length-preserving: every case kept the frame exactly as long as hostapd built
it, so how a peer handles a short or over-long frame was unreachable by construction rather
than by chance. A frame's length is a domain in its own right — `0 .. capacity` — and
independent of anything inside it.

A call site opts in by allocating headroom and using the return value:

```c
capacity = rlen + FUZZ_HEADROOM;
buf = os_zalloc(capacity);
...
rlen = apply_mutation_resize(dbg, FUZZ_TYPE_IEEE80211_MGMT, reply, rlen, capacity);
```

`FUZZ_HEADROOM` is `2 + 255` — one maximal element's worth, the smallest headroom in which
a whole new element can appear. It is `0` without `CONFIG_FUZZ`, so a stock build allocates
exactly what it did, `apply_mutation_resize()` folds to returning the length it was given,
and the call site needs no `#ifdef` of its own.

`send_auth_reply()` is opted in. Everything else still calls `apply_mutation()`, which
passes `capacity == len` — the length domain is then empty and the case space is the one it
has always been. That is checked rather than asserted: the two entry points are run over
the same case space and compared case for case.

### The domains are interleaved, not concatenated

Appending one domain's cases after another's would put them past the end of every run
that does not finish — which, against a real station, is every run: a measured ten minutes
reached case 596 of an EAPOL-Key frame's 32,428. So the sweep is a round robin: in round
*r*, every domain with more than *r* cases contributes its case *r*. The mapping is total
and duplicate-free — every `case_id` below `case_max` is exactly one `(domain, n)`, and
every value in each domain is reached exactly once — and it degenerates correctly to a
single domain, which is what keeps `apply_mutation()` the function it has always been.

`case_max` is therefore the sum of the domains' sizes, and the length domain's `0..capacity`
leaves
out the frame's own length, because resizing a frame to the length it already has changes
nothing — the same reason a mask of `0` is not one of the 255 cases per byte offset.

A length case reports `"type":"MUT_LEN"` with `was` and `len` instead of
`idx`/`mask`/`before`/`after`, and changes only the length: not one octet of the frame as
built moves. Growth is filled with a constant, deliberately — what the new octets *say* is
a domain of its own and not this one, and mixing the two would mean neither is enumerated.

### Lengths the driver will not send

The domain is the caller's capacity, not what the local driver will accept.
`wpa_driver_nl80211_send_mlme()` refuses anything shorter than the 24-byte 802.11 header, so
for a management frame the cases below 24 are built, reported and then dropped at the driver
with `send_auth_reply: send failed`. They are kept in the domain anyway — whether a length
leaves this machine is a property of this driver, not of the length — and the ledger counts
them separately so the log never implies they reached a peer.

## Stage multiplicity

The sweep delivers one case per occurrence of a stage. A stage the state machine produces
exactly once per peer therefore gets exactly one case per session, however long the run is.
How many times a stage occurs is a domain of its own — `0..N` — and it is pinned at the
constant 1 by the state machine, not by anything the mutation engine can reach: the engine
changes octets of a frame, and this is about whether there is a second frame at all.

`FUZZ_REPEAT_<STAGE>` unpins it:

```sh
FUZZ_REPEAT_EAPOL_M1=3 ./hostapd hostapd-wpa3.conf     # message 1/4, four times
FUZZ_REPEAT_SAE_COMEBACK=2 ./hostapd hostapd-wpa3.conf
```

The budget is per `(stage, peer)` and is spent down, never refilled within a session, so a
stage is re-issued a bounded number of times no matter how often its guard is evaluated.
That bound is the point: unbounded re-issue starves every stage behind it, which is the
same failure `FUZZ_HOLD_*` exists to prevent. A second bound clamps the value at 32, so a
mistyped variable cannot turn a run into one stage repeated forever. The default is 0, so a
binary with this compiled in behaves exactly as it did until a budget is set.

| stage | frame |
| --- | --- |
| `eapol-m1` | EAPOL-Key message 1/4 — `SM_STATE(WPA_PTK, PTKSTART)` |
| `eapol-m3` | EAPOL-Key message 3/4 — `SM_STATE(WPA_PTK, PTKINITNEGOTIATING)` |
| `group-m1` | group rekey message 1/2 — `SM_STATE(WPA_PTK_GROUP, REKEYNEGOTIATING)` |
| `sae-comeback` | SAE comeback request — the branch that asks a station for a token |

`fuzzing/stages/stages.py --check` fails if that table and the `fuzz_stage_repeat()` call sites
disagree, and the [inventory](#the-inventory) announces the set, so a stage nobody set a
budget for can still be told apart from a stage this build does not have.

### The budget resets with the session

`ap_free_sta()` drops the peer's budgets. Without that, a station that reconnects — which
against a real one is continuous — would find its budget already spent, and every session
after the first would deliver each stage exactly once. That is the pinned behaviour this
exists to lift, reappearing silently after the first reconnect, and it would look identical
to a stage that does not repeat at all.

`FUZZ_DISCONNECT_MS` interacts with this directly. A forced disconnect ends the session, so
it resets the budget *and* destroys any occurrence that had not happened yet: with
`FUZZ_DISCONNECT_MS=1000`, a repeat of a stage that only occurs late in the exchange may
never be reached. Set `FUZZ_DISCONNECT_MS=0` when repeating anything at or past the 4-way
handshake, for the same reason that flag exists at all.

### Finding the sites

The sites are enumerated, not chosen:

```sh
python3 fuzzing/stages/oneshot.py .                       # every one-shot transmit branch
python3 fuzzing/stages/oneshot.py . --file src/ap/wpa_auth.c
```

Two shapes are searched for. The first is a **latch** — a branch whose condition reads a
per-peer field, whose body transmits, and which writes that same field. A field tested
before sending and set after it is the code saying "once per peer" in the only way C has of
saying it. The second is a **transmitting state-machine state**: `SM_STATE()` sends and then
moves on, so the stage occurs once and there is no latch field to find, because the latch is
the state variable. Missing that second shape would have cost the entire EAPOL exchange.

78 sites come out: 3 transmitting states and 75 latched branches. Four are guarded today.
The rest are listed so that placing another is a decision about effort rather than a search.

## Targets

| target | where | frame |
| --- | --- | --- |
| `probe_resp` | `src/ap/beacon.c` | probe response |
| `assoc_resp` | `src/ap/ieee802_11.c` | association response |
| `deauth` | `src/ap/ieee802_11.c` | deauthentication |
| `eapol` | `src/ap/wpa_auth.c` | EAPOL-Key |
| `auth-sae`, `sae-send-commit`, `sae-send-confirm`, `handle-auth`, `auth-ft-finish`, … | `src/ap/ieee802_11.c` | authentication; the name is the caller's own debug label, so SAE commit and confirm sweep independently |
| `sta-auth-sae-commit`, `sta-auth-sae-confirm`, `sta-auth-fils`, `sta-auth-8021x`, `sta-auth-eppke-1`, `sta-auth-eppke-3`, `sta-auth` | `wpa_supplicant/sme.c` | the station's own Authentication frame body, before the driver wraps it |
| `sta-assoc-req` | `wpa_supplicant/sme.c` | the Association Request's element chain |
| `sta-eapol` | `src/rsn_supp/wpa.c` | the supplicant's EAPOL-Key frames — messages 2 and 4, and the group reply |
| `sta-ext-sae-commit`, `sta-ext-sae-confirm`, `sta-ext-8021x-auth` | `wpa_supplicant/sme.c` | the same frames on the external-auth (SAE offload) path, where the station builds the whole management frame itself |
| `mesh-plink`, `mesh-plink-ampe` | `wpa_supplicant/mesh_mpm.c` | mesh peering Open / Confirm / Close |

Each target keeps its own case counter, so a slow-moving target is not starved by a busy
one.

### Direction

The first group travels **AP to station**. The rest travel **station to AP**, or between
mesh peers, and they exist because an AP-only harness is a spotlight one level up from the
ones this document keeps warning about: the whole set of parsers on the AP side is
unreachable, not because it is hard to reach but because nothing was pointed at it.

`src/common/fuzz.c` needed no change for this. It was already direction-agnostic — a
label, a frame kind, a buffer — and nothing in it is AP-specific.

Two of these reach differently on purpose. A secured mesh MICs the peering body, so
`mesh-plink-ampe` is mutated before the MIC and at a fixed length; `mesh-plink`, with no
MIC to keep, gets the length and element domains as well. One label over both would report
a reach the run did not have.

## What the victim read

Everything above this line is the transmit side. It is all true, and not one number in it
can tell a case space that is sweeping from one that is being **discarded at the door** —
the walker stopped at item two, the frame was dropped before any handler ran, the daemon
never dispatched it. From the transmit side those two runs look identical: same frames,
same counters, same green run, same speed.

Two figures from elsewhere on this product, for the size of the hazard rather than for
anything they found: a generator aimed at the DPP attribute stream had **206 of 257** cases
rejected before any handler ran, and one aimed at WPS reached the end of the parser **zero
times in 40** while reporting a clean sweep.

So the receiver says what it read. `CONFIG_FUZZ_REACH=y` compiles `src/common/fuzz_reach.c`
into a build, and the hooks sit at the **exits of the receive-side walkers**:

```
[fuzz] {"msg":"reach","daemon":"hostapd","parser":"elems","seq":412,
        "n":143,"got":143,"whole":1,"span":"000f686f737461702d66757a7a..."}
```

`n` is the span the walker was handed and `got` is how far into it the walker got. `got ==
n` is a completed walk; `got < n` is a walk that stopped, and **where** it stopped is the
receive-side counterpart of the `pre`/`post` depth every element case already reports from
the transmit side.

### It is a second flag, not a corner of the first

`CONFIG_FUZZ_REACH` is separate from `CONFIG_FUZZ` on purpose. The victim in the inverted
topology must not mutate — a run with both ends mutating has no reference in it — so it
cannot be a `CONFIG_FUZZ` build, and until there were two flags there was no build that
could both *be* a victim and *say what it read*. A reach build transmits exactly what a
stock build transmits.

That is checked rather than argued. `fuzzing/reach/verify_reach.py` compiles
`ieee802_11_common.c` twice — once as it stands with the flag off, once with the
`fuzz_reach()` lines deleted — and compares the generated code. They are identical.

```sh
cd hostapd && cp defconfig .config && echo CONFIG_FUZZ_REACH=y >> .config && make
```

The topology scripts say which kind of victim they were handed, and a run without one is
reported as `NOT MEASURED` rather than as a zero.

### The parse is matched to the case by its octets

The receiver cannot know which case it is holding. It has no case counter, no target label,
and no way to be told one without the harness putting something on the air a real peer
would not send. So each parse quotes **the span it was given** and the ledger looks for it
in the frames the run transmitted. A parse that matches is **attributed**; one that does
not is **ambient** — the receiver parses ordinary traffic too, and a report that counted
every parse would say the run was read perfectly while every mutated frame was being
dropped at the door.

Quoting the whole span rather than a fingerprint of it was learned from a live run, and
it is worth knowing why, because it is a fact about this product rather than about this
harness. **A station's association request is not the buffer the station built.**
wpa_supplicant hands the driver its own elements; mac80211 builds the frame with *its*
elements in front of them and a WMM element after them. Of the 143 octets the AP walked,
85 were what the station sent — in the middle. Matching the head found nothing. Matching
the head and the tail found nothing. Both reported every association request of the run as
a frame nobody read, which is the exact wrong answer from an instrument whose job is to
say when nobody read a frame.

So the match is an **overlap**, not a containment: 16-octet windows of the span taken every
8 octets, so any common run of 23 octets or more is found, and 23 octets of agreement
between two frames is not chance. A match that is not the whole span is counted apart and
reported — a walker that was handed *more* than the run sent is a different fact from one
handed exactly it.

Measured over one run's saved logs, 94 element spans:

| matching | attributed |
| --- | --- |
| containment, or the first 16 octets, or the first and last 16 | **0** |
| 16-octet windows every 8 | **42** |

The contrast is the useful half. All 27 EAPOL-Key spans in the same run match *exactly* —
that buffer is the one the station built. **The wrapping is mac80211's**, and it is there
for every frame the kernel assembles, so any target on a management path inherits it.

The window of recent cases is 16 deep. A hwsim frame is parsed within microseconds of being
sent, and a deeper window would start crediting a parse to a case from a second ago — most
often exactly where the run is repetitive.

Which means the attribution is a **live** measurement: `monitor_fuzzing.py` reads the
subject and each victim as they speak, and the interleaving is what places a parse. Running
`ledger.py` afterwards over a saved subject log and a saved victim log separately will
report the parsers and their states correctly and attribute nothing, because the two files
carry no common clock. The ledger JSON a live run writes carries the attribution for a
campaign to union.

### A target that was never read is a failure

Measured, two minutes, a fuzzing station against a reach-instrumented AP:

```
  per target        sent     read   through
  sta-assoc-req       44       33         33
  sta-eapol          101       27         27
```

`sta-eapol` is what this is for. **Three quarters of that target's cases never reached the
KDE walker at all** — `wpa_receive()` rejects on the key info, the type or the length
before the key data is parsed — and nothing anywhere in this harness could previously tell
those 74 cases from 74 that swept. A target that reaches *nothing* gets a louder form of
the same row — the shape of it, with whichever target it happens to be:

```
  TARGETS WHOSE CASES WERE NEVER READ
    <target>         <n> cases sent, 0 reached an instrumented parser
  This is a FAILURE and is printed as one.
```

Before this existed, that row was indistinguishable from a target that was working
perfectly. **THE LIMIT**, printed beside it every time: "never read" means no *instrumented*
parser read it. A target whose frames no hooked walker handles reads zero here and is a gap
in the instrument, not in the sweep.

Which is why the run also announces how big the instrument is. `fuzzing/reach/reach.py`
counts every function in the tree that walks an element chain — through the shared
`for_each_element*` macros, so the denominator is a property of the tree — against how many
of them report:

```
  element walkers in the tree: 20, instrumented: 1
    the other 19 are NOT MEASURED.
```

A reach figure quoted without that ratio reads as a claim about the product when it is a
claim about one parser.

### The roster is generated, and the rule is enforced

Four parsers carry hooks today — `elems` (`__ieee802_11_parse_elems`), `kde`
(`wpa_parse_kde_ies`), `wps` (`wps_parse_msg`) and `dpp` (`dpp_check_attrs`) — and
`src/common/fuzz_reach_targets.h` is generated from their call sites, with each label's
**build condition** derived the same way `targets.py` derives a transmit label's. So a
binary without `CONFIG_WPS` announces `wps` as *absent from this run's binaries* rather
than reporting it never reached: the same four states the transmit side uses, for the same
reason.

```sh
python3 fuzzing/reach/reach.py . --check    # fails when the tree has moved
python3 fuzzing/reach/reach.py . --gaps     # the element walkers with no hook
```

One rule is enforced rather than reported: **every `return` in a hooked function passes
through the hook.** A walker with an unmarked early return reports fewer parses than
happened, and every one it fails to report looks like a frame that never arrived. Upstream
adding a `return -1` to a parser we hook fails `--check` instead of quietly halving the
number.

### Where the victim is not ours

The weaker signal needs nothing compiled in and puts nothing new on the air: whether the
victim *said* anything after a case.

```
  WITHOUT INSTRUMENTATION, the signal is what the victim
  said: 312 lines, after 103 of 145 cases.
  THE LIMIT: a log line is not a parse.
```

It is in the report because it is all there is where the victim is a binary somebody else
built, and its bound is printed beside it because a number gets quoted without its bound
otherwise.


## How many identities one peer presents

[More than one peer](#more-than-one-peer) sweeps concurrent peers with N real
stations. Underneath that is a cheaper and larger domain, and it is the one that
decides whether a second attempt at anything ever happens: **the number of distinct
source addresses one peer presents.** The state that gates a second attempt on this
product is keyed by address, not by radio — a WPS registrar's device list, a P2P peer
table with its own eviction, SAE's comeback slots, a DPP Controller's connection
list, and `nan_ndp_attr_handle_req()`, which refuses a second request from a peer
already in progress. **One fixed address gets exactly one request through per run**,
and everything behind the second is unreachable however many cases run.

```sh
FUZZ_ADDRS=4 ./fuzzing/topology/sta-vs-ap.sh 10
```

### Neither extra vifs nor injection

Both obvious ways are wrong. N vifs is N stations — that is the multi-peer topology
again, at N times the cost, answering a different question. And injection cannot be
done from a hooked daemon at all: **an injected frame whose `addr2` matches no local
interface is dropped by mac80211 before it leaves the radio**, silently, because it
never resolves a channel context.

So the domain goes where this product already changes its address on purpose — MAC
address randomisation. The frame still leaves through the daemon's own vif, which is
exactly what keeps that drop out of reach, and the sweep turns a coin toss into an
enumeration.

It needs the station's configuration as well as the environment variable, and the run
script adds both when (and only when) `FUZZ_ADDRS` is set:

```
mac_addr=2             change it per connection, keeping the OUI
rand_addr_lifetime=0   and change it EVERY connection — the default is 60 seconds,
                       which at this cadence is one identity per few hundred cases
```

A run that sets `FUZZ_ADDRS` and does not get this says so rather than looking like it
worked:

```
SOURCE ADDRESSES -- how many identities one peer presented
  asked for: 4 (FUZZ_ADDRS)
  AND NOT ONE ADDRESS EVER CHANGED.
```

### What varies, and what deliberately does not

The value is **the case number**, placed in the address's varying octets, and nothing
else. No mixing constant: what the tables behind this are keyed on is the address
being *different*, and a counter is different by construction, reproducible across
runs, and printable in a repro record.

Octets 1..5 vary. **Octet 0 is never touched** — it carries the field's structure
(unicast, locally administered) and the caller's own picker has just set it;
re-applying that rule here would be a second copy of a rule that already exists. The
consequence is reported rather than hidden: where the caller's style randomises the
OUI, the run presents *more* distinct addresses than the domain asked for, and both
numbers are printed.

**The last octet is never zero**, and that is load-bearing rather than cosmetic. Every
`mac80211_hwsim` radio in these topologies is addressed `02:00:00:00:NN:00`, so an
address this produces cannot collide with one. A station that took its AP's address
would not be a case; it would be a broken rig that looked like one.

### The roster, and why the hook is not where it belongs

The tree picks a source address in exactly two functions — `random_mac_addr()` and
`random_mac_addr_keep_oui()`. One place to hook, covering every caller. It cannot be
hooked: `src/utils/common.o` is linked into `hostapd_cli` and `wpa_cli`, which do not
link the engine, so the call would not resolve.

So the hook sits at the **callers**, six identities across four files, and
`fuzzing/source/sources.py` is what replaces the single point:

```sh
python3 fuzzing/source/sources.py .            # the identities and their guards
python3 fuzzing/source/sources.py . --check    # fails when the tree has moved
```

It refuses a function that asks the tree for an address more times than it reports,
and separately refuses any function outside those two that open-codes the
locally-administered bits — that second rule is what makes "every picker is hooked" a
statement about the tree rather than about a list someone wrote down. Each identity
carries its build condition, so `own-p2p-dev` in a build without `CONFIG_P2P` reads
*absent from this run's binaries* rather than *never varied*.

Every label begins `own-`, and the generator refuses one that does not. That is not
cosmetic: the verifier's ground truth is the label's *string* surviving into the
object its call site compiles to, and **the compiler merges a short string that is a
suffix of a longer one** — a label of `"sta"` is invisible in any object that also
holds `"...sta"`, which `wpa_supplicant.o` does. (Looking for the call site's
*function* in the linked binary instead does not work either: `gas_query_set_sa()` is
static and gets inlined away.) A naming rule that exists for a checker is a rule that
will be broken the first time nobody remembers why, so the generator remembers.

### Measured, and what it costs

Two minutes, `FUZZ_ADDRS=4`, a fuzzing station against a stock AP: 4 distinct
addresses over 15 changes, and the AP's own log shows all four as separate stations.

**THE PRICE is large and is printed beside the number.** An address change takes the
interface down and up — `nl80211_set_mac_addr()` clears the flags, sets the hwaddr and
brings it back. The same two-minute rig went from **145 frames to 22** with the domain
on. A case rate is not comparable across runs with different domains, and a campaign
unioning them has to say which it was.

**THE LIMIT:** this is occupancy and eviction, which is what those tables are keyed
on. It does not claim to exercise how they *hash* — the values are a counter, so
adjacent identities may land in adjacent buckets.


## Which build the numbers came from

Every domain above says what a run **swept**. This one says what existed to sweep.

A sweep built without a flag reports clean on code the binary never contained, and it
reports it in exactly the same words as a sweep that found nothing. Those are opposite
results. Underneath the 591 run-time options `hostapd/config_file.c` parses is a second
registry: **272 compile-time flags across the two Makefiles**, and which of them were on
decides whether a parser is in the binary at all.

So each binary announces its own, in the inventory line it already sends:

```
[fuzz] {"msg":"inventory","daemon":"hostapd","version":"2.13-devel-fuzz-2026-11-22",
        "config":["CONFIG_ACS","CONFIG_FUZZ",...],
        "config_roster":[["CONFIG_ACS",3,3,0,0],...]}
```

and the ledger prints it first, before any number it would otherwise qualify:

```
BUILD -- what existed to sweep
  hostapd          2.13-devel-fuzz-2026-11-22
                   25 flag(s) on, of 191 this Makefile tests
                   9 NOT set by upstream defconfig
                     CONFIG_ACS CONFIG_FUZZ CONFIG_IEEE80211AC ...
                   4 set by upstream defconfig and NOT here
                     CONFIG_DPP CONFIG_DPP2 CONFIG_EAP_GTC CONFIG_OWE
                   63 flag(s) it cannot report either way: they reach
                     no -D and steer the link only.
```

The two directions are different claims and both matter. **A finding behind a flag that
ships commented out is a weaker claim than one in a default build**, so the run has to be
able to say which it made — that is the first list. The second is the one that is easy to
miss: parse surface upstream ships *on* that this build left out, which a run cannot have
covered whatever its numbers say.

### What the build cost this run

Every roster this harness has — transmit targets, [source identities](#how-many-identities-one-peer-presents),
[instrumented parsers](#what-the-victim-read) — already reports *absent from this build* as
one of its four states. This is the sentence that follows it:

```
  WHAT THE BUILD COST THIS RUN
    CONFIG_IEEE8021X_AUTH               3  send-8021x-auth-reply sta-auth-8021x ...
    CONFIG_P2P                          3  own-gas own-p2p-dev own-p2p-iface
    CONFIG_WPS                          1  wps-msg
    CONFIG_DPP+CONFIG_DPP2              1  dpp-tcp
```

The guard each roster entry carries is evaluated against the flag set the binary
announced, and when it comes out false the report searches for the flag that **alone**
would bring the entry back. Turning every named flag on at once is not a valid probe: a
guard with a `!defined()` in it is not monotone, and that was the first thing this got
wrong. An entry no flag explains — the wrong daemon, or a guard with no flag in it — is
counted apart rather than blamed on one.

Guards arrive in the log as C preprocessor expressions and are **parsed, never `eval`'d**.
A log is a file from somewhere else.

### The shipped configurations are narrower than upstream's

The largest thing this turned up is about this harness, not about hostap. `defconfig-fuzz`
is not `defconfig` plus the hooks:

| Off here, on in upstream `defconfig` | What it costs |
| --- | --- |
| `CONFIG_WPS` | `wps_parse_msg()`, one of the four instrumented parsers, is in **neither** binary. `wps-msg` has no call site |
| `CONFIG_DPP`, `CONFIG_DPP2` | `dpp_check_attrs()`, another of the four, likewise. `dpp-tcp` has no call site |
| `CONFIG_P2P`, `CONFIG_INTERWORKING`, `CONFIG_HS20`, `CONFIG_MBO` | `own-gas`, `own-p2p-dev` and `own-p2p-iface` — **three of the six source identities** — exist in no binary of this configuration |
| `CONFIG_TDLS` | `sta-tdls` has no call site |
| `CONFIG_OWE` | the OWE Diffie-Hellman Parameter element is neither built nor parsed |

Every one of those was reachable before as *absent from this build*, in the same four-state
table that has been there since the target roster. What was missing was the word *why*.

### Every difference from upstream carries a reason

`defconfig-fuzz` is a point in the flag space and used to be an undocumented one. Each of
the **52 settings** on which the two fuzz configs differ from the upstream defconfigs now
carries a `# WHY` line in the file, and `fuzzing/config/config.py --check` fails on a delta
with no reason **and** on a reason whose delta has gone away, so neither side rots.

That check paid for itself immediately: both files set `CONFIG_INTERNAL_LIBTOMMATH` with a
reason about bignums, and it is **inert** — its `-D` sits inside
`ifeq ($(CONFIG_CRYPTO), internal)` and neither build sets `CONFIG_CRYPTO`, so the option is
set and never reaches the compiler. Both reasons now say so.

### Three flags that do not compile on their own

These read as a broken checkout and cost an afternoon each, so they are recorded as their
**structural cause** — a member declared under one flag and read under another — and the
cause is re-derived from the tree, so the record fails loudly when upstream fixes it rather
than going on telling the next person a lie:

| Flag | Member | Declared under | Read without it |
| --- | --- | --- | --- |
| `CONFIG_PASN` | `pasn->uncompressed` | `CONFIG_TESTING_OPTIONS` in `src/pasn/pasn_common.h` | `src/pasn/pasn_initiator.c:642` |
| `CONFIG_INTERWORKING` | `ssid->roaming_consortium_selection` | `CONFIG_HS20` in `wpa_supplicant/config_ssid.h` | `wpa_supplicant/interworking.c:1661` |
| `CONFIG_IEEE80211AX` / `BE` | `conf->he_oper_chwidth`, `conf->eht_oper_chwidth` | `CONFIG_IEEE80211AX` / `BE` in `src/ap/ap_config.h` | `src/ap/ctrl_iface_ap.c:851`, `:881` |

The third is why `defconfig-fuzz` forces AC + AX + BE together: **upstream does not build
with its own defconfig at this pin.**

### The limits, stated

* This says what the **binary** was built with, not what a `.config` asked for. The Makefile
  derives a great deal: `CONFIG_IEEE8021X_EAPOL` is absent from
  `wpa_supplicant/defconfig-fuzz` and on in the build, because the EAP methods set it.
* **79 of the 272 flags reach no `-D` of their own name** and steer only which objects are
  linked. No binary can report them. For those, absent from the on-list means *cannot tell*,
  not *off* — and the roster carries a `witness` column so the report can say which.
* A flag tested for its **value** rather than for being set — `CONFIG_TLS=openssl` — is
  marked as such and never reported on or off, because on/off is the wrong question about it.
* Two runs of the same daemon built differently, unioned into one log, make every number a
  sum over code that was not the same code. The ledger says **TWO BUILDS UNDER ONE NAME**
  when it sees that; nothing else here would notice.


## Phasing

Separate counters are not enough, because the targets are **stages of one exchange**.
Whichever stage first breaks the exchange starves every stage behind it: the station never
gets far enough for those frames to be sent, so their case space is unreachable no matter
how long the run goes.

Measured over ten-minute runs against two unrelated stations (full data in
`fuzzing/live/RESULTS.md`). A MikroTik hAP ax² in station mode, RouterOS 7, on
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

## Configuration axes

The engine mutates octets of frames the running configuration caused hostapd to build. It
cannot make a frame exist. So a frame that no configuration in the campaign constructs is
not under-fuzzed — it is **absent**, and no length of run will reach it. Against a real
ten-minute run, six of the fourteen target labels were reached and eight were never sent
once.

Widening that is a matter of running more than one configuration. The unit is a **run**:
one option moved, everything else held, the [coverage ledger](#the-inventory) recording
what reached the air. A family is covered when every member of it has been the setting of
some run.

### What a config line is worth, measured

Two minutes each, same harness, a fuzzing hostapd against two stock stations. The left
column is a plain WPA3-SAE config: `hw_mode=g`, no `ieee80211n`, nothing optional.

| | plain | plus five lines |
| --- | --- | --- |
| element ids built | **7** of 179 | **13** of 179 |
| targets reached | 6 of 28 | 6 of 28 |

The five lines are `ieee80211n=1`, `wmm_enabled=1`, `rrm_neighbor_report=1`,
`rrm_beacon_report=1`, `time_advertisement=2`, and what they add is
`HT_CAP`, `HT_OPERATION`, `RRM_ENABLED_CAPABILITIES`, `TIME_ADVERTISEMENT`, `TIME_ZONE`
and the WMM `VENDOR_SPECIFIC`. Nearly double the element surface for five lines.

**The target count did not move**, and that is the point of the distinction. Configuration
widens what is inside the frames; it does not change which frames get sent. The targets a
hostapd run never reaches need a different direction or a different protocol, not more
config: twelve of them are station-side and two are mesh, so no hostapd configuration
reaches them at all.

`hw_mode` is the single largest one. On `g` there is no VHT, HE or EHT element to mutate,
which is where the recent upstream out-of-bounds fixes live — `check_valid_he_mcs()`,
`get_max_nss_capability()`, the Multi-Link parsing. A second profile on `hw_mode=a`,
`channel=36`, `ieee80211ac=1`, `ieee80211ax=1` is one config change for the largest block
of surface a 2.4 GHz run cannot have.

Two things that do not work in the hwsim topologies: `country_code` with `ieee80211d=1`
fails with `Failed to set country code`, because the namespace has no regulatory domain
(use `fuzzing/live/run_live.sh` on a real adapter for those), and `ocv` and
`bss_transition` are rejected outright unless the build has `CONFIG_OCV=y` and
`CONFIG_WNM_AP=y`. Part of the surface is a defconfig change, not a config line.

Which options, and which values, are both derived rather than chosen:

```sh
python3 fuzzing/axes/axes.py .                  # the axis list, nearest the builders first
python3 fuzzing/axes/axes.py . --all            # including those with no derivable domain
python3 fuzzing/axes/profiles.py plan .         # what a campaign would run
python3 fuzzing/axes/families.py .              # the registries an option draws values from
python3 fuzzing/axes/decls.py . <field>         # what a field's declaration permits
python3 fuzzing/axes/reach.py . <field>         # how far it sits from a frame builder
```

The options come from the `os_strcmp()` chain in `hostapd_config_fill()` — all 592 of them,
so an option added upstream appears here on its own and one removed disappears. The domains
come from the declarations and from the registries the parsers consult: a `:1` bitfield
accepts two values, an `enum` accepts its members, `wpa_key_mgmt` accepts the 22 names its
parser compares against, `rsn_pairwise` the 13 its cipher parser does. Nothing in `fuzzing/axes/` is
a list of interesting values someone typed.

A domain too large to enumerate over the air is reduced, and the reduction says what it
leaves behind rather than pretending to be a sample of what matters:

| tier | what it runs |
| --- | --- |
| `FULL` | every value in the domain |
| `LADDER` | the edges of the domain, the edges of each width it could be narrowed to on the way into an element, and the field's own default |
| `STRIDE` | a prime stride with a per-run offset, so the union over runs is the whole domain — deferral, not sampling |

49 axes come out `FULL` and 270 `LADDER`, 6227 settings in all. The default selection — the
`FULL` tier, read no more than one call from a frame builder — is 44 axes and 391 runs.

### Distance, not a filter

Each axis is reported with its distance from a function that writes octets into a frame:
`d0` means the field is read inside one, `d1` one call away, and so on, measured on the
undirected call graph because both directions matter. Downwards is a builder consulting a
helper. Upwards is the decision to build the frame *at all*, which is the stronger case —
a field read there can make a frame exist rather than merely change its contents.

Distance orders the campaign. It does not filter it. A filter is a list of things someone
decided not to look at, and a wrong exclusion is permanent and silent: the frame family it
drops is never swept by any run and nothing in the output says so, while a wrong inclusion
costs one run. The only thing reported as out of reach is a field read nowhere outside the
parser, which is a fact about the tree rather than a decision about the field.

### Running a campaign

```sh
sudo ./axes/run_profiles.sh --minutes 2                  # the default selection
sudo ./axes/run_profiles.sh --option 'sae_|owe_' --minutes 3
./axes/run_profiles.sh --report-only                     # union what already ran
```

Each profile gets its own run and its own ledger (`monitor_fuzzing.py --ledger-json`). The
report unions them and names, for each target label, a setting that reached it — or says
plainly that nothing did. A configuration hostapd refused is recorded as refused and not
as a run that reached nothing: a configuration that never started is a fact about the
configuration, and folding it into the total would turn a broken profile into evidence that
a target is unreachable.

This wants an interface it can own for the campaign; `mac80211_hwsim` is the sane place for
it. Most of these configurations are not ones to point at a radio something else is using.

### Compile-time gates on a domain

Some domains are bounded by a build flag rather than by anything a `.conf` can say, and
`fuzzing/axes/families.py` reports the gate alongside the registry. The group registry is the clear
case:

| | groups |
| --- | --- |
| the tree can instantiate | 20 — ten FFC, ten ECC |
| `dragonfly_suitable_group()` accepts | 7 |
| reachable in a default build | **3** (19, 20, 21) |

Fourteen of the twenty are behind `ALL_DH_GROUPS` or an OpenSSL brainpool NID, and
`sae_set_group()` skips the suitability filter entirely under `CONFIG_TESTING_OPTIONS`. The
field on the air is a `u16`. Building with those flags is what turns three reachable values
into twenty — a property of the build, not of the sweep, which is exactly why it is worth
printing rather than discovering later.

## Output

**Every line prefixed `[fuzz] ` is a JSON object with a `msg` key.** That is the contract:
the prefix means "this line is for the consumer", so nothing has to sniff for `{`, and a
`msg` a consumer does not recognise is ignorable by construction — a message added later
breaks nobody. A `[fuzz] ` line that does not parse is therefore a real fault, and the
monitor reports it instead of silently swallowing it.

Two lines per mutated frame:

```
[fuzz] {"msg":"progress","case_id":1234,"case_max":2550,"target":"auth-sae","state":"mutating"}
[fuzz] {"msg":"fuzz","target":"auth-sae","idx":4,"type":"MUT_BYTE_XOR","mask":150,
        "before":0,"after":150,"hdr":24,"data":"b0003a01..."}
```

`idx` is the offset **within the fuzzable region**, not the frame; `hdr` is the skipped
header, so the octet that moved is at `data[hdr + idx]`. `data` is the whole frame,
headers included, as transmitted.

`peer` says which peer the frame is for — the destination address a management frame
already carries, or a one-shot hint from the call site for a frame that has no address of
its own. Absent when neither applies: no value is inferred.

`opset` says which **case space** the `case_id` indexes: the operator-set version, how
many domains exist, the tier and the stride offset. Every `progress` and `fuzz` message
carries it. A `case_id` is an index into an enumeration, and under a different enumeration
it reproduces a different frame *without complaining* — so a repro record carries the
`opset` it was written under and `monitor_fuzzing.py --replay` refuses a record from
another one. This is the hazard already documented here for `order` and for
`CASES_PER_OFFSET`, with more axes.

`from` and `read` are on every field case. `from` says where the row came from: a member
of a struct the generator could read, an offset **solved for** in this frame, or the layout
an Action frame's category selects. `read` says whether the receiver on the other side
of this target reads those octets at all, with `-1` for "nothing here can say". `chain` is
on every synthesised item, because the five TLV formats have overlapping identity spaces
and a number without its chain is unreadable. All four are described under
[The frame past the struct](#the-frame-past-the-struct).

`frame` says what the buffer **is**, one of `mgmt`, `eapol`, `action`, `body` or
`stream`, and every mutation message carries it. A consumer that instead guesses the layout from the target's name is
wrong the first time someone names a call site something sensible, and silently so: a
mutated frame failing to dissect is an ordinary outcome here. `body` means a frame body
with no header of its own, because the driver builds one; its first octet is an element id
or an Action category, and read as a frame control field it will happily yield a subtype
and a fixed-field length that are arithmetic on unrelated bytes.

Because the mutation is a single XOR, `hdr` is also what lets a consumer recover the frame
**as hostapd built it** — undo `mask` at that offset. That is the only record of what the
running configuration actually emits, as opposed to what the sweep turned it into.

| `msg` | when | fields |
| --- | --- | --- |
| `inventory` | once, before any other message | `targets`, `stages`, `config`, `layouts`, `var_fields`, `readers`, `chains` |
| `repeat` | a one-shot stage was re-issued | `stage`, `n`, `of`, `peer` |
| `fuzz` (`type":"MUT_LEN"`) | a length case | `was`, `len` instead of `idx`/`mask`/`before`/`after` |
| `fuzz` (`type":"MUT_ELEM"`) | a synthesised element or attribute | `chain`, `eid` or `ext_id`, `body`, `pos`, `npos`, `at`, `copies`, `was`, `len` |
| `fuzz` (`type":"MUT_CHAIN"`) | the chain's shape changed | `op`, `i`, `j`, `nelem`, `was`, `len` |
| `fuzz` (`type":"MUT_FIELD"`) | a named field took a value from its domain | `field`, `from`, `read`, `at`, `width`, `tier`, `before`, `after`, `len` |
| `fuzz` (`type":"MUT_PATTERN"`) | an opaque field was filled | `field`, `from`, `read`, `at`, `width`, `pattern`, `len` |

`peer` appears on `progress` and on every `fuzz` message whenever it is known, so a run
with several peers in flight says which one received which case.
| `progress` | once per frame, per target, always | `case_id`, `case_max`, `target`, `state`, `order`, `opset`, `fields` |
| `fuzz` | the mutation that was applied | `target`, `order`, `idx`, `type`, `mask`, `before`, `after`, `hdr`, `frame`, `data` |
| `abandoned` | a case was announced but its frame was never sent | `target`, `case_id` |
| `resume` | a target started at `FUZZ_START_…` rather than the warm-up | `target`, `case_id` |
| `bad_env` | a `FUZZ_*` value was not an integer and was ignored | `name`, `value` |
| `disconnect` | the forced disconnect fired (`src/ap/wpa_auth.c`) | — |
| `reconnect` | the station cycled its association (`wpa_supplicant/wpa_supplicant.c`) | — |

`state` says what the target did with the case it just announced, because `case_id` alone
does not:

| `state` | meaning |
| --- | --- |
| `warmup` | `case_id < 0`: an unmutated frame, so a client can associate before anything is corrupted. Nine of these per target. |
| `mutating` | the case ran; a `fuzz` message follows |
| `held` | `FUZZ_HOLD_<TARGET>` is set: unmutated on purpose, and no case consumed |
| `done` | the sweep reached `case_max` and stopped, reporting a constant `case_id` |

### The inventory

The per-target case counters are created lazily, on a target's first transmitted frame, so
a target the configuration never causes hostapd to build is simply **absent** from the
output — and absent looks exactly like "this build has no such target". Those are very
different facts: the first is a configuration that needs changing, the second is nothing at
all.

`inventory` is emitted once, ahead of everything else, and lists every target label the
tree can emit:

```
[fuzz] {"msg":"inventory","targets":["assoc_resp","auth-fils-finish","auth-ft-finish",
        "auth-sae","auth-sae-reflection-attack","deauth","eapol","handle-auth",
        "pasn-sec-profile-reject","probe_resp","sae-commit-override","sae-send-commit",
        "sae-send-confirm","send-8021x-auth-reply"]}
```

A consumer subtracts the targets it saw a `progress` line for from this list; what remains
was never reached. Against a measured ten-minute run that difference is **8 of 14** —
eight labelled transmit paths that the stock `hostapd-wpa3.conf` never takes, and that no
length of run would have reached.

The message carries a `stages` array alongside `targets`, listing the stages
[`FUZZ_REPEAT_<STAGE>`](#stage-multiplicity) will honour, for the same reason: a stage
nobody set a budget for emits nothing, and from the outside that is indistinguishable from
a stage this build does not have.

Both lists are compiled into `src/common/fuzz.c` and are **generated, not written**. The
targets are extracted from the call sites of `apply_mutation()`,
`apply_mutation_defer_log()` and the `send_auth_reply()` wrapper that passes its `dbg`
argument through; the stages from the `fuzz_stage_repeat()` call sites. A label added at a
call site without being added to its table would be invisible to a consumer, so that is
checked rather than trusted — `fuzzing/ledger/targets.py --check` and `fuzzing/stages/stages.py --check`.

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
  "who": "victim",
  "exit": "killed by signal 11 (SIGSEGV)",
  "returncode": -11,
  "opset": "v6/10d/STRIDE/251@0",
  "replay_env": { "FUZZ_START_AUTH_SAE": 1235 },
  "case": { "msg": "fuzz", "target": "auth-sae", "idx": 4, ... }
}
```

Then `FUZZ_START_AUTH_SAE=1235 ./monitor_fuzzing.py` re-runs that exact mutation on the
first frame of that target — or, better, hand the record back:

```sh
./monitor_fuzzing.py --replay fuzz-repro/20261120T101500Z-victim-auth-sae-1235.json
```

which applies the `replay_env` **and stops** if the binary announces a different `opset`
from the one the record was written under. A `case_id` indexes an enumeration; under a
different one it reproduces a different frame and reads as a flaky crash. `who` says which
process died, because in the inverted direction it is not the one that sent the frame.

---

## How the sweep works

For a fuzzable region of `L` bytes:

```
255 = the XOR masks 1..255
case_max = L * 255
```

`case_id` maps onto `(offset, mask)` exactly once. Masks run 1..255 rather than 0..255
because mask 0 is a no-op, so the 255 cases at an offset are precisely the 255 values that
byte can be changed to — each sent once, none twice. The first 9 frames per target are
left unmutated as a warm-up (`case_id` counts up from -9), so a client can associate
before anything is corrupted. Once `case_id` reaches `case_max` that target stops mutating
and reports a constant `case_id`.

There used to be 268 cases per offset: 5 "set the byte to an interesting value", 8
single-bit flips, then these same 255 masks. The first 13 were all duplicates. A bit flip
is an XOR by a power of two, and setting a byte to `v` is an XOR by `orig ^ v`, so for
every possible original byte each of the 13 repeated a value the mask sweep already
produced — or, where the byte already held `v`, changed nothing at all. Dropping them cost
no coverage and saves 4.9% of every declared space. What those kinds really supplied was
an **order**, and that is kept: see below.

### Which masks come first

The masks are not applied in numeric order. For a byte currently holding `orig`, the
schedule is:

1. the masks that set it to `0x00`, `0x01`, `0x7F`, `0x80`, `0xFF` — that is, `orig ^ v`
2. the single-bit flips
3. everything else, ascending

skipping any mask an earlier rule already emitted. The union is always the whole of
1..255, so the schedule is a permutation and the offset's sweep stays exhaustive; how many
cases each rule contributes depends on `orig`. A byte that already holds one of the
interesting values has no "set it to that" case at all, and spends the freed slot on a bit
flip instead of on a no-op — which is one of the 13 the old scheme wasted.

This matters because `rem` advances slowest under the breadth-first sweep, so these are
passes over the whole frame and a bounded run gets only the first few of them. The
measured ten-minute run below reached `rem` 4: under the old scheme that was the five
interesting values and nothing else, so the order is doing the real work, not the kinds.

### Order: breadth-first by default

**Breadth-first** applies one mutation at every byte offset before trying the next
mutation anywhere. **Depth-first** (`FUZZ_SWEEP_DEPTH_FIRST=1`) runs all 255 mutations at
offset 0, then all 255 at offset 1.

Depth-first localises a crash to one field, which is what you want *after* a crash. It is
the wrong default, because every run against a real station is bounded by the station's
re-join rate rather than by `case_max`:

| cases delivered | offsets reached, depth-first | offsets reached, breadth-first |
| ---: | --- | --- |
| 105 | **1** | all |
| 596 | **3** | all, 4.9 times over |

Those are not estimates. A ten-minute live run delivered 596 `eapol` cases and reached
three byte offsets — EAPOL version, type, and the high byte of the body length. A whole
offset's worth of those cases said "this frame is not an EAPOL-Key", which a supplicant is
required to reject. The key data, the nonce and the RSN IE begin at offset 11 and were
never reached. Full data in `fuzzing/verify/sweep_ordering/README.md`.

**The orders renumber every case**, so a `case_id` recorded under one does not replay
under the other. Both `progress` and `fuzz` carry an `order` field (`"breadth"` or
`"depth"`) for exactly that reason, and `monitor_fuzzing.py` writes
`FUZZ_SWEEP_DEPTH_FIRST` into a repro record's `replay_env` when it applies. Note that
`order` does not distinguish a change to the number of cases per offset, which renumbers
just as thoroughly: the 268 -> 255 change above invalidates every `case_id` recorded
before it.

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
python3 fuzzing/verify/fuzz_verify/fuzz_verify.py .                    # 52 checks: sweep, hold, contract
python3 fuzzing/verify/fuzz_output_contract/fuzz_output_contract.py .  # 4 checks: the output contract
python3 fuzzing/phasing/phase_starvation.py ./hostapd/hostapd
python3 fuzzing/verify/sweep_ordering/verify_ordering.py .             # 19 checks: sweep order
python3 fuzzing/ledger/targets.py . --check                            # the announced labels match the tree
python3 fuzzing/stages/stages.py . --check                             # the announced stages match the tree
python3 fuzzing/axes/verify_axes.py .                                  # 18 checks: the axis list is derived
python3 fuzzing/stages/verify_stages.py .                              # 24 checks: the repeat budget
python3 fuzzing/resize/verify_resize.py .                              # 29 checks: the resize contract
python3 fuzzing/synth/verify_synth.py .                                # 98 checks: element synthesis
python3 fuzzing/tail/verify_tail.py .                                  # 26 checks: the tail case space
python3 fuzzing/reach/verify_reach.py .                                # 67 checks: what the victim read
python3 fuzzing/source/verify_sources.py .                             # 52 checks: distinct source identities
python3 fuzzing/config/verify_config.py .                              # 72 checks: the compile-time axis
python3 fuzzing/layout/verify_layout.py .                              # 101 checks: the frame past the struct
python3 fuzzing/direction/verify_direction.py .                        # 115 checks: the inverted direction
python3 fuzzing/fields/verify_fields.py .                              # 53 checks: the field model and its tiers
python3 fuzzing/peers/verify_peers.py .                                # 38 checks: multi-peer runs
python3 fuzzing/action/verify_action.py .                              # 39 checks: the Action frame labels
python3 fuzzing/ledger/verify_ledger.py .                              # 63 checks: the ledger's own claims
python3 fuzzing/ledger/registries.py . --check                         # the registry tables are not stale
python3 fuzzing/ledger/fields.py . --check                             # the field table is not stale
python3 fuzzing/ledger/minima.py . --check                             # the enforced lengths are not stale
python3 fuzzing/reach/reach.py . --check                               # the reach roster is not stale
python3 fuzzing/source/sources.py . --check                            # every address picker is hooked
python3 fuzzing/config/config.py . --check                             # the flag space, and every defconfig delta has a reason
python3 fuzzing/layout/layout.py . --check                             # the layouts and the read sets are not stale
python3 fuzzing/chain/chain.py . --check                               # the five TLV formats are not stale
```

870 checks, none of which needs a radio. The four topologies below do, and are not among
them; `fuzzing/direction/verify_direction.py` checks everything about them that can be checked
without one, including that each refuses to run with the subject and the victim the wrong
way round.


- 2550 cases for a 34-byte frame = 10 offsets x 255, **zero duplicates**, each offset
  getting each of the masks 1..255 exactly once, lowest mutated byte 24, locking at
  `case_max`.
- No case is wasted: at every offset the 255 cases leave the byte at 255 *distinct*
  values — every value it can hold other than the one it came with — and none of them
  leaves it unchanged. This is the 268 -> 255 change; under the old scheme 13 of the 268
  repeated a value already sent at that offset, for all 256 possible original bytes.
- The head of the order survives that: the first 5 cases at every offset still leave the
  byte at `0x00`, `0x01`, `0x7F`, `0x80`, `0xFF`, and all 8 single-bit flips still land
  within the first 13.
- Sweep order: breadth-first is the default and the first 10 cases of a 10-offset frame
  touch all 10 offsets, each applying `0x00`; a budget of 105 reaches every offset where
  depth-first reaches one; `FUZZ_SWEEP_DEPTH_FIRST=1` puts the first 255 cases at offset 0
  and `=0` does not; both orders sweep exactly 2550 cases with no duplicates and cover the
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
  hold; with nothing held, behaviour is byte-identical to before the change (2550 cases for
  a 34-byte frame, zero duplicates, 255 per offset, masks 1..255, lowest mutated byte 24,
  locking at `case_max`). A target held at `FUZZ_START_EAPOL=500` parks at
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
`fuzzing/live/RESULTS.md`, reproduce with `fuzzing/live/run_live.sh`.

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
  retained logs, every one a JSON object with a `msg`, zero parse failures. A further 364
  lines were checked at the time in a run whose log was later overwritten. Raw logs are not
  carried in the tree: each run overwrites `$FUZZ_LOGDIR/live/logs/`, so the record is the
  tally in `fuzzing/live/RESULTS.md` and the run that reproduces it. This is the one claim
  no offline harness can make.
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
  offline (19 checks, `fuzzing/verify/sweep_ordering/verify_ordering.py`) but has not yet had a
  live run; the measured numbers above all predate it.
- `interface=wlan0` in `hostapd-wpa3.conf` is a placeholder. On a machine where `wlan0` is
  the uplink, it is a dangerous one — `fuzzing/live/run_live.sh` generates its own config
  rather than using it, refuses any interface holding the default route or an association,
  and refuses a built-in radio outright.

**Running it live:** `fuzzing/live/run_live.sh` does the whole sequence — sanity
(`FUZZ_DISABLE=1`, so a failure here is configuration, not mutation), then a control with
nothing held, then a held phase — and prints a per-target table after each. It picks an
external AP-capable adapter, never a built-in radio, and hands the interface back to
NetworkManager on exit.

```sh
sudo ./fuzzing/live/run_live.sh --ssid <what your station seeks> --password <its psk> \
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

Within the harness, the C hooks live in `src/` beside the code they hook. Everything that
derives, generates or checks something lives under `fuzzing/`, one directory per job:

| directory | what it holds |
| --- | --- |
| `fuzzing/ledger/` | what a run sent: the target, stage, registry and field extractors, and the coverage tally |
| `fuzzing/axes/` | the configuration axes, derived from `hostapd_config_fill()` |
| `fuzzing/stages/` | the one-shot stage inventory and its verifier |
| `fuzzing/resize/`, `fuzzing/synth/`, `fuzzing/direction/`, `fuzzing/fields/` | the behavioural verifiers for the length domain, element synthesis, the inverted direction and the field model |
| `fuzzing/verify/` | the older verifiers: the sweep itself, the output contract, sweep order |
| `fuzzing/topology/` | the hwsim run scripts, their configs and the per-peer generator |
| `fuzzing/peers/` | the multi-peer verifier |
| `fuzzing/reach/` | the receive-side roster and its verifier: what the victim's parsers read |
| `fuzzing/source/` | the source-address roster and its verifier: how many identities one peer presents |
| `fuzzing/live/` | the real-RF run: a hostapd against an actual station, and the recorded results |
| `fuzzing/phasing/` | the starvation measurement: which stage blocks the ones behind it |

**Nothing under `fuzzing/` is needed to build.** `hostapd/` and `wpa_supplicant/` compile
from `src/` alone; the generated headers it produces (`src/common/fuzz_registries.h`,
`src/common/fuzz_fields.h`, `src/common/fuzz_targets.h`, `src/common/fuzz_minima.h`,
`src/common/fuzz_reach_targets.h`, `src/common/fuzz_sources.h`) are committed, so a checkout builds without running any of it. What `fuzzing/` is for is
keeping those headers honest — `--check` on each generator fails when the tree has moved
and the header has not.

`monitor_fuzzing.py` stays at the top level: it is the thing you run, not part of the
machinery. It imports the coverage ledger from `fuzzing/ledger/ledger.py` and from nowhere
else. A checkout without it still runs — the ledger is a reporting convenience, not part of
fuzzing — but it says on stderr which path it wanted rather than going quiet.

It used to search for the ledger instead, which meant any stale copy left anywhere in the
checkout would be imported and the run would report coverage parsed by the wrong version:
output that looks right and is not. One path trades that for a different failure — moving
the ledger breaks the monitor — and that one is caught by
`fuzzing/direction/verify_direction.py`, which asserts the named path exists and that a
ledger planted elsewhere in the tree is declined.

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
python3 fuzzing/verify/fuzz_verify/fuzz_verify.py .          # from the repo root
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
problem-by-problem working record was kept locally while that work was done and is not
part of the repository, so those commit messages are the record.
