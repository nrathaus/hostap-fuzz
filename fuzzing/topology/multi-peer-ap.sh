#!/bin/sh
# Topology 4: a fuzzing hostapd with N stock stations.
#
# The other multi-peer script points N fuzzing stations at one AP, which puts
# N concurrent sessions into the victim -- that is where shared state is under
# two subsystems at once. This one is the other way round, and it is the one
# where the per-peer record earns its keep: the subject here talks to N peers,
# so "which peer received which case" is a question with N answers rather than
# one. A station has exactly one peer and its ledger says so.
#
# The stations are stock builds and transmit nothing mutated. Each negotiates
# a different finite cyclic group, chosen by topology/peers.py from the
# registry fuzzing/axes/families.py derives, so the AP runs N sessions in
# different group code at the same time. All of them are watched: with several
# peers there are several processes that might die.
#
# Every station shares the AP's per-target case counter, so each receives a
# DIFFERENT case. N peers is N times the stimulus, not N copies of it, and the
# ledger prints the split to show it rather than leaving it to be assumed.
#
#   ./fuzzing/topology/multi-peer-ap.sh [minutes] [stations]
#
# Needs mac80211_hwsim loaded -- the one privileged step, once per boot:
#
#   sudo modprobe mac80211_hwsim radios=0

set -eu

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
MINUTES=${1:-10}
STATIONS=${2:-3}

LOGDIR=${FUZZ_LOGDIR:-${TMPDIR:-/tmp}/hostap-fuzz}
AP=${AP:-$ROOT/hostapd/hostapd}
STA=${STA:-$ROOT/wpa_supplicant/wpa_supplicant}

if [ ! -x "$AP" ] || [ ! -x "$STA" ]; then
	echo "error: build both first:" >&2
	echo "  hostapd:        defconfig-fuzz" >&2
	echo "  wpa_supplicant: defconfig + CONFIG_SAE (a stock build)" >&2
	exit 2
fi
if ! "$AP" -v 2>&1 | grep -q 'fuzzing hooks are COMPILED IN'; then
	echo "error: $AP has no fuzzing hooks; build it from defconfig-fuzz" >&2
	exit 2
fi
if "$STA" -v 2>&1 | grep -q 'fuzzing hooks are COMPILED IN'; then
	echo "error: $STA is a fuzzing build; the peers must be stock ones, or" >&2
	echo "       both ends mutate and nothing in the run is a reference" >&2
	exit 2
fi
if [ ! -d /sys/module/mac80211_hwsim ]; then
	echo "error: mac80211_hwsim is not loaded." >&2
	echo "  sudo modprobe mac80211_hwsim radios=0" >&2
	exit 2
fi

if [ "${IN_NS:-}" != "1" ]; then
	exec env IN_NS=1 unshare -r -m -n -- "$0" "$@"
fi

# Everything a run produces goes outside the checkout. A log or a ledger
# written next to the source is one `git add -A` away from being committed,
# and these are per-run artefacts that nothing should carry. Override with
# FUZZ_LOGDIR to put them somewhere durable.
mkdir -p "$LOGDIR"
echo "logs:   $LOGDIR"

RUNDIR=$(mktemp -d)
trap 'rm -rf "$RUNDIR"' EXIT

ip link set lo up

IFACES=$(python3 "$ROOT/fuzzing/topology/radios.py" $((STATIONS + 1)))
AP_IFACE=${IFACES%% *}
STA_IFACES=${IFACES#* }
echo "radios: AP=$AP_IFACE stations=$STA_IFACES"

FUZZ_RUNDIR=$RUNDIR python3 "$ROOT/fuzzing/topology/peers.py" \
	"$ROOT" "$STATIONS" "$RUNDIR" > "$RUNDIR/peers.txt"
cat "$RUNDIR/peers.txt"

# Not named GROUPS: that is a read-only array in bash holding the caller's
# group ids, so the assignment is discarded and the expansion gives a group
# id instead. The AP would then accept nothing and no station would associate,
# with no error reported anywhere.
SAE_GROUPS=$(sed -n 's/.*group=//p' "$RUNDIR/peers.txt" | sort -un |
	tr '\n' ' ')
echo "groups: $SAE_GROUPS"
if [ -z "$SAE_GROUPS" ]; then
	echo "error: no groups were assigned; the registry came back empty" >&2
	exit 2
fi

sed -e "s|@AP_IFACE@|$AP_IFACE|" -e "s|@RUNDIR@|$RUNDIR|" \
	"$ROOT/fuzzing/topology/ap-stock.conf" > "$RUNDIR/ap.conf"
sed -i "s|^sae_groups=.*|sae_groups=$SAE_GROUPS|" "$RUNDIR/ap.conf"

ASAN_OPTIONS=${ASAN_OPTIONS:-abort_on_error=1:detect_leaks=0}
export ASAN_OPTIONS
# The AP is the subject here, so it is the AP-side knob that paces the run.
FUZZ_DISCONNECT_MS=${FUZZ_DISCONNECT_MS:-1000}
export FUZZ_DISCONNECT_MS

# Built with set -- rather than a string: each --victim value is one argument
# containing spaces, and a string would be word-split into pieces that are no
# longer a command.
set -- --subject "$AP $RUNDIR/ap.conf"
i=0
for IFACE in $STA_IFACES; do
	set -- "$@" --victim "$STA -i $IFACE -c $RUNDIR/sta$i.conf"
	i=$((i + 1))
done
set -- "$@" --victim-log "$LOGDIR/fuzz-victim-sta.log" \
	--repro-dir "$LOGDIR/repro" \
	--ledger-json "$LOGDIR/fuzz-ledger-ap.json" --quiet

exec timeout "${MINUTES}m" python3 "$ROOT/monitor_fuzzing.py" "$@"
