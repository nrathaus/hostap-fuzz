#!/bin/sh
# Topology 3: N fuzzing stations against one stock hostapd.
#
# A one-peer run cannot produce concurrent-session stimulus at all. Whatever
# the single station negotiated is the only thing the AP has live, and every
# code path that only runs when two sessions overlap is unreachable -- not
# because it is hard to reach, but because there is only ever one session.
#
# So: N stations, each negotiating a DIFFERENT finite cyclic group, chosen by
# topology/peers.py out of the registry fuzzing/axes/families.py derives from
# the tree. The AP accepts all of them, so it ends up running N sessions in
# different group code at the same time.
#
# They share each target's case counter, so each station receives a different
# case. N peers is N times the stimulus, not N copies of it, and the ledger
# prints the split per peer to show it.
#
#   ./fuzzing/topology/multi-sta.sh [minutes] [stations]
#
# Needs mac80211_hwsim loaded -- the one privileged step, once per boot:
#
#   sudo modprobe mac80211_hwsim radios=0
#
# This creates stations + 1 radios in its own namespace. hwsim has no fixed
# limit worth worrying about here; four stations is a sensible default and
# more is a scheduling question, not a correctness one.

set -eu

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
MINUTES=${1:-10}
STATIONS=${2:-3}

LOGDIR=${FUZZ_LOGDIR:-${TMPDIR:-/tmp}/hostap-fuzz}
AP=${AP:-$ROOT/hostapd/hostapd}
STA=${STA:-$ROOT/wpa_supplicant/wpa_supplicant}

if [ ! -x "$AP" ] || [ ! -x "$STA" ]; then
	echo "error: build both first:" >&2
	echo "  hostapd:        defconfig + CONFIG_SAE + AC/AX/BE, with ASan" >&2
	echo "  wpa_supplicant: defconfig-fuzz" >&2
	exit 2
fi
if "$AP" -v 2>&1 | grep -q 'fuzzing hooks are COMPILED IN'; then
	echo "error: $AP is a fuzzing build; the victim must be a stock one" >&2
	exit 2
fi
if ! "$STA" -v 2>&1 | grep -q 'fuzzing hooks are COMPILED IN'; then
	echo "error: $STA has no fuzzing hooks; build it from defconfig-fuzz" >&2
	exit 2
fi

# A victim that reports what it READ is what tells a case space that is
# sweeping from one that is being discarded at the door. That is a DIFFERENT
# flag from CONFIG_FUZZ -- a reach build mutates nothing and transmits
# exactly what a stock build transmits -- so it is not the check above, and
# it is a note rather than a requirement. A run without it still works, and
# the ledger says NOT MEASURED instead of reporting a zero it cannot read.
if "$AP" -v 2>&1 | grep -q 'Reach instrumentation is COMPILED IN'; then
	echo "victim: reports what it read"
else
	echo "victim: NOT instrumented, so this run cannot say what it read."
	echo "  Build one:  cd hostapd && cp defconfig .config &&"
	echo "              echo CONFIG_FUZZ_REACH=y >> .config && make"
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

set -- $(python3 "$ROOT/fuzzing/topology/radios.py" $((STATIONS + 1)))
AP_IFACE=$1
shift
echo "radios: AP=$AP_IFACE stations=$*"

# The stations are generated first, and the AP is then configured to accept
# exactly the groups they chose. One computation, read once: asking peers.py
# twice would be two chances to disagree, and an AP that rejected a group
# would make "which group this session is in" the AP's decision rather than
# the station's.
FUZZ_RUNDIR=$RUNDIR python3 "$ROOT/fuzzing/topology/peers.py" \
	"$ROOT" "$STATIONS" "$RUNDIR" > "$RUNDIR/peers.txt"
cat "$RUNDIR/peers.txt"

# Not named GROUPS: that is a read-only array in bash holding the caller's
# group ids, so the assignment is silently discarded and the expansion gives
# the primary group id instead -- 0 inside this namespace. The AP then gets
# sae_groups=0, accepts nothing, and every station fails to associate while
# the run reports no error at all.
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
FUZZ_RECONNECT_MS=${FUZZ_RECONNECT_MS:-200}
export FUZZ_RECONNECT_MS

# Station 0 is the subject: its [fuzz] lines go through the monitor and its
# ledger is the one printed live. The others are subjects too -- every one of
# them carries hooks and mutates what it sends -- and their logs are run
# through the ledger afterwards. The AP is the victim and is only watched;
# with several stations in flight it is also the only process that sees all of
# them at once, which is the whole reason this topology exists.
i=1
for IFACE in "$@"; do
	if [ "$i" = 1 ]; then
		FIRST=$IFACE
	else
		"$STA" -i "$IFACE" -c "$RUNDIR/sta$((i - 1)).conf" \
			> "$LOGDIR/fuzz-sta$((i - 1)).log" 2>&1 &
	fi
	i=$((i + 1))
done

set +e
timeout "${MINUTES}m" python3 "$ROOT/monitor_fuzzing.py" \
	--subject "$STA -i $FIRST -c $RUNDIR/sta0.conf" \
	--victim "$AP $RUNDIR/ap.conf" \
	--victim-log "$LOGDIR/fuzz-victim-ap.log" \
	--repro-dir "$LOGDIR/repro" \
	--ledger-json "$LOGDIR/fuzz-ledger-sta0.json" \
	--quiet
rc=$?
set -e

kill %1 2>/dev/null || true
wait 2>/dev/null || true

i=1
while [ "$i" -lt "$STATIONS" ]; do
	echo
	echo "=== station $i's own ledger (a subject too, not a bystander) ==="
	python3 "$ROOT/fuzzing/ledger/ledger.py" "$ROOT" \
		"$LOGDIR/fuzz-sta$i.log" || true
	i=$((i + 1))
done

exit $rc
