#!/bin/sh
# Topology 2: two fuzzing wpa_supplicants in a mesh.
#
# The third transmit direction. Both ends run the same program and each
# mutates the peering frames it sends, so neither is a stock reference -- a
# crash says one of the two mutations caused it and not which. That is the
# price of a topology where the code under test is also the code doing the
# testing, and it is still worth having, because mesh peering is reachable
# from nowhere else: an AP never sends a Mesh Peering Open and neither does a
# station.
#
#   ./topology/mesh.sh [minutes]
#
# Needs mac80211_hwsim loaded:
#
#   sudo modprobe mac80211_hwsim radios=0
#
# Build wpa_supplicant from defconfig-fuzz, which turns CONFIG_MESH on;
# upstream defconfig does not, and without it the peering hooks have no call
# site at all. With ASan, since here the victim is a fuzzing build too:
#
#   make clean
#   make CFLAGS="-fsanitize=address -fno-omit-frame-pointer -g -O1" \
#        LDFLAGS="-fsanitize=address"

set -eu

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
MINUTES=${1:-10}

LOGDIR=${FUZZ_LOGDIR:-${TMPDIR:-/tmp}/hostap-fuzz}
STA=${STA:-$ROOT/wpa_supplicant/wpa_supplicant}

if [ ! -x "$STA" ]; then
	echo "error: build wpa_supplicant from defconfig-fuzz first" >&2
	exit 2
fi
if ! "$STA" -v 2>&1 | grep -q 'fuzzing hooks are COMPILED IN'; then
	echo "error: $STA has no fuzzing hooks; build it from defconfig-fuzz" >&2
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

set -- $(python3 "$ROOT/fuzzing/topology/radios.py" 2)
A=$1
B=$2
echo "radios: A=$A B=$B"

for n in a b; do
	mkdir -p "$RUNDIR/$n"
	sed -e "s|@RUNDIR@|$RUNDIR/$n|" \
		"$ROOT/fuzzing/topology/mesh-fuzz.conf" > "$RUNDIR/$n.conf"
done

ASAN_OPTIONS=${ASAN_OPTIONS:-abort_on_error=1:detect_leaks=0}
export ASAN_OPTIONS

# Both nodes carry hooks, so both emit [fuzz] lines. Only node A's go through
# the monitor; node B's land in its log, and the ledger is run over that
# afterwards rather than being merged in -- a merged tally would say the mesh
# covered twice what either node did, which is true of the pair and false of
# each.
B_LOG=$LOGDIR/fuzz-mesh-b.log

set +e
timeout "${MINUTES}m" python3 "$ROOT/monitor_fuzzing.py" \
	--subject "$STA -i $A -c $RUNDIR/a.conf" \
	--victim "$STA -i $B -c $RUNDIR/b.conf" \
	--victim-log "$B_LOG" \
	--repro-dir "$LOGDIR/repro" \
	--ledger-json "$LOGDIR/fuzz-ledger-mesh-a.json" \
	--quiet
rc=$?
set -e

echo
echo "=== node B's own ledger (it was a subject too, not only a victim) ==="
python3 "$ROOT/fuzzing/ledger/ledger.py" "$ROOT" "$B_LOG" || true

exit $rc
