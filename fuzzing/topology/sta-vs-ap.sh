#!/bin/sh
# Topology 1: a fuzzing wpa_supplicant against a stock hostapd.
#
# This is the inverted direction. Every hook in src/ap points AP to station,
# which leaves hostapd's own parsers -- Authentication, Association Request,
# the EAPOL-Key frames the supplicant sends -- reachable by nothing. Here the
# station does the sending and the AP is the victim.
#
# The victim is an ordinary build and the oracle is that it died. There is no
# detection code in this harness and there is not going to be: a process that
# crashed is not a judgement call, and anything softer than that is a filter
# over what counts as interesting, written by whoever wrote the filter.
#
#   ./topology/sta-vs-ap.sh [minutes]
#
# Needs mac80211_hwsim loaded. That is the one privileged step:
#
#   sudo modprobe mac80211_hwsim radios=0
#
# radios=0 because this script creates its own, inside its own network
# namespace, where they belong to the run and vanish with it.

set -eu

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
MINUTES=${1:-10}

LOGDIR=${FUZZ_LOGDIR:-${TMPDIR:-/tmp}/hostap-fuzz}
AP=${AP:-$ROOT/hostapd/hostapd}
STA=${STA:-$ROOT/wpa_supplicant/wpa_supplicant}

if [ ! -x "$AP" ] || [ ! -x "$STA" ]; then
	echo "error: build both first:" >&2
	echo "  hostapd:        defconfig + CONFIG_SAE + AC/AX/BE, with ASan" >&2
	echo "  wpa_supplicant: defconfig-fuzz" >&2
	exit 2
fi

# A fuzzing AP here would mean both ends mutating and neither being a
# reference, which is the mesh topology, not this one.
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
	# -r maps this user to root inside, which is what makes CAP_NET_ADMIN
	# over the new namespaces available without being root outside them.
	# -m so the control sockets below land in a mount namespace of their
	# own; -n so the radios do.
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
AP_IFACE=$1
STA_IFACE=$2
echo "radios: AP=$AP_IFACE STA=$STA_IFACE"

sed -e "s|@AP_IFACE@|$AP_IFACE|" -e "s|@RUNDIR@|$RUNDIR|" \
	"$ROOT/fuzzing/topology/ap-stock.conf" > "$RUNDIR/ap.conf"
sed -e "s|@RUNDIR@|$RUNDIR|" \
	"$ROOT/fuzzing/topology/sta-fuzz.conf" > "$RUNDIR/sta.conf"

# W14. The source address as a swept domain. A station changes its address
# only where its configuration asks it to, so a run that sets FUZZ_ADDRS and
# nothing else presents ONE identity however many cases it sends -- and
# every table keyed by address behind it sees a single peer.
#
#   mac_addr=2             change it per connection, keeping the OUI, so the
#                          identities stay inside this radio's own block and
#                          cannot collide with another radio's address.
#   rand_addr_lifetime=0   and change it EVERY connection. The default is 60
#                          seconds, which at this cadence is one identity
#                          per few hundred cases.
#
# The ledger reports the ask and the delivery separately, so a run that sets
# FUZZ_ADDRS without this says so rather than looking like it worked.
if [ "${FUZZ_ADDRS:-0}" -gt 0 ]; then
	export FUZZ_ADDRS
	printf 'mac_addr=2\nrand_addr_lifetime=0\n' >> "$RUNDIR/sta.conf"
	echo "source addresses: a domain of $FUZZ_ADDRS, per connection"
fi

# ASan's own abort is the signal we are watching for, so make sure it aborts.
ASAN_OPTIONS=${ASAN_OPTIONS:-abort_on_error=1:detect_leaks=0}
export ASAN_OPTIONS

# One case per association, so the rate of cases is the rate of associations.
# Override to 0 to leave the station connected, for anything past the
# handshake.
FUZZ_RECONNECT_MS=${FUZZ_RECONNECT_MS:-200}
export FUZZ_RECONNECT_MS

# The station is the subject -- it carries the hooks and emits the [fuzz]
# lines. The AP is the victim and is only watched.
# SIGTERM at the deadline rather than SIGKILL, so the run still prints what
# it covered. monitor_fuzzing.py routes it through its clean stop.
exec timeout "${MINUTES}m" python3 "$ROOT/monitor_fuzzing.py" \
	--subject "$STA -i $STA_IFACE -c $RUNDIR/sta.conf -d" \
	--victim "$AP $RUNDIR/ap.conf" \
	--victim-log "$LOGDIR/fuzz-victim-ap.log" \
	--repro-dir "$LOGDIR/repro" \
	--ledger-json "$LOGDIR/fuzz-ledger-sta.json" \
	--quiet
