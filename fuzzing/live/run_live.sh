#!/bin/bash
#
# Live acceptance for the fuzzing hooks, against a real SAE station.
#
#   sudo ./fuzzing/live/run_live.sh                     # all three phases
#   sudo ./fuzzing/live/run_live.sh --minutes 5
#   sudo ./fuzzing/live/run_live.sh --phase held
#   sudo ./fuzzing/live/run_live.sh --phase held --hold probe_resp,sae-send-commit
#
# --hold names the targets to answer CORRECTLY, so the stage behind them is
# reachable. To fuzz eapol, hold every stage before it.
#   sudo ./fuzzing/live/run_live.sh --ssid penzzer-test --password password \
#                                      --channel 8
#
# Three phases, in this order, because it separates configuration problems from
# mutation problems:
#
#   sanity   FUZZ_DISABLE=1 -- the station must associate normally. If this
#            fails, nothing after it means anything.
#   control  nothing held -- reproduces the starvation: probe_resp advances and
#            the stages behind it do not.
#   held     FUZZ_HOLD_PROBE_RESP=1 -- the ask. The station should complete the
#            four-way handshake repeatedly and sae-send-commit should advance.
#
# Every phase's full output is kept under $FUZZ_LOGDIR/live/logs/, so the run can
# be re-read afterwards without repeating it.

set -u -o pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SELFDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

#  Everything a run produces goes outside the checkout. A log or a generated
#  config written next to the source is one 'git add -A' from being committed,
#  and this script runs under sudo, so it would land there owned by root.
OUTDIR="${FUZZ_LOGDIR:-${TMPDIR:-/tmp}/hostap-fuzz}/live"
LOGDIR="$OUTDIR/logs"
CONF="$OUTDIR/hostapd-live.conf"

IFACE="${IFACE:-}"
#  Empty means "whatever hostapd-wpa3.conf says". Overriding is usually easier
#  than reflashing a station that is already pointed somewhere.
SSID_OVERRIDE=""
PASS_OVERRIDE=""
CHANNEL_OVERRIDE=""
#  Which targets the 'held' phase answers correctly. The phasing recipe works
#  backwards: hold every stage earlier than the one being fuzzed, so a station
#  can actually reach it.
HOLD_TARGETS="probe_resp"
MINUTES=10
SANITY_SECONDS=120
PHASES="sanity control held"

while [ $# -gt 0 ]; do
	case "$1" in
	--iface)   IFACE="$2"; shift 2 ;;
	--minutes) MINUTES="$2"; shift 2 ;;
	--phase)   PHASES="$2"; shift 2 ;;
	--ssid)    SSID_OVERRIDE="$2"; shift 2 ;;
	--password) PASS_OVERRIDE="$2"; shift 2 ;;
	--channel) CHANNEL_OVERRIDE="$2"; shift 2 ;;
	--hold)    HOLD_TARGETS="$2"; shift 2 ;;
	--list)    LIST_ONLY=yes; shift ;;
	-h|--help) sed -n '2,30p' "${BASH_SOURCE[0]}"; exit 0 ;;
	*) echo "unknown argument: $1" >&2; exit 2 ;;
	esac
done

say()  { printf '\n\033[1m== %s\033[0m\n' "$*"; }
warn() { printf '   !! %s\n' "$*"; }
info() { printf '   %s\n' "$*"; }

# ---------------------------------------------------------------- preflight --
if [ "$(id -u)" -ne 0 ] && [ "${LIST_ONLY:-}" != yes ]; then
	echo "run this with sudo: it configures an interface"
	echo "(--list works without root)"
	exit 2
fi

HOSTAPD="$ROOT/hostapd/hostapd"
[ -x "$HOSTAPD" ] || { echo "no build at $HOSTAPD -- run make in hostapd/ first"; exit 2; }

#  hostapd -v exits 1, so this must not be a pipeline: with pipefail set, a
#  matching grep downstream of it still reports failure.
BANNER=$("$HOSTAPD" -v 2>&1 | head -1)
case "$BANNER" in
*-fuzz*) ;;
*)
	echo "$BANNER is NOT a fuzzing build."
	echo "Build with CONFIG_FUZZ=y: cd hostapd && cp defconfig-fuzz .config && make"
	exit 2
	;;
esac

#  Pick the AP-capable radio that is NOT carrying a connection. Getting this
#  wrong takes down the machine's own link, so an interface that is associated
#  or owns the default route is refused rather than used.
default_route_iface() { ip route show default 2>/dev/null | awk '{print $5; exit}'; }

#  The built-in radio is off limits, whether or not it happens to be idle right
#  now: it is the machine's own link, and "idle at this instant" is not a
#  property worth betting the uplink on. Only an external (USB) adapter is
#  eligible, and --iface does not override this -- change the case below if
#  that ever needs to stop being true.
interface_is_builtin() {
	local path
	path=$(readlink -f "/sys/class/net/$1/device" 2>/dev/null) || return 0
	case "$path" in
	*/usb[0-9]*) return 1 ;;
	*)           return 0 ;;
	esac
}

interface_is_busy() {
	local dev="$1"
	[ "$dev" = "$(default_route_iface)" ] && return 0
	iw dev "$dev" link 2>/dev/null | grep -q "^Connected to" && return 0
	return 1
}

#  Enumerated from /sys rather than from `iw dev`: it needs no tool, so a
#  missing or misbehaving iw shows up as its own error instead of as an empty
#  candidate list.
wireless_interfaces() {
	local path
	for path in /sys/class/net/*/phy80211; do
		[ -e "$path" ] || continue
		basename "$(dirname "$path")"
	done
}

#  Why each interface was or was not chosen. Silence here was the whole problem
#  the first time this ran.
survey_interfaces() {
	local dev phy verdict
	for dev in $(wireless_interfaces); do
		phy=$(cat "/sys/class/net/$dev/phy80211/name" 2>/dev/null || echo "?")
		if interface_is_builtin "$dev"; then
			verdict="REFUSED: built-in radio, never used"
		elif [ "$dev" = "$(default_route_iface)" ]; then
			verdict="REFUSED: holds the default route"
		elif iw dev "$dev" link 2>/dev/null | grep -q "^Connected to"; then
			verdict="REFUSED: associated to a network"
		elif ! iw phy "$phy" info 2>/dev/null | grep -qE '^[[:space:]]+\* AP$'; then
			verdict="unusable: $phy does not advertise AP mode"
		else
			verdict="usable"
		fi
		printf '   %-18s %-6s %s\n' "$dev" "$phy" "$verdict"
	done
}

command -v iw >/dev/null 2>&1 || { echo "'iw' is not on PATH ($PATH)"; exit 2; }

if [ -z "$IFACE" ]; then
	for dev in $(wireless_interfaces); do
		phy=$(cat "/sys/class/net/$dev/phy80211/name" 2>/dev/null) || continue
		interface_is_builtin "$dev" && continue
		iw phy "$phy" info 2>/dev/null | grep -qE '^[[:space:]]+\* AP$' || continue
		interface_is_busy "$dev" && continue
		IFACE="$dev"
		break
	done
fi

if [ "${LIST_ONLY:-}" = yes ]; then
	say "Interfaces as this script sees them"
	survey_interfaces
	printf '\n   would use: %s\n' "${IFACE:-none}"
	exit 0
fi

if [ -z "$IFACE" ]; then
	echo "no idle AP-capable interface found. What this script sees:"
	survey_interfaces
	echo
	echo "Pass --iface NAME to override, or --list to see this without running."
	exit 2
fi

if interface_is_builtin "$IFACE"; then
	echo "$IFACE is a built-in radio. This script will not use one:"
	echo "it is the machine's own link. Use an external USB adapter."
	survey_interfaces
	exit 2
fi

if interface_is_busy "$IFACE"; then
	echo "$IFACE is carrying a connection or the default route. Refusing to use it."
	survey_interfaces
	if [ "$IFACE" != "$(default_route_iface)" ]; then
		echo
		echo "If NetworkManager merely picked it up, free it and retry:"
		echo "    nmcli device set $IFACE managed no"
	fi
	exit 2
fi

PHY=$(cat "/sys/class/net/$IFACE/phy80211/name" 2>/dev/null || echo "?")
DRIVER=$(basename "$(readlink -f "/sys/class/net/$IFACE/device/driver" 2>/dev/null)" 2>/dev/null || echo "?")

say "Preflight"
info "build:     $BANNER"
info "interface: $IFACE  ($PHY, $DRIVER)"
info "default route is on: $(default_route_iface) -- untouched"

if ! iw phy "$PHY" info 2>/dev/null | grep -q "CMAC (00-0f-ac:6)"; then
	warn "$PHY does not advertise BIP-CMAC-128; ieee80211w=2 (which SAE"
	warn "requires) will probably fail to start. Continuing anyway."
fi

mkdir -p "$LOGDIR"

#  scapy is usually in a venv rather than installed system-wide, and sudo runs
#  root's bare python3, which would not see one in your home directory -- every
#  frame would then be reported as raw hex. Point FUZZ_PYTHON at the interpreter
#  that has scapy to avoid that. Dissection is a convenience; the run does not
#  depend on it.
PYTHON="${FUZZ_PYTHON:-}"
if [ -n "$PYTHON" ] && [ ! -x "$PYTHON" ]; then
	warn "FUZZ_PYTHON=$PYTHON is not executable; falling back to python3"
	PYTHON=""
fi
[ -n "$PYTHON" ] || PYTHON="$(command -v python3)"
if "$PYTHON" -c "import scapy" 2>/dev/null; then
	info "python:    $PYTHON (scapy $("$PYTHON" -c 'import scapy; print(scapy.__version__)' 2>/dev/null))"
else
	info "python:    $PYTHON (no scapy -- frames will be shown as raw hex)"
	info "           set FUZZ_PYTHON to an interpreter that has it"
fi

# ---------------------------------------------------------------- interface --
NM_RELEASED=""
release_interface() {
	if command -v nmcli >/dev/null 2>&1; then
		if nmcli -t -f DEVICE,STATE device 2>/dev/null | grep -q "^$IFACE:unmanaged"; then
			info "NetworkManager already leaves $IFACE alone"
		else
			nmcli device set "$IFACE" managed no >/dev/null 2>&1 &&
				NM_RELEASED=yes &&
				info "took $IFACE out of NetworkManager's hands"
		fi
	fi
	ip link set "$IFACE" down 2>/dev/null
	rm -f "/var/run/hostapd/$IFACE"
}

restore_interface() {
	[ -n "$NM_RELEASED" ] && command -v nmcli >/dev/null 2>&1 &&
		nmcli device set "$IFACE" managed yes >/dev/null 2>&1 &&
		info "gave $IFACE back to NetworkManager"
	rm -f "/var/run/hostapd/$IFACE"
	#  Logs and repro records are written as root; hand them back.
	if [ -n "${SUDO_USER:-}" ]; then
		chown -R "$SUDO_USER" "$OUTDIR" 2>/dev/null
	fi
}
trap restore_interface EXIT

#  sudo runs this script in a NEW SESSION, so a Ctrl-C in the invoking terminal
#  reaches sudo and nothing below it: the phase's timeout/python/hostapd sit in
#  their own process group and keep running. Catching the signal here and
#  passing it down explicitly is what makes Ctrl-C work.
PHASE_PID=""
stop_now() {
	local i
	printf '\n'
	info "stopping on signal"
	if [ -n "$PHASE_PID" ]; then
		#  INT first, because the monitor turns it into a clean hostapd
		#  shutdown. Then escalate: a plain 'wait' here would hang if the
		#  child is ignoring INT, which is exactly when stopping matters.
		kill -INT "$PHASE_PID" 2>/dev/null
		for i in 1 2 3 4 5; do
			kill -0 "$PHASE_PID" 2>/dev/null || break
			sleep 1
		done
		kill -TERM "$PHASE_PID" 2>/dev/null
	fi
	exit 130
}
trap stop_now INT TERM

sed "s/^interface=.*/interface=$IFACE/" "$ROOT/hostapd/hostapd-wpa3.conf" > "$CONF"

#  The station has to be able to find this AP; what the network is called is
#  incidental to what is being measured.
if [ -n "$SSID_OVERRIDE" ]; then
	sed -i "s/^ssid=.*/ssid=$SSID_OVERRIDE/" "$CONF"
fi
if [ -n "$PASS_OVERRIDE" ]; then
	sed -i "s/^sae_password=.*/sae_password=$PASS_OVERRIDE/" "$CONF"
fi
if [ -n "$CHANNEL_OVERRIDE" ]; then
	sed -i "s/^channel=.*/channel=$CHANNEL_OVERRIDE/" "$CONF"
fi

SSID=$(awk -F= '/^ssid=/ {print $2}' "$CONF")
PASS=$(awk -F= '/^sae_password=/ {print $2}' "$CONF")
info "network:   SSID '''$SSID''', password '''$PASS''', WPA3-SAE, channel $(awk -F= '''/^channel=/ {print $2}''' "$CONF")"

# -------------------------------------------------------------------- phases --
run_phase() {
	#  Separate declarations: bash 5.3 makes every name in a 'local' list
	#  local-and-unset before running any of the assignments, so a later
	#  value referring to an earlier name is an unbound variable under set -u.
	local name="$1"
	local seconds="$2"
	local log="$LOGDIR/$name.log"
	shift 2

	say "Phase '$name' -- ${seconds}s"
	if [ $# -gt 0 ]; then
		info "environment: $*"
	else
		info "environment: (nothing held -- this is the control)"
	fi
	info "log: $log"
	info "the station should be powered on and trying to join '$SSID' now"

	release_interface

	#  SIGINT rather than SIGTERM: the monitor handles it, so it stops hostapd
	#  cleanly and the log ends mid-run rather than mid-write.
	#  Backgrounded and waited on, rather than run in the foreground: 'wait'
	#  is interruptible, so the INT trap above can act while a phase runs.
	env "$@" timeout -s INT "$seconds" \
		"$PYTHON" -u "$ROOT/monitor_fuzzing.py" \
			--hostapd "$HOSTAPD" \
			--config "$CONF" \
			--repro-dir "$OUTDIR/repro" \
		> "$log" 2>&1 &
	PHASE_PID=$!
	wait "$PHASE_PID"
	local status=$?
	PHASE_PID=""

	case $status in
	124|130) info "phase ended on its timer (expected)" ;;
	0)       warn "hostapd exited on its own with status 0" ;;
	1)       warn "hostapd DIED -- see $log and $OUTDIR/repro/" ;;
	*)       warn "monitor exited with status $status" ;;
	esac

	"$PYTHON" "$SELFDIR/summarise.py" "$log"
}

for phase in $PHASES; do
	case "$phase" in
	sanity)
		run_phase sanity "$SANITY_SECONDS" FUZZ_DISABLE=1
		info "wanted: associations and four-way handshakes above zero."
		info "No [fuzz] lines is CORRECT here -- FUZZ_DISABLE=1 means the"
		info "hooks emit nothing and the AP behaves as stock."
		;;
	control)
		run_phase control "$((MINUTES * 60))"
		info "expected: probe_resp advances, the stages behind it do not."
		info "That is the starvation this run exists to reproduce."
		;;
	held)
		hold_env=""
		for target in $(echo "$HOLD_TARGETS" | tr ',' ' '); do
			#  Same folding rule as fuzz_env_name() in src/common/fuzz.c:
			#  uppercase, everything not alphanumeric becomes '_'.
			folded=$(printf '%s' "$target" |
				 tr '[:lower:]' '[:upper:]' |
				 tr -c '[:alnum:]' '_')
			hold_env="$hold_env FUZZ_HOLD_${folded}=1"
		done
		# shellcheck disable=SC2086
		run_phase held "$((MINUTES * 60))" $hold_env
		info "wanted: probe_resp held at -9 and still announcing, four-way"
		info "handshakes above zero, sae-send-commit past 100."
		;;
	*)
		echo "unknown phase: $phase" >&2; exit 2 ;;
	esac
done

say "Done"
info "logs:  $LOGDIR"
info "Send those back for the analysis -- the control and held tables side by"
info "side are the result."
