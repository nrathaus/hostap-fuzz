#!/bin/bash
#
# Run one hostapd configuration per axis setting, and union the coverage.
#
#   sudo ./axes/run_profiles.sh --minutes 2
#   sudo ./axes/run_profiles.sh --profiles fuzz-profiles --minutes 5
#   sudo ./axes/run_profiles.sh --option 'sae_|owe_' --minutes 3
#
# The mutation engine can only change octets of a frame the running
# configuration caused hostapd to build, so a frame no configuration in the
# campaign constructs is not under-fuzzed -- it is absent. One run per axis
# setting is how an absent frame becomes a present one.
#
# Each profile gets its own run and its own ledger. A profile hostapd refuses
# is recorded as refused rather than as a profile that reached nothing: a
# configuration that never started is a fact about the configuration, and
# folding it into the coverage total would turn a broken profile into evidence
# that a target is unreachable.
#
# This wants an interface it can own for the whole campaign. mac80211_hwsim is
# the sane place for it -- the matrix is long, and most of these configurations
# are not ones to point at a radio that something else is using.

set -u -o pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PROFILES="$ROOT/fuzz-profiles"
HOSTAPD="$ROOT/hostapd/hostapd"
MONITOR="$ROOT/monitor_fuzzing.py"
PYTHON="${PYTHON:-python3}"
MINUTES=2
OPTION=""
TIER=""
DISTANCE=1
LIMIT=""
HOLD="${HOLD:-probe_resp}"
REGEN=1

usage() { sed -n '2,24p' "${BASH_SOURCE[0]}" | sed 's/^# \?//'; exit "${1:-0}"; }

while [ $# -gt 0 ]; do
	case "$1" in
	--profiles) PROFILES="$2"; shift 2 ;;
	--minutes) MINUTES="$2"; shift 2 ;;
	--option) OPTION="$2"; shift 2 ;;
	--tier) TIER="$2"; shift 2 ;;
	--distance) DISTANCE="$2"; shift 2 ;;
	--limit) LIMIT="$2"; shift 2 ;;
	--hostapd) HOSTAPD="$2"; shift 2 ;;
	--hold) HOLD="$2"; shift 2 ;;
	--no-regen) REGEN=0; shift ;;
	--report-only) REGEN=0; MINUTES=0; shift ;;
	-h|--help) usage 0 ;;
	*) echo "unknown argument: $1" >&2; usage 1 ;;
	esac
done

if [ ! -x "$HOSTAPD" ]; then
	echo "error: $HOSTAPD is not executable." >&2
	echo "Build it with CONFIG_FUZZ=y first; without the hooks there is" >&2
	echo "nothing for this to measure." >&2
	exit 2
fi

if [ "$REGEN" = 1 ]; then
	GEN_ARGS=(gen "$ROOT" --out "$PROFILES" --distance "$DISTANCE")
	[ -n "$OPTION" ] && GEN_ARGS+=(--option "$OPTION")
	[ -n "$LIMIT" ] && GEN_ARGS+=(--limit "$LIMIT")
	if [ -n "$TIER" ]; then
		IFS=, read -ra TIERS <<< "$TIER"
		for t in "${TIERS[@]}"; do GEN_ARGS+=(--tier "$t"); done
	fi
	"$PYTHON" "$ROOT/fuzzing/axes/profiles.py" "${GEN_ARGS[@]}" || exit 1
fi

MANIFEST="$PROFILES/manifest.json"
[ -f "$MANIFEST" ] || { echo "error: no $MANIFEST" >&2; exit 2; }

mapfile -t IDS < <("$PYTHON" - "$MANIFEST" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1]))
for p in (doc["profiles"] if isinstance(doc, dict) else doc):
    print(p["id"])
PY
)

# Answer these stages correctly so the stages behind them stay reachable.
# Without it a campaign measures how far the first stage got, over and over.
for target in ${HOLD//,/ }; do
	var="FUZZ_HOLD_$(echo "$target" | tr 'a-z-' 'A-Z_')"
	export "$var=1"
done

total=${#IDS[@]}
n=0
if [ "$MINUTES" != 0 ]; then
	echo "== $total profile(s), ${MINUTES}m each, holding: $HOLD"
	for id in "${IDS[@]}"; do
		n=$((n + 1))
		conf="$PROFILES/$id.conf"
		out="$PROFILES/$id.json"
		log="$PROFILES/$id.log"
		printf '[%d/%d] %s ... ' "$n" "$total" "$id"

		timeout --signal=INT "$((MINUTES * 60))" \
			"$PYTHON" "$MONITOR" --hostapd "$HOSTAPD" \
			--config "$conf" --quiet \
			--ledger-json "$out" >"$log" 2>&1
		rc=$?

		if [ ! -s "$out" ]; then
			# No ledger at all: hostapd never got far enough to emit
			# one. Say so rather than letting it count as a run.
			"$PYTHON" - "$out" "$rc" "$log" <<'PY'
import json, sys
out, rc, log = sys.argv[1], int(sys.argv[2]), sys.argv[3]
try:
    tail = open(log, errors="replace").read()[-2000:]
except OSError:
    tail = ""
json.dump({"startup_failed": True, "returncode": rc, "log_tail": tail},
          open(out, "w"), indent=1)
PY
			echo "refused (rc=$rc)"
		else
			hits=$("$PYTHON" -c 'import json,sys; d=json.load(open(sys.argv[1])); print(len(d.get("targets") or []))' "$out")
			echo "$hits target(s)"
		fi
	done
fi

echo
"$PYTHON" "$ROOT/fuzzing/axes/profiles.py" report "$PROFILES"
