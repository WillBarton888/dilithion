#!/bin/bash
# Phase 8 PR8.4 — bypass quantification under --usenewpeerman=1.
#
# Runs the 4-node regtest harness N times under each flag value
# (USE_NEW_PEERMAN=0 control vs USE_NEW_PEERMAN=1 port path) and captures
# per-trial metrics for statistical comparison. Produces CSV output for
# downstream aggregation (bootstrap CIs in a Python/R analysis step, or
# direct percentile reporting in the results doc).
#
# Per Cursor v0.1 CONCERN #2 statistical methodology refinement
# (port_phase_8_implementation_plan.md v0.1.1 §PR8.4):
#   - Scenario engineering for ≥10× event rate per trial (stress
#     scenario uses dual-mining; reorg events occur every few blocks)
#   - N ≥ 30 trials per scenario for tail estimates (this script supports
#     any N via PR8_TRIALS env var)
#   - Bootstrap 95% CIs computed downstream (not in this bash; use the
#     CSV with a separate Python/R aggregator)
#   - Wilson CIs on binary outcomes computed downstream
#
# IMPORTANT v0.1.3 caveat (Phase 7 close brief structural finding): under
# γ dual-dispatch, flag=1 fires BOTH legacy AND port adapter; the bypass
# is operationally LOAD-BEARING only at Phase 9+ when legacy retires.
# Today's flag=0-vs-flag=1 comparison measures legacy-only vs legacy+port-
# additive — useful baseline data, but not a full bypass-isolation
# measurement. The results doc must label this honestly.
#
# Usage:
#   PR8_TRIALS=N bash tools/run_phase8_bypass_quantification.sh [SCENARIO]
#     SCENARIO defaults to "stress" (dual-miner).
#     PR8_TRIALS defaults to 5 (demonstration).
#     For decision-grade: set PR8_TRIALS=30+ + dedicate a Linux CI run.
#
# Output:
#   ${TMPDIR:-/tmp}/phase8_bypass_quantification.csv — one row per trial:
#     trial,scenario,flag,height,max_reorg_depth,reorg_count,unique_miners,duration_s,result
#   stdout — progress + summary

set -u

SCENARIO="${1:-stress}"
TRIALS="${PR8_TRIALS:-5}"
MIN_HEIGHT="${PR8_MIN_HEIGHT:-30}"
MAX_WAIT="${PR8_MAX_WAIT:-180}"

REPO="$(cd "$(dirname "$0")/.." && pwd)"
HARNESS="$REPO/scripts/four_node_local.sh"

if [[ ! -x "$HARNESS" ]]; then
    echo "ERROR: harness not found / not executable: $HARNESS" >&2
    exit 2
fi

CSV_OUT="${TMPDIR:-/tmp}/phase8_bypass_quantification.csv"
echo "trial,scenario,flag,height,max_reorg_depth,reorg_count,unique_miners,duration_s,result" > "$CSV_OUT"

echo "=== Phase 8 PR8.4 bypass quantification ==="
echo "Scenario:     $SCENARIO"
echo "Trials/flag:  $TRIALS"
echo "Min height:   $MIN_HEIGHT"
echo "Max wait:     ${MAX_WAIT}s"
echo "CSV output:   $CSV_OUT"
echo

# ============================================================================
# Per-trial helper — runs harness once, parses metrics from output
# ============================================================================
run_trial() {
    local trial=$1
    local flag=$2
    local out=$(mktemp)
    local start=$(date +%s)
    USE_NEW_PEERMAN=$flag bash "$HARNESS" "$SCENARIO" "$MIN_HEIGHT" "$MAX_WAIT" >"$out" 2>&1
    local exit_code=$?
    local end=$(date +%s)
    local duration=$(( end - start ))

    # Parse metrics from harness output. Defaults to "?" or "0" on missing.
    local height=$(grep -oP "Node A height: \K[0-9]+" "$out" | head -1 || echo "?")
    local max_reorg=$(grep -oP "max depth: \K[0-9]+" "$out" | head -1 || echo "0")
    local reorg_count=$(grep -oP "Total reorg events: \K[0-9]+" "$out" | head -1 || echo "0")
    local unique_miners=$(grep -oP "Unique miners observed: \K[0-9]+" "$out" | head -1 || echo "0")
    local result="UNKNOWN"
    if grep -q "RESULT: 4-node integration test PASSED" "$out"; then
        result="PASS"
    elif grep -q "RESULT: 4-node integration test FAILED" "$out"; then
        result="FAIL"
    elif grep -q "RESULT: DIVERGENT" "$out"; then
        result="DIVERGENT"
    elif grep -q "RESULT: CHAIN-TOO-SHALLOW" "$out"; then
        result="CHAIN-TOO-SHALLOW"
    fi

    echo "$trial,$SCENARIO,$flag,$height,$max_reorg,$reorg_count,$unique_miners,$duration,$result" >> "$CSV_OUT"
    printf "  trial=%2d flag=%d height=%s reorg_max=%s reorg_count=%s miners=%s dur=%ss result=%s\n" \
        "$trial" "$flag" "$height" "$max_reorg" "$reorg_count" "$unique_miners" "$duration" "$result"

    rm -f "$out"
    return $exit_code
}

# ============================================================================
# Run trials: alternating flag=0 and flag=1 to even out any host-load drift
# ============================================================================
echo "Trials (flag=0 = legacy only; flag=1 = legacy + port-adapter additive):"
for ((i=1; i<=TRIALS; i++)); do
    run_trial "$i" 0 || true  # don't propagate harness exit code; parsed result is what matters
    run_trial "$i" 1 || true
done

# ============================================================================
# Summary stats (median; bootstrap CIs left to downstream Python)
# ============================================================================
echo
echo "=== Summary (median values across $TRIALS trials per flag) ==="
echo "  flag | height | reorg_max | reorg_count | unique_miners | duration_s | pass_rate"
for flag in 0 1; do
    local_med_height=$(awk -F, -v f=$flag '$3==f && $4!="?" {print $4}' "$CSV_OUT" | sort -n | awk 'BEGIN{c=0} {a[c++]=$1} END{if(c>0)print a[int(c/2)]; else print "?"}')
    local_med_reorg_max=$(awk -F, -v f=$flag '$3==f && $5!="?" {print $5}' "$CSV_OUT" | sort -n | awk 'BEGIN{c=0} {a[c++]=$1} END{if(c>0)print a[int(c/2)]; else print "?"}')
    local_med_reorg_count=$(awk -F, -v f=$flag '$3==f && $6!="?" {print $6}' "$CSV_OUT" | sort -n | awk 'BEGIN{c=0} {a[c++]=$1} END{if(c>0)print a[int(c/2)]; else print "?"}')
    local_med_miners=$(awk -F, -v f=$flag '$3==f && $7!="?" {print $7}' "$CSV_OUT" | sort -n | awk 'BEGIN{c=0} {a[c++]=$1} END{if(c>0)print a[int(c/2)]; else print "?"}')
    local_med_duration=$(awk -F, -v f=$flag '$3==f && $8!="?" {print $8}' "$CSV_OUT" | sort -n | awk 'BEGIN{c=0} {a[c++]=$1} END{if(c>0)print a[int(c/2)]; else print "?"}')
    local_pass_count=$(awk -F, -v f=$flag '$3==f && $9=="PASS"' "$CSV_OUT" | wc -l)
    local_total=$(awk -F, -v f=$flag '$3==f' "$CSV_OUT" | wc -l)
    local_pass_rate=$(awk "BEGIN { if ($local_total > 0) printf \"%.0f%%\", $local_pass_count * 100 / $local_total; else print \"?\" }")
    printf "    %d   |  %5s |    %5s  |     %5s   |     %5s     |    %5ss  |   %s (%d/%d)\n" \
        "$flag" "$local_med_height" "$local_med_reorg_max" "$local_med_reorg_count" \
        "$local_med_miners" "$local_med_duration" "$local_pass_rate" "$local_pass_count" "$local_total"
done

echo
echo "Raw CSV: $CSV_OUT"
echo "For decision-grade analysis (bootstrap 95% CIs, Wilson CIs): pipe CSV"
echo "through tools/aggregate_phase8_bypass_quantification.py (TODO; not"
echo "blocking — bash medians above are sufficient for sanity check)."
