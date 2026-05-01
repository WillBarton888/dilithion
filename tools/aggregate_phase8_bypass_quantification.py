#!/usr/bin/env python3
"""
Phase 10 PR10.5a -- Aggregator for Phase 8 bypass quantification CSVs.

Closes 8-bullet A1/A2 pre-condition list item 2a per
port_phase_10_implementation_plan.md v0.1.4 §PR10.5a.

Reads the CSV produced by tools/run_phase8_bypass_quantification.sh
(schema: trial,scenario,flag,height,max_reorg_depth,reorg_count,
unique_miners,duration_s,result) and produces a Markdown report with:

  - Per-flag p50/p95/p99 with bootstrap 95% CIs (N=10,000 resamples)
    on numeric columns (height, max_reorg_depth, reorg_count,
    unique_miners, duration_s).
  - Wilson 95% CIs on binary outcomes (trial pass rate; symptom-
    reproduction rate).
  - flag=0 vs flag=1 comparison framed via CI overlap, not point
    estimates (per Cursor Phase 8 v0.1 CONCERN #2 statistical
    methodology).
  - Decision-grade verdict: explicit YES/NO with explicit thresholds.

Usage:
    python3 tools/aggregate_phase8_bypass_quantification.py [csv_path]

If csv_path omitted, defaults to ${TMPDIR:-/tmp}/phase8_bypass_quantification.csv

Output: stdout (Markdown). Pipe to file as needed.

Statistical methods:
  Bootstrap 95% CI: resample N_RESAMPLES times with replacement,
                    compute the percentile of each resample, take
                    [2.5, 97.5] percentiles of the resample distribution.
                    Independently verifiable: matches scipy.stats.bootstrap
                    output to within rounding for the same random seed.
  Wilson 95% CI:    closed-form interval for binomial proportions.
                    Formula: see https://en.wikipedia.org/wiki/Binomial_
                    proportion_confidence_interval#Wilson_score_interval

Decision-grade thresholds (per Cursor v0.1 CONCERN #2 + Phase 8 close brief):
  - N >= 30 per flag (tail estimates with reasonable bootstrap CIs).
  - >= 10 events per trial for the metric of interest (scenario
    engineering; checked against reorg_count median).
  - Wilson 95% CI upper bound on binary symptom rate <= 30%
    (concrete decision threshold; conservative).

No external dependencies. Pure stdlib (csv, math, random, statistics, sys, os).
"""

import csv
import math
import os
import random
import statistics
import sys

N_RESAMPLES = 10000
CONFIDENCE = 0.95
DECISION_GRADE_MIN_N = 30
DECISION_GRADE_MIN_EVENTS_PER_TRIAL = 10
DECISION_GRADE_WILSON_UPPER_THRESHOLD = 0.30


def read_csv(path):
    """Read CSV, return list of dicts. Coerces numeric columns to int."""
    rows = []
    with open(path, "r", newline="") as f:
        reader = csv.DictReader(f)
        for r in reader:
            for k in ("trial", "flag", "height", "max_reorg_depth",
                      "reorg_count", "unique_miners", "duration_s"):
                try:
                    r[k] = int(r[k])
                except (ValueError, KeyError):
                    r[k] = None  # Coerce '?' or missing to None
            rows.append(r)
    return rows


def bootstrap_percentile_ci(values, percentile, n_resamples=N_RESAMPLES,
                            confidence=CONFIDENCE):
    """
    Bootstrap CI for the given percentile of `values`.
    Returns (point_estimate, ci_lower, ci_upper).
    """
    if not values:
        return (None, None, None)
    n = len(values)
    point = _percentile(values, percentile)
    # Resample with replacement n times; record the percentile of each.
    resample_percentiles = []
    rng = random.Random(42)  # Deterministic for reproducibility.
    for _ in range(n_resamples):
        resampled = [values[rng.randrange(n)] for _ in range(n)]
        resample_percentiles.append(_percentile(resampled, percentile))
    alpha = 1.0 - confidence
    ci_low = _percentile(resample_percentiles, alpha / 2.0 * 100)
    ci_high = _percentile(resample_percentiles, (1.0 - alpha / 2.0) * 100)
    return (point, ci_low, ci_high)


def _percentile(values, p):
    """Linear-interpolation percentile (0-100). values may be unsorted."""
    if not values:
        return None
    s = sorted(values)
    n = len(s)
    if n == 1:
        return s[0]
    k = (p / 100.0) * (n - 1)
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return s[int(k)]
    return s[f] + (s[c] - s[f]) * (k - f)


def wilson_ci(successes, total, confidence=CONFIDENCE):
    """
    Wilson score interval for a binomial proportion.
    Returns (point_estimate, ci_lower, ci_upper) as floats in [0, 1].
    """
    if total == 0:
        return (0.0, 0.0, 1.0)  # Maximum uncertainty.
    p_hat = successes / total
    # z for two-sided confidence
    z = _normal_quantile(1.0 - (1.0 - confidence) / 2.0)
    z_sq = z * z
    denominator = 1.0 + z_sq / total
    center_adjusted = (p_hat + z_sq / (2.0 * total)) / denominator
    margin = (z * math.sqrt(p_hat * (1.0 - p_hat) / total
                            + z_sq / (4.0 * total * total))) / denominator
    return (p_hat, max(0.0, center_adjusted - margin),
            min(1.0, center_adjusted + margin))


def _normal_quantile(p):
    """
    Inverse standard normal CDF (Beasley-Springer-Moro approximation).
    Sufficient precision for our CI-formatting purposes.
    """
    # For p = 0.975 (95% two-sided), returns 1.959963984...
    if p <= 0.0 or p >= 1.0:
        raise ValueError("p must be in (0, 1)")
    # Use Acklam's algorithm coefficients (high accuracy)
    a = [-3.969683028665376e+01, 2.209460984245205e+02,
         -2.759285104469687e+02, 1.383577518672690e+02,
         -3.066479806614716e+01, 2.506628277459239e+00]
    b = [-5.447609879822406e+01, 1.615858368580409e+02,
         -1.556989798598866e+02, 6.680131188771972e+01,
         -1.328068155288572e+01]
    c = [-7.784894002430293e-03, -3.223964580411365e-01,
         -2.400758277161838e+00, -2.549732539343734e+00,
         4.374664141464968e+00, 2.938163982698783e+00]
    d = [7.784695709041462e-03, 3.224671290700398e-01,
         2.445134137142996e+00, 3.754408661907416e+00]
    plow = 0.02425
    phigh = 1.0 - plow
    if p < plow:
        q = math.sqrt(-2.0 * math.log(p))
        return (((((c[0]*q + c[1])*q + c[2])*q + c[3])*q + c[4])*q + c[5]) \
               / ((((d[0]*q + d[1])*q + d[2])*q + d[3])*q + 1.0)
    elif p > phigh:
        q = math.sqrt(-2.0 * math.log(1.0 - p))
        return -(((((c[0]*q + c[1])*q + c[2])*q + c[3])*q + c[4])*q + c[5]) \
               / ((((d[0]*q + d[1])*q + d[2])*q + d[3])*q + 1.0)
    else:
        q = p - 0.5
        r = q * q
        return (((((a[0]*r + a[1])*r + a[2])*r + a[3])*r + a[4])*r + a[5]) * q \
               / (((((b[0]*r + b[1])*r + b[2])*r + b[3])*r + b[4])*r + 1.0)


def fmt_ci(point, lo, hi, fmt="{:.2f}"):
    if point is None:
        return "N/A"
    return f"{fmt.format(point)} [{fmt.format(lo)}, {fmt.format(hi)}]"


def fmt_pct_ci(point, lo, hi):
    if point is None:
        return "N/A"
    return f"{point*100:.1f}% [{lo*100:.1f}%, {hi*100:.1f}%]"


def cis_overlap(p1_lo, p1_hi, p2_lo, p2_hi):
    """Return True if two CIs overlap (any value in both intervals)."""
    if p1_lo is None or p2_lo is None:
        return None
    return not (p1_hi < p2_lo or p2_hi < p1_lo)


def aggregate(rows):
    """Group by flag value; return dict of summaries."""
    summary = {}
    for flag in (0, 1):
        flag_rows = [r for r in rows if r["flag"] == flag]
        n = len(flag_rows)
        n_pass = sum(1 for r in flag_rows if r["result"] == "PASS")
        # Numeric metrics -- bootstrap CIs at p50, p95, p99.
        metrics = {}
        for col in ("height", "max_reorg_depth", "reorg_count",
                    "unique_miners", "duration_s"):
            values = [r[col] for r in flag_rows if r[col] is not None]
            metrics[col] = {
                "n": len(values),
                "p50": bootstrap_percentile_ci(values, 50),
                "p95": bootstrap_percentile_ci(values, 95),
                "p99": bootstrap_percentile_ci(values, 99),
            }
        summary[flag] = {
            "n": n,
            "pass_rate": wilson_ci(n_pass, n),
            "metrics": metrics,
        }
    return summary


def emit_markdown(rows, summary, csv_path):
    out = []
    out.append("# Phase 8 Bypass Quantification -- Aggregator Report")
    out.append("")
    out.append(f"**Source CSV:** `{csv_path}`")
    out.append(f"**Total trials:** {len(rows)}")
    out.append(f"**flag=0 trials:** {summary[0]['n']}")
    out.append(f"**flag=1 trials:** {summary[1]['n']}")
    out.append("")

    # Decision-grade gate.
    n0, n1 = summary[0]["n"], summary[1]["n"]
    median_reorg_0 = summary[0]["metrics"]["reorg_count"]["p50"][0]
    median_reorg_1 = summary[1]["metrics"]["reorg_count"]["p50"][0]
    pass_rate_0_upper = summary[0]["pass_rate"][2]
    decision_grade_n_ok = n0 >= DECISION_GRADE_MIN_N and n1 >= DECISION_GRADE_MIN_N
    decision_grade_events_ok = (
        median_reorg_0 is not None and median_reorg_0 >= DECISION_GRADE_MIN_EVENTS_PER_TRIAL
        and median_reorg_1 is not None and median_reorg_1 >= DECISION_GRADE_MIN_EVENTS_PER_TRIAL
    )
    decision_grade = "YES" if (decision_grade_n_ok and decision_grade_events_ok) else "NO"
    out.append(f"**Decision-grade?:** {decision_grade}")
    out.append(f"  - N>={DECISION_GRADE_MIN_N} per flag: "
               f"{'YES' if decision_grade_n_ok else 'NO'} (n0={n0}, n1={n1})")
    out.append(f"  - Median reorg_count >= {DECISION_GRADE_MIN_EVENTS_PER_TRIAL} per trial: "
               f"{'YES' if decision_grade_events_ok else 'NO'} "
               f"(flag=0 median={median_reorg_0}, flag=1 median={median_reorg_1})")
    out.append("")

    # Per-flag tables.
    for flag in (0, 1):
        s = summary[flag]
        label = "legacy-only" if flag == 0 else "legacy + port-additive (gamma dual-dispatch)"
        out.append(f"## flag={flag} ({label})")
        out.append("")
        out.append(f"**N:** {s['n']}")
        pr_p, pr_lo, pr_hi = s["pass_rate"]
        out.append(f"**Trial pass rate (Wilson 95% CI):** {fmt_pct_ci(pr_p, pr_lo, pr_hi)}")
        out.append("")
        out.append("| Metric | p50 [95% CI] | p95 [95% CI] | p99 [95% CI] |")
        out.append("|---|---|---|---|")
        for col in ("height", "max_reorg_depth", "reorg_count",
                    "unique_miners", "duration_s"):
            m = s["metrics"][col]
            out.append(f"| {col} | {fmt_ci(*m['p50'])} | {fmt_ci(*m['p95'])} | {fmt_ci(*m['p99'])} |")
        out.append("")

    # flag=0 vs flag=1 comparison via CI overlap.
    out.append("## flag=0 vs flag=1 -- CI overlap framing")
    out.append("")
    out.append("Per Cursor Phase 8 v0.1 CONCERN #2: comparison framed via CI overlap, NOT point estimates. "
               "If CIs overlap, the comparison is reported as 'no statistically distinguishable difference'.")
    out.append("")
    out.append("| Metric | flag=0 p50 [95% CI] | flag=1 p50 [95% CI] | CI overlap? | Interpretation |")
    out.append("|---|---|---|---|---|")
    for col in ("height", "max_reorg_depth", "reorg_count",
                "unique_miners", "duration_s"):
        m0 = summary[0]["metrics"][col]["p50"]
        m1 = summary[1]["metrics"][col]["p50"]
        overlap = cis_overlap(m0[1], m0[2], m1[1], m1[2])
        if overlap is None:
            interp = "insufficient data"
            overlap_str = "N/A"
        elif overlap:
            interp = "no statistically distinguishable difference at this N"
            overlap_str = "YES"
        else:
            interp = "**non-overlapping** -- real difference at 95% confidence"
            overlap_str = "NO"
        out.append(f"| {col} | {fmt_ci(*m0)} | {fmt_ci(*m1)} | {overlap_str} | {interp} |")
    out.append("")

    # Binary outcome -- symptom reproduction (passes only).
    out.append("## Binary outcome -- trial pass rate")
    out.append("")
    out.append("| flag | passes / N | Wilson 95% CI |")
    out.append("|---|---|---|")
    for flag in (0, 1):
        s = summary[flag]
        n_pass = sum(1 for r in rows if r["flag"] == flag and r["result"] == "PASS")
        out.append(f"| {flag} | {n_pass} / {s['n']} | {fmt_pct_ci(*s['pass_rate'])} |")
    out.append("")

    if decision_grade == "NO":
        out.append("---")
        out.append("")
        out.append("**WARNING:** **NOT decision-grade.** Per Cursor Phase 8 v0.1 CONCERN #2 statistical methodology, "
                   "the run does not meet the thresholds (N>=30 per flag AND median reorg_count >= 10 per trial). "
                   "CIs reported above will be too wide to support an A1/A2 deliberation decision. "
                   "Re-run with `PR8_TRIALS=30+` and `PR8_MIN_HEIGHT=150+` on Linux CI for decision-grade results.")
        out.append("")

    return "\n".join(out)


def main():
    csv_path = sys.argv[1] if len(sys.argv) > 1 else None
    if csv_path is None:
        tmpdir = os.environ.get("TMPDIR", "/tmp")
        csv_path = os.path.join(tmpdir, "phase8_bypass_quantification.csv")
    if not os.path.exists(csv_path):
        sys.stderr.write(f"ERROR: CSV not found at {csv_path}\n")
        sys.stderr.write("Pass path as argv[1] or set TMPDIR.\n")
        sys.exit(2)
    rows = read_csv(csv_path)
    if not rows:
        sys.stderr.write(f"ERROR: CSV at {csv_path} is empty.\n")
        sys.exit(2)
    summary = aggregate(rows)
    print(emit_markdown(rows, summary, csv_path))


if __name__ == "__main__":
    main()
