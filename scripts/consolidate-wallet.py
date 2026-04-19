#!/usr/bin/env python3
"""
Consolidate small UTXOs in a Dilithion wallet.

Fires consolidateutxos RPC in a loop until the count of "small" UTXOs falls
below a target threshold. Designed for wallets that have accumulated many
dust-sized outputs (e.g., from mining dev rewards) and can no longer pay
large amounts because every tx hits the 1 MB mempool cap at ~188 Dilithium
inputs per transaction.

Usage:
  python scripts/consolidate-wallet.py [options]

Prerequisites:
  - Dilithion node running with RPC enabled
  - Wallet unlocked (use walletpassphrase before running, or unlock via UI)
  - Node built from commit c6e7ef4 or later (consolidateutxos filters locked
    coins — earlier versions will produce double-spend rejects on back-to-back
    calls).
"""

import argparse
import base64
import json
import signal
import sys
import time
import urllib.error
import urllib.request


# ions -> DIL
IONS_PER_DIL = 100_000_000


class RPCError(Exception):
    def __init__(self, code, message, full):
        super().__init__(f"RPC error {code}: {message}")
        self.code = code
        self.message = message
        self.full = full


def rpc_call(url, user, password, method, params):
    """Make a single RPC call. Returns the 'result' field on success."""
    body = json.dumps({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    }).encode("utf-8")

    auth = base64.b64encode(f"{user}:{password}".encode("utf-8")).decode("ascii")
    req = urllib.request.Request(url, data=body, method="POST", headers={
        "Content-Type": "application/json",
        "X-Dilithion-RPC": "1",
        "Authorization": f"Basic {auth}",
    })

    with urllib.request.urlopen(req, timeout=120) as resp:
        text = resp.read().decode("utf-8")

    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as e:
        raise RPCError(-1, f"invalid JSON response: {text[:200]}", text) from e

    if parsed.get("error"):
        err = parsed["error"]
        raise RPCError(err.get("code", -1), err.get("message", "unknown"), parsed)
    return parsed.get("result")


def count_small_utxos(url, user, password, small_dil):
    """Return (small_count, total_utxos, total_value_ions)."""
    utxos = rpc_call(url, user, password, "listunspent", [])
    total_value = 0
    small = 0
    for u in utxos:
        amt_ions = int(round(u["amount"] * IONS_PER_DIL))
        total_value += amt_ions
        if u["amount"] < small_dil:
            small += 1
    return small, len(utxos), total_value


def check_wallet(url, user, password):
    """Raise if wallet is locked or RPC isn't available."""
    info = rpc_call(url, user, password, "getwalletinfo", [])
    if info.get("encrypted") and info.get("locked"):
        raise RuntimeError(
            "Wallet is locked. Unlock via the web wallet or "
            "`walletpassphrase \"<pass>\" <seconds>` before running this script."
        )
    return info


def fmt_dil(ions):
    return f"{ions / IONS_PER_DIL:.8f}"


def main():
    p = argparse.ArgumentParser(
        description="Incrementally consolidate small UTXOs until under a target count.",
    )
    p.add_argument("--chain", choices=["dil", "dilv"], default="dil",
                   help="Sets RPC port default: dil=8332, dilv=9332 (default: dil)")
    p.add_argument("--rpc-url",
                   help="Full RPC URL. Overrides --chain defaults.")
    p.add_argument("--rpc-user", default="rpc")
    p.add_argument("--rpc-pass", default="rpc")
    p.add_argument("--max-inputs", type=int, default=180,
                   help="Inputs per consolidation tx. Max 200 (RPC caps). "
                        "180 leaves margin under the 1 MB mempool limit. "
                        "(default: 180)")
    p.add_argument("--small-dil", type=float, default=5.0,
                   help="A UTXO is 'small' if its value < this many DIL. "
                        "(default: 5.0)")
    p.add_argument("--target-small", type=int, default=200,
                   help="Stop when the wallet has fewer than this many small "
                        "UTXOs left. (default: 200)")
    p.add_argument("--interval", type=float, default=10.0,
                   help="Seconds between consolidation calls. Lower = faster "
                        "but risks mempool saturation. (default: 10)")
    p.add_argument("--max-rounds", type=int, default=500,
                   help="Safety cap: abort after N consolidations. (default: 500)")
    p.add_argument("--dry-run", action="store_true",
                   help="Print the plan and exit without firing any RPCs.")
    args = p.parse_args()

    if args.rpc_url:
        url = args.rpc_url
    else:
        port = 8332 if args.chain == "dil" else 9332
        url = f"http://127.0.0.1:{port}/"

    print(f"Target node:    {url}")
    print(f"Chain:          {args.chain}")
    print(f"Max inputs/tx:  {args.max_inputs}")
    print(f"'Small' UTXO:   < {args.small_dil} DIL")
    print(f"Stop when small UTXOs <= {args.target_small}")
    print(f"Interval:       {args.interval}s")
    print(f"Max rounds:     {args.max_rounds}")
    print()

    # Preflight: wallet reachable + unlocked, snapshot baseline.
    try:
        check_wallet(url, args.rpc_user, args.rpc_pass)
    except (RPCError, urllib.error.URLError, RuntimeError) as e:
        print(f"Preflight failed: {e}", file=sys.stderr)
        sys.exit(2)

    small0, total0, value0 = count_small_utxos(
        url, args.rpc_user, args.rpc_pass, args.small_dil)
    print(f"Baseline:       {total0} UTXOs, {small0} small "
          f"(< {args.small_dil} DIL), total {fmt_dil(value0)} DIL")

    if small0 <= args.target_small:
        print(f"Already below target ({small0} <= {args.target_small}). Nothing to do.")
        return

    to_consolidate = small0 - args.target_small
    est_rounds = (to_consolidate + args.max_inputs - 1) // args.max_inputs
    est_minutes = est_rounds * args.interval / 60.0
    # Rough fee estimate: each consolidation ~ max_inputs × 5308 bytes × 5 ions/byte
    est_fee_per_round = args.max_inputs * 5308 * 5
    est_total_fee = est_rounds * est_fee_per_round
    print(f"Estimate:       ~{est_rounds} rounds, ~{est_minutes:.1f} min, "
          f"~{fmt_dil(est_total_fee)} DIL in fees")
    print()

    if args.dry_run:
        print("--dry-run set, exiting without doing anything.")
        return

    # Graceful Ctrl-C: print summary before exiting.
    stop = {"requested": False}

    def handle_sigint(_sig, _frame):
        if stop["requested"]:
            print("\nForce-exit.", file=sys.stderr)
            sys.exit(130)
        print("\nCtrl-C received. Finishing current round then stopping...",
              file=sys.stderr)
        stop["requested"] = True

    signal.signal(signal.SIGINT, handle_sigint)

    start = time.time()
    rounds = 0
    total_inputs_consolidated = 0
    total_fee_ions = 0
    consecutive_errors = 0

    while rounds < args.max_rounds:
        if stop["requested"]:
            break

        # Check where we are.
        try:
            small, total, _value = count_small_utxos(
                url, args.rpc_user, args.rpc_pass, args.small_dil)
        except (RPCError, urllib.error.URLError) as e:
            consecutive_errors += 1
            print(f"[round {rounds+1}] count query failed: {e} "
                  f"(consecutive errors: {consecutive_errors})", file=sys.stderr)
            if consecutive_errors >= 5:
                print("Too many consecutive errors, aborting.", file=sys.stderr)
                sys.exit(3)
            time.sleep(min(args.interval * consecutive_errors, 60))
            continue

        if small <= args.target_small:
            print(f"\nDone: {small} small UTXOs left (target <= {args.target_small}).")
            break

        rounds += 1
        # Re-check wallet still unlocked before firing.
        try:
            winfo = rpc_call(url, args.rpc_user, args.rpc_pass, "getwalletinfo", [])
        except (RPCError, urllib.error.URLError) as e:
            print(f"[round {rounds}] walletinfo failed: {e}", file=sys.stderr)
            time.sleep(args.interval)
            continue

        if winfo.get("encrypted") and winfo.get("locked"):
            print(f"[round {rounds}] Wallet locked. Waiting 30s...", file=sys.stderr)
            time.sleep(30)
            continue

        # Fire consolidation.
        try:
            result = rpc_call(url, args.rpc_user, args.rpc_pass,
                              "consolidateutxos",
                              {"max_inputs": args.max_inputs})
        except RPCError as e:
            # Non-fatal cases we recover from:
            msg = e.message.lower() if e.message else ""
            if "nothing to consolidate" in msg:
                print(f"[round {rounds}] {e.message} — stopping.", file=sys.stderr)
                break
            consecutive_errors += 1
            print(f"[round {rounds}] consolidateutxos failed: {e.message} "
                  f"(consecutive errors: {consecutive_errors})", file=sys.stderr)
            if consecutive_errors >= 5:
                print("Too many consecutive errors, aborting.", file=sys.stderr)
                sys.exit(3)
            time.sleep(min(args.interval * consecutive_errors, 60))
            continue
        except urllib.error.URLError as e:
            consecutive_errors += 1
            print(f"[round {rounds}] network error: {e}", file=sys.stderr)
            time.sleep(min(args.interval * consecutive_errors, 60))
            continue

        consecutive_errors = 0
        inputs = int(result.get("inputs_consolidated", 0))
        fee_raw = result.get("fee", "0")
        try:
            fee_ions = int(round(float(fee_raw) * IONS_PER_DIL))
        except (TypeError, ValueError):
            fee_ions = 0
        total_inputs_consolidated += inputs
        total_fee_ions += fee_ions

        remaining = small - inputs  # approximate — some consumed UTXOs might be above threshold
        print(f"[round {rounds}] consolidated {inputs} inputs, "
              f"fee {fmt_dil(fee_ions)} DIL, "
              f"txid {result.get('txid', '?')[:16]}... "
              f"(~{remaining} small UTXOs left)")

        time.sleep(args.interval)

    # Final summary.
    elapsed = time.time() - start
    try:
        small_final, total_final, value_final = count_small_utxos(
            url, args.rpc_user, args.rpc_pass, args.small_dil)
    except Exception:
        small_final = total_final = value_final = None

    print()
    print("=" * 60)
    print(f"Rounds:                 {rounds}")
    print(f"Inputs consolidated:    {total_inputs_consolidated}")
    print(f"Total fees spent:       {fmt_dil(total_fee_ions)} DIL")
    print(f"Elapsed:                {elapsed/60:.1f} min")
    if small_final is not None:
        print(f"Small UTXOs: {small0} -> {small_final} "
              f"(-{small0 - small_final})")
        print(f"Total UTXOs: {total0} -> {total_final} "
              f"(-{total0 - total_final})")
        print(f"Wallet value: {fmt_dil(value0)} -> {fmt_dil(value_final)} DIL")
    print("=" * 60)


if __name__ == "__main__":
    main()
