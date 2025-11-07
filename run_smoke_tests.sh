#!/bin/bash
# Smoke test all 9 working fuzzers

echo '=== SMOKE TESTS: 9 Working Fuzzers ==='
echo

for fuzzer in fuzz_sha3 fuzz_tx_validation fuzz_utxo fuzz_difficulty fuzz_transaction fuzz_block fuzz_merkle fuzz_subsidy fuzz_compactsize; do
  corpus=
  echo "[21:33:28] Testing ..."
  mkdir -p fuzz_corpus/
  timeout 30 ./ -max_total_time=30 fuzz_corpus// > /tmp/.log 2>&1
  if [ 0 -le 124 ]; then
    rate=
    echo "  PASS -  exec/s"
  else
    echo "  FAIL"
  fi
done

echo
echo '=== SMOKE TESTS COMPLETE ==='
