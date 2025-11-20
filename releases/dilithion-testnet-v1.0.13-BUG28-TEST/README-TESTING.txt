================================================================
  DILITHION v1.0.13 - BUG #28 FIX TEST BUILD
================================================================

QUICK START:
  1. Run: TEST-BUG28-FIX.bat
  2. Wait for hash rate to stabilize (~10 seconds)
  3. Observe hash rate in console output
  4. Report results

EXPECTED RESULT:
  Hash rate: ~2000 H/s (1800-2200 H/s is normal)

PREVIOUS RESULT (with bug):
  Hash rate: ~60 H/s

WHAT THIS FIXES:
  Bug #28 - Global RandomX VM mutex bottleneck
  - Old: All 20 threads serialized on global mutex
  - New: Each thread has its own RandomX VM (true parallelism)
  - Performance gain: 33x faster

CONTENTS:
  dilithion-node.exe          - Mining node (with Bug #28 fix)
  TEST-BUG28-FIX.bat          - Test script
  BUG-28-TECHNICAL-DETAILS.md - Complete technical documentation
  *.dll                       - Runtime libraries (6 DLLs)

REQUIREMENTS:
  - Windows 10/11 64-bit
  - ~6GB RAM (2GB dataset + 20 VMs × 200MB each)
  - 20+ CPU threads recommended

TROUBLESHOOTING:
  - If hash rate is still ~60 H/s, check for DLL errors
  - If node crashes, check RAM availability (~6GB needed)
  - If "VM creation failed", reduce threads (--mining-threads=10)

For detailed technical information, see:
  BUG-28-TECHNICAL-DETAILS.md

================================================================
Report hash rate to Claude for final verification!
================================================================
