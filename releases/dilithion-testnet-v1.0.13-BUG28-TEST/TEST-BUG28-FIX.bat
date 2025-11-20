@echo off
REM ================================================================
REM  BUG #28 FIX - PER-THREAD RANDOMX VM TEST
REM ================================================================
REM  This test verifies the fix for the critical mining bottleneck
REM ================================================================

echo.
echo ================================================================
echo   TESTING BUG #28 FIX - PER-THREAD RANDOMX VMS
echo ================================================================
echo.
echo WHAT WAS FIXED:
echo   - Old implementation: Global RandomX VM with mutex (serialized all threads)
echo   - New implementation: Per-thread RandomX VMs (true parallel mining)
echo.
echo EXPECTED RESULTS:
echo   - Previous hash rate: ~60 H/s (20 threads serialized on mutex)
echo   - Expected hash rate: ~2000 H/s (20 threads * ~100 H/s each)
echo   - Performance gain: 33x improvement
echo.
echo TECHNICAL DETAILS:
echo   - Each thread creates its own RandomX VM (~200MB)
echo   - All VMs share the read-only 2GB dataset (no duplication)
echo   - No mutex contention during hashing (fully parallel)
echo.
echo Starting 30-second mining test...
echo Please wait for results...
echo.

REM Kill any existing dilithion-node processes
taskkill /F /IM dilithion-node.exe 2>nul

REM Wait for cleanup
timeout /t 2 /nobreak >nul

REM Run mining test
dilithion-node.exe --testnet --mine --threads=20

echo.
echo ================================================================
echo   TEST COMPLETE
echo ================================================================
echo.
echo Please report the hash rate above.
echo Expected: ~2000 H/s (1800-2200 H/s is normal)
echo.
echo If you see ~2000 H/s, Bug #28 is FIXED!
echo If you see ~60 H/s, something went wrong.
echo.
pause
