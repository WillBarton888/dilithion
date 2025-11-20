@echo off
REM Test Bug #28 fix - Per-thread RandomX VMs
REM Expected: ~2000 H/s (20 threads * ~100 H/s per thread)

echo.
echo ================================================================
echo   TESTING BUG #28 FIX - PER-THREAD RANDOMX VMS
echo ================================================================
echo.
echo Expected hash rate: ~2000 H/s (20 threads in FULL mode)
echo Previous hash rate: ~60 H/s (global mutex bottleneck)
echo.
echo Starting 20-second mining test...
echo.

REM Kill any existing dilithion-node processes
taskkill /F /IM dilithion-node.exe 2>nul

REM Run mining test for 20 seconds
timeout /t 2 /nobreak >nul
start /B release-binaries\windows\dilithion-node.exe --testnet --mine --mining-threads=20 --testnet-wipe-if-bad-genesis > test-bug28-output.txt 2>&1
timeout /t 20 /nobreak

REM Kill the process
taskkill /F /IM dilithion-node.exe 2>nul

REM Wait for file to be written
timeout /t 2 /nobreak >nul

echo.
echo ================================================================
echo   TEST RESULTS
echo ================================================================
echo.

REM Show hash rate stats
type test-bug28-output.txt | findstr /C:"Hash rate" /C:"H/s" /C:"[FULL MODE]" /C:"RandomX" /C:"Mining started" /C:"BUG #28"

echo.
echo Full output saved to: test-bug28-output.txt
echo.
