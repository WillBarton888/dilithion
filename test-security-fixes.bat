@echo off
REM ========================================================
REM WINDOWS SECURITY FIXES VALIDATION TEST SUITE
REM Tests all CRITICAL and HIGH priority Windows fixes
REM ========================================================

setlocal enabledelayedexpansion

set TESTS_PASSED=0
set TESTS_FAILED=0
set TESTS_TOTAL=0

color 0B
cls
echo.
echo ========================================================
echo   DILITHION WINDOWS SECURITY VALIDATION
echo ========================================================
echo.

REM ========================================================
REM TEST 1: Command Injection Protection
REM ========================================================
echo [TEST CATEGORY] Command Injection Protection
echo.

REM Test 1.1: Check for validation in SETUP-AND-START.bat
findstr /C:"valid=0" SETUP-AND-START.bat >nul 2>&1
if %errorlevel% equ 0 (
    call :test_pass "Command injection validation exists"
) else (
    call :test_fail "Command injection validation missing"
)

findstr /C:"for /L" SETUP-AND-START.bat >nul 2>&1
if %errorlevel% equ 0 (
    call :test_pass "Numeric validation loop found"
) else (
    call :test_fail "Numeric validation loop missing"
)

findstr /C:"Invalid Input" SETUP-AND-START.bat >nul 2>&1
if %errorlevel% equ 0 (
    call :test_pass "Input rejection error message exists"
) else (
    call :test_fail "Input rejection error message missing"
)

echo.

REM ========================================================
REM TEST 2: TEMP Directory Validation
REM ========================================================
echo [TEST CATEGORY] TEMP Directory Validation
echo.

findstr /C:"not defined TEMP" dilithion-wallet.bat >nul 2>&1
if %errorlevel% equ 0 (
    call :test_pass "TEMP variable validation exists"
) else (
    call :test_fail "TEMP variable validation missing"
)

findstr /C:"not exist" dilithion-wallet.bat | findstr /C:"TEMP" >nul 2>&1
if %errorlevel% equ 0 (
    call :test_pass "TEMP directory existence check found"
) else (
    call :test_fail "TEMP directory existence check missing"
)

echo.

REM ========================================================
REM TEST 3: RPC Environment Variable Validation
REM ========================================================
echo [TEST CATEGORY] RPC Environment Variable Validation
echo.

findstr /C:"DILITHION_RPC_HOST" dilithion-wallet.bat | findstr /C:"suspicious" >nul 2>&1
if %errorlevel% equ 0 (
    call :test_pass "RPC_HOST validation exists"
) else (
    call :test_fail "RPC_HOST validation missing"
)

findstr /C:"findstr /R" dilithion-wallet.bat >nul 2>&1
if %errorlevel% equ 0 (
    call :test_pass "Character validation regex found"
) else (
    call :test_fail "Character validation regex missing"
)

echo.

REM ========================================================
REM TEST 4: Binary Existence Checks
REM ========================================================
echo [TEST CATEGORY] Binary Existence Checks
echo.

findstr /C:"not exist" START-MINING.bat | findstr /C:"dilithion-node.exe" >nul 2>&1
if %errorlevel% equ 0 (
    call :test_pass "Binary check in START-MINING.bat"
) else (
    call :test_fail "Binary check missing in START-MINING.bat"
)

findstr /C:"not exist" SETUP-AND-START.bat | findstr /C:"dilithion-node.exe" >nul 2>&1
if %errorlevel% equ 0 (
    call :test_pass "Binary check in SETUP-AND-START.bat"
) else (
    call :test_fail "Binary check missing in SETUP-AND-START.bat"
)

echo.

REM ========================================================
REM TEST 5: curl Detection
REM ========================================================
echo [TEST CATEGORY] curl Detection and Error Messages
echo.

findstr /C:"where curl" dilithion-wallet.bat >nul 2>&1
if %errorlevel% equ 0 (
    call :test_pass "curl detection attempt (PATH)"
) else (
    call :test_fail "curl PATH detection missing"
)

findstr /C:"Windows\System32\curl.exe" dilithion-wallet.bat >nul 2>&1
if %errorlevel% equ 0 (
    call :test_pass "curl detection (System32)"
) else (
    call :test_fail "curl System32 detection missing"
)

findstr /C:"Git\mingw64\bin\curl.exe" dilithion-wallet.bat >nul 2>&1
if %errorlevel% equ 0 (
    call :test_pass "curl detection (Git for Windows)"
) else (
    call :test_fail "curl Git detection missing"
)

findstr /C:"Windows 10 pre-1803" dilithion-wallet.bat >nul 2>&1
if %errorlevel% equ 0 (
    call :test_pass "Windows 10 pre-1803 guidance"
) else (
    call :test_fail "Pre-1803 guidance missing"
)

echo.

REM ========================================================
REM TEST 6: Error Message Quality
REM ========================================================
echo [TEST CATEGORY] Error Message Quality
echo.

findstr /C:"discord.gg/dilithion" START-MINING.bat >nul 2>&1
if %errorlevel% equ 0 (
    call :test_pass "Discord support link in START-MINING.bat"
) else (
    call :test_fail "Discord support link missing"
)

findstr /C:"discord.gg/dilithion" SETUP-AND-START.bat >nul 2>&1
if %errorlevel% equ 0 (
    call :test_pass "Discord support link in SETUP-AND-START.bat"
) else (
    call :test_fail "Discord support link missing"
)

findstr /C:"Current directory" SETUP-AND-START.bat >nul 2>&1
if %errorlevel% equ 0 (
    call :test_pass "Helpful context in error messages"
) else (
    call :test_fail "Context missing in error messages"
)

echo.

REM ========================================================
REM SUMMARY
REM ========================================================
echo ========================================================
echo   TEST RESULTS SUMMARY
echo ========================================================
echo.
echo Total Tests:  !TESTS_TOTAL!
echo Passed:       !TESTS_PASSED!
echo Failed:       !TESTS_FAILED!
echo.

set /a PASS_RATE=!TESTS_PASSED! * 100 / !TESTS_TOTAL!
echo Pass Rate:    !PASS_RATE!%%
echo.

if !TESTS_FAILED! equ 0 (
    color 0A
    echo [SUCCESS] ALL TESTS PASSED
    echo Security and compatibility fixes validated successfully!
    pause
    exit /b 0
) else (
    color 0E
    echo [WARNING] SOME TESTS FAILED
    echo Review failed tests above and fix issues.
    pause
    exit /b 1
)

REM ========================================================
REM Helper Functions
REM ========================================================

:test_pass
set /a TESTS_TOTAL=!TESTS_TOTAL! + 1
set /a TESTS_PASSED=!TESTS_PASSED! + 1
echo [PASS] %~1
goto :eof

:test_fail
set /a TESTS_TOTAL=!TESTS_TOTAL! + 1
set /a TESTS_FAILED=!TESTS_FAILED! + 1
echo [FAIL] %~1
goto :eof
