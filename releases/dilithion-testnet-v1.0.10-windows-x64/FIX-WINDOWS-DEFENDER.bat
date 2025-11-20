@echo off
REM ================================================================
REM  DILITHION - WINDOWS DEFENDER EXCLUSION FIX
REM ================================================================
REM  This script adds Windows Defender exclusions for Dilithion
REM  Run this AS ADMINISTRATOR
REM ================================================================

color 0E
cls
echo.
echo ================================================================
echo   DILITHION - WINDOWS DEFENDER EXCLUSION TOOL
echo ================================================================
echo.
echo This script will add Windows Defender exclusions for:
echo   - dilithion-node.exe
echo   - check-wallet-balance.exe
echo   - genesis_gen.exe
echo.
echo You must run this AS ADMINISTRATOR for it to work.
echo.
pause

REM Check if running as administrator
net session >nul 2>&1
if %errorLevel% neq 0 (
    color 0C
    echo.
    echo ================================================================
    echo   ERROR: Not running as Administrator
    echo ================================================================
    echo.
    echo Please:
    echo   1. Right-click FIX-WINDOWS-DEFENDER.bat
    echo   2. Select "Run as Administrator"
    echo   3. Click "Yes" on the UAC prompt
    echo.
    pause
    exit /b 1
)

echo.
echo Adding Windows Defender exclusions...
echo.

REM Add folder exclusion
powershell -Command "Add-MpPreference -ExclusionPath '%CD%'" 2>&1
if %errorlevel% equ 0 (
    echo [OK] Added folder exclusion: %CD%
) else (
    echo [FAIL] Could not add folder exclusion
)

REM Add process exclusions
powershell -Command "Add-MpPreference -ExclusionProcess 'dilithion-node.exe'" 2>&1
if %errorlevel% equ 0 (
    echo [OK] Added process exclusion: dilithion-node.exe
) else (
    echo [FAIL] Could not add process exclusion
)

powershell -Command "Add-MpPreference -ExclusionProcess 'check-wallet-balance.exe'" 2>&1
if %errorlevel% equ 0 (
    echo [OK] Added process exclusion: check-wallet-balance.exe
) else (
    echo [FAIL] Could not add process exclusion
)

powershell -Command "Add-MpPreference -ExclusionProcess 'genesis_gen.exe'" 2>&1
if %errorlevel% equ 0 (
    echo [OK] Added process exclusion: genesis_gen.exe
) else (
    echo [FAIL] Could not add process exclusion
)

echo.
echo ================================================================
echo   Checking Windows Defender Protection History...
echo ================================================================
echo.
echo Recent threats (looking for Dilithion files):
powershell -Command "Get-MpThreatDetection | Where-Object {$_.Resources -like '*dilithion*'} | Select-Object -First 5 | Format-List Resources, ThreatName"

echo.
echo ================================================================
echo   NEXT STEPS:
echo ================================================================
echo.
echo 1. Go to Windows Security
echo 2. Click "Virus ^& threat protection"
echo 3. Click "Protection history"
echo 4. Find dilithion-node.exe in quarantine
echo 5. Click "Actions" → "Restore"
echo 6. Re-extract the ZIP file to this folder
echo 7. Run SETUP-AND-START.bat again
echo.
echo Folder exclusion added for: %CD%
echo.
pause
