@echo off
REM =======================================================
REM  DILITHION TESTNET - ONE-CLICK MINING
REM =======================================================
REM  Based on v1.0.6 - SIMPLIFIED VERSION THAT WORKED
REM =======================================================

cls
color 0A
echo.
echo  ================================================
echo    DILITHION TESTNET - QUICK START MINER
echo  ================================================
echo.
echo  Starting Dilithion testnet mining...
echo  - Network: TESTNET (coins have NO value)
echo  - Seed Nodes: NYC, Singapore, London (auto-connect)
echo  - Mining: ENABLED (auto-detecting CPU threads)
echo.
echo  Mining will start in 3 seconds...
echo  Press Ctrl+C to stop mining anytime.
echo.
timeout /t 3 /nobreak >nul

echo  Starting node...
echo.

REM Only check if binary exists - THAT'S IT!
if not exist "dilithion-node.exe" (
    color 0C
    echo.
    echo  ================================================
    echo    ERROR: dilithion-node.exe not found
    echo  ================================================
    echo.
    echo  ANTIVIRUS likely quarantined the file!
    echo.
    echo  Fix:
    echo    1. Open Windows Security
    echo    2. Go to "Protection history"
    echo    3. Find and RESTORE dilithion-node.exe
    echo    4. Add folder exclusion: %CD%
    echo.
    echo  Current directory: %CD%
    echo.
    echo  For support: https://discord.gg/dilithion
    echo  ================================================
    echo.
    pause
    exit /b 1
)

REM Just run it - let the binary handle everything else!
dilithion-node.exe --testnet --mine --threads=auto

REM If node exits, show message
echo.
echo  ================================================
echo    Mining stopped
echo  ================================================
echo.
pause
