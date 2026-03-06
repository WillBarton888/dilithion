@echo off
REM ========================================================
REM  DilV MAINNET - WINDOWS SETUP AND START
REM ========================================================
REM  Post-quantum payments chain
REM  VDF Distribution Consensus
REM ========================================================

title DilV Node - Setup

echo.
echo  ========================================================
echo    DilV MAINNET - POST-QUANTUM PAYMENTS CHAIN
echo  ========================================================
echo.
echo  Welcome to DilV!
echo.
echo  DilV is a fast payments cryptocurrency using VDF
echo  (Verifiable Delay Function) consensus. Any CPU can
echo  participate equally in the block distribution lottery.
echo.
echo  Key facts:
echo    - Block time:    ~45 seconds
echo    - Block reward:  100 DilV
echo    - Data folder:   %%APPDATA%%\.dilv\
echo    - P2P port:      9444
echo    - RPC port:      9332
echo.
echo  --------------------------------------------------------
echo  WHAT WOULD YOU LIKE TO DO?
echo  --------------------------------------------------------
echo.
echo  [1] Start mining DilV
echo  [2] Run as relay node only (no mining)
echo  [3] Check wallet balance
echo  [4] Exit
echo.
set /p choice="Enter your choice (1-4): "

if "%choice%"=="1" goto mine
if "%choice%"=="2" goto relay
if "%choice%"=="3" goto balance
if "%choice%"=="4" goto end

:mine
echo.
echo  Starting DilV VDF miner...
echo  Press Ctrl+C to stop.
echo.
dilv-node.exe --mine
goto end

:relay
echo.
echo  Starting DilV relay node (no mining)...
echo  Press Ctrl+C to stop.
echo.
dilv-node.exe --relay-only
goto end

:balance
echo.
check-wallet-balance.exe
echo.
pause
goto end

:end
echo.
echo  Goodbye!
pause
