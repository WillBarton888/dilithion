@echo off
REM =======================================================
REM  DILITHION MAINNET - INTERACTIVE SETUP WIZARD
REM =======================================================
REM  v1.4.0 - MAINNET LAUNCH
REM =======================================================

color 0B
cls
echo.
echo  ========================================================
echo    DILITHION MAINNET - FIRST TIME SETUP WIZARD
echo  ========================================================
echo.
echo  Welcome to Dilithion - Post-Quantum Cryptocurrency!
echo.
echo  This wizard will help you get started mining DIL.
echo  You are joining the MAINNET - real DIL with real value!
echo.
echo  ========================================================
echo.
pause

cls
echo.
echo  ========================================================
echo    STEP 1: CONFIGURE MINING
echo  ========================================================
echo.
echo  How many CPU cores would you like to use for mining?
echo.
echo  Recommendations:
echo    - Leave BLANK for AUTO (recommended for beginners)
echo    - Enter 1-2 for light mining (laptop/low power)
echo    - Enter 4-8 for medium mining (desktop)
echo    - Enter 8+ for maximum mining (powerful PC)
echo.
echo  Your CPU will be auto-detected if you leave this blank.
echo.
set /p threads="Enter number of CPU cores (or press ENTER for auto): "

REM Validate input
if "%threads%"=="" (
    set threads=auto
    set threads_display=Auto-Detect
    goto input_valid
)

echo %threads% | findstr /i /x "auto" >nul
if %errorlevel% equ 0 (
    set threads=auto
    set threads_display=Auto-Detect
    goto input_valid
)

REM Validate numeric input (1-128 cores)
set "valid=0"
for /L %%i in (1,1,128) do (
    if "%threads%"=="%%i" set "valid=1"
)

if "%valid%"=="0" (
    cls
    echo.
    echo  ========================================================
    echo    ERROR: Invalid Input
    echo  ========================================================
    echo.
    echo  Please enter either:
    echo    - A number between 1 and 128
    echo    - "auto" for automatic detection
    echo    - Press ENTER for automatic detection
    echo.
    echo  Your input "%threads%" is not valid.
    echo.
    echo  ========================================================
    echo.
    pause
    exit /b 1
)

set threads_display=%threads% cores

:input_valid

cls
echo.
echo  ========================================================
echo    STEP 2: REVIEW CONFIGURATION
echo  ========================================================
echo.
echo  Your Settings:
echo    - Network:     MAINNET
echo    - Seed Nodes:  NYC, London, Singapore, Sydney (auto-connect)
echo    - Mining:      ENABLED
echo    - CPU Threads: %threads_display%
echo.
echo  ========================================================
echo.
echo  Ready to start mining!
echo.
pause

cls
echo.
echo  ========================================================
echo    DILITHION MAINNET MINER - STARTING
echo  ========================================================
echo.
echo  Connecting to seed nodes...
echo  Initializing mining with %threads_display%...
echo.
echo  The node will start shortly.
echo  Press Ctrl+C anytime to stop mining.
echo.
echo  ========================================================
echo.
timeout /t 2 /nobreak >nul

REM Run the node - file check removed (causes false positives on some Windows systems)
dilithion-node.exe --mine --threads=%threads%

echo.
echo  ========================================================
echo    Mining Stopped
echo  ========================================================
echo.
echo  To start mining again:
echo    - Double-click START-MINING.bat for quick start
echo    - Or run this wizard again
echo.
pause
