@echo off
REM =======================================================
REM  DILITHION TESTNET - INTERACTIVE SETUP WIZARD V2
REM =======================================================
REM  Fixed version that handles Windows Defender properly
REM =======================================================

color 0B
cls
echo.
echo  ========================================================
echo    DILITHION TESTNET - FIRST TIME SETUP WIZARD
echo  ========================================================
echo.
echo  Welcome to Dilithion - Post-Quantum Cryptocurrency!
echo.
echo  This wizard will help you get started mining testnet DIL.
echo  Testnet coins have NO monetary value (for testing only).
echo.
echo  ========================================================
echo.
echo  IMPORTANT - Windows Defender Prompts:
echo  - You will see 2 firewall prompts (ports 18444 and 18332)
echo  - Click "Allow access" on both prompts
echo  - This is normal for cryptocurrency mining software
echo.
echo  ========================================================
echo.
pause

REM =======================================================
REM CRITICAL FIX #4: Check if running from inside ZIP file
REM =======================================================
cls
echo.
echo  ========================================================
echo    SYSTEM CHECK: Validating installation
echo  ========================================================
echo.
echo %CD% | findstr /I "Temp\\Rar Temp\\7z Temp\\zip" >nul
if %errorlevel% equ 0 (
    color 0C
    cls
    echo.
    echo  ========================================================
    echo    ERROR: Running from inside ZIP file
    echo  ========================================================
    echo.
    echo  You must EXTRACT the complete ZIP file first!
    echo.
    echo  Steps to fix:
    echo    1. Right-click the ZIP file
    echo    2. Select "Extract All..."
    echo    3. Choose a destination (e.g., C:\Dilithion)
    echo    4. Wait for extraction to complete
    echo    5. Navigate to extracted folder
    echo    6. Run SETUP-AND-START.bat from there
    echo.
    echo  Current location: %CD%
    echo.
    echo  ========================================================
    echo.
    pause
    exit /b 1
)

echo    [32m✓[0m Extraction verified

REM =======================================================
REM Check if current directory is writable (using mkdir instead)
REM =======================================================
if not exist ".dilithion-testnet" (
    mkdir ".dilithion-testnet" 2>nul
    if errorlevel 1 (
        color 0C
        echo.
        echo  ========================================================
        echo    ERROR: Cannot create directories
        echo  ========================================================
        echo.
        echo  Mining software needs write access to:
        echo  %CD%
        echo.
        echo  To fix:
        echo    1. Right-click SETUP-AND-START.bat
        echo    2. Select "Run as Administrator"
        echo    3. Click "Yes" on the UAC prompt
        echo.
        echo  ========================================================
        echo.
        pause
        exit /b 1
    )
    rmdir ".dilithion-testnet" 2>nul
)

echo    [32m✓[0m Write permissions OK

REM =======================================================
REM CRITICAL FIX #5: Check available disk space
REM =======================================================
for /f "tokens=3" %%a in ('dir /-c . ^| findstr /C:"bytes free"') do set FREE_BYTES=%%a
set /a FREE_GB=%FREE_BYTES:~0,-9%

if %FREE_GB% lss 1 (
    color 0C
    echo.
    echo  ========================================================
    echo    WARNING: Low disk space
    echo  ========================================================
    echo.
    echo  Available space: %FREE_GB% GB
    echo  Recommended: At least 1 GB free
    echo.
    echo  Please free up space before continuing.
    echo.
    echo  ========================================================
    echo.
    pause
    exit /b 1
)

echo    [32m✓[0m Disk space OK (%FREE_GB% GB available)

REM =======================================================
REM SECURITY: Check if binary exists
REM =======================================================
if not exist "dilithion-node.exe" (
    color 0C
    echo.
    echo  ========================================================
    echo    ERROR: dilithion-node.exe not found
    echo  ========================================================
    echo.
    echo  The dilithion-node.exe binary is missing!
    echo.
    echo  Common causes:
    echo    1. Incomplete ZIP extraction
    echo    2. ANTIVIRUS QUARANTINED THE FILE (most common!)
    echo    3. File was manually deleted
    echo.
    echo  If antivirus blocked it:
    echo    - Check your antivirus quarantine/history
    echo    - Add exception for dilithion-node.exe
    echo    - Restore file from quarantine
    echo    - Whitelist folder: %CD%
    echo.
    echo  Dilithion is legitimate open-source software:
    echo    - Source: github.com/WillBarton888/dilithion
    echo    - No malware, no viruses
    echo.
    echo  For support: https://discord.gg/dilithion
    echo  ========================================================
    echo.
    pause
    exit /b 1
)

echo    [32m✓[0m Binary found

REM =======================================================
REM CRITICAL FIX #6: Check for required DLL dependencies
REM =======================================================
set "MISSING_DLLS="

if not exist "libgcc_s_seh-1.dll" set "MISSING_DLLS=%MISSING_DLLS% libgcc_s_seh-1.dll"
if not exist "libstdc++-6.dll" set "MISSING_DLLS=%MISSING_DLLS% libstdc++-6.dll"
if not exist "libwinpthread-1.dll" set "MISSING_DLLS=%MISSING_DLLS% libwinpthread-1.dll"

if not "%MISSING_DLLS%"=="" (
    color 0C
    echo.
    echo  ========================================================
    echo    ERROR: Missing DLL files
    echo  ========================================================
    echo.
    echo  Required files are missing:
    echo  %MISSING_DLLS%
    echo.
    echo  Please ensure you:
    echo    1. Extracted the COMPLETE zip file
    echo    2. Did not move/delete any files
    echo    3. Downloaded official Windows release
    echo.
    echo  ========================================================
    echo.
    pause
    exit /b 1
)

echo    [32m✓[0m DLL dependencies OK

REM =======================================================
REM Check if another instance is running
REM =======================================================
tasklist /FI "IMAGENAME eq dilithion-node.exe" 2>NUL | find /I /N "dilithion-node.exe">NUL
if %errorlevel% equ 0 (
    color 0E
    echo.
    echo  ========================================================
    echo    WARNING: Dilithion node already running
    echo  ========================================================
    echo.
    echo  Another instance is already running.
    echo.
    echo  ========================================================
    echo.
    choice /C YN /M "Stop the other instance and continue"
    if errorlevel 2 (
        exit /b 0
    )
    taskkill /IM dilithion-node.exe /F >nul 2>&1
    timeout /t 2 /nobreak >nul
    echo.
    echo    [32m✓[0m Previous instance terminated
    echo.
)

echo    [32m✓[0m No duplicate instances
echo.
echo  ========================================================
echo    All system checks passed!
echo  ========================================================
echo.
timeout /t 2 /nobreak >nul

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

REM ========================================
REM SECURITY: Validate input to prevent command injection
REM ========================================
if "%threads%"=="" (
    set threads=auto
    set threads_display=Auto-Detect
    goto input_valid
)

REM Check if input is "auto" (case-insensitive)
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
echo    - Network:     TESTNET
echo    - Seed Node:   170.64.203.134:18444 (official)
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
echo    DILITHION TESTNET MINER - STARTING
echo  ========================================================
echo.
echo  Connecting to seed node...
echo  Initializing mining with %threads_display%...
echo.
echo  Performing final checks...
echo.
timeout /t 2 /nobreak >nul

REM =======================================================
REM CRITICAL FIX #2: Check for stale lock file
REM =======================================================
if exist ".dilithion-testnet\blocks\LOCK" (
    color 0E
    echo.
    echo  ========================================================
    echo    WARNING: Stale lock file detected
    echo  ========================================================
    echo.
    echo  A LOCK file exists from a previous session.
    echo  This happens if the node crashed or was force-stopped.
    echo.
    echo  It is safe to delete if no other node is running.
    echo.
    echo  ========================================================
    echo.
    choice /C YN /M "Delete lock file and continue"
    if errorlevel 2 (
        echo.
        echo  Operation cancelled.
        pause
        exit /b 0
    )
    del ".dilithion-testnet\blocks\LOCK" >nul 2>&1
    echo.
    echo    [32m✓[0m Lock file deleted
    echo.
)

REM =======================================================
REM Create data directory structure if it doesn't exist
REM =======================================================
if not exist ".dilithion-testnet" mkdir ".dilithion-testnet"
if not exist ".dilithion-testnet\blocks" mkdir ".dilithion-testnet\blocks"

REM Verify directories were created successfully
if not exist ".dilithion-testnet\blocks\" (
    color 0C
    echo.
    echo  ========================================================
    echo    ERROR: Failed to create data directory
    echo  ========================================================
    echo.
    echo  Could not create: %CD%\.dilithion-testnet\blocks
    echo.
    echo  Possible causes:
    echo    - Insufficient permissions
    echo    - Path contains unsupported characters
    echo.
    echo  ========================================================
    echo.
    pause
    exit /b 1
)

echo    [32m✓[0m Data directory ready
echo.
echo  ========================================================
echo    All checks passed - Starting node...
echo  ========================================================
echo.
echo  EXPECT 2 WINDOWS FIREWALL PROMPTS:
echo    1. Port 18444 (P2P networking) - Click "Allow access"
echo    2. Port 18332 (RPC server) - Click "Allow access"
echo.
echo  Press Ctrl+C anytime to stop mining.
echo.
echo  ========================================================
echo.
timeout /t 3 /nobreak >nul

REM =======================================================
REM CRITICAL FIX #1: Execute node and capture exit code
REM =======================================================
dilithion-node.exe --testnet --addnode=170.64.203.134:18444 --mine --threads=%threads%
set NODE_EXIT_CODE=%errorlevel%

REM Check if node exited with error
if %NODE_EXIT_CODE% neq 0 (
    color 0C
    echo.
    echo  ========================================================
    echo    ERROR: Node failed (Exit Code: %NODE_EXIT_CODE%)
    echo  ========================================================
    echo.
    echo  Common causes:
    echo    - Database corruption
    echo    - Port conflict
    echo    - Another instance running
    echo    - Antivirus interference
    echo    - Windows Firewall blocked (you must click Allow!)
    echo.
    echo  To fix database corruption:
    echo    1. Close all Dilithion windows
    echo    2. Delete folder: .dilithion-testnet
    echo    3. Run SETUP-AND-START.bat again
    echo.
    echo  For support: https://discord.gg/dilithion
    echo  ========================================================
    echo.
    pause
    exit /b %NODE_EXIT_CODE%
)

REM Normal exit (Ctrl+C)
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
