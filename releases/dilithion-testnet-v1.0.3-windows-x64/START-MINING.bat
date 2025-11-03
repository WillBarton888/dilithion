@echo off
REM =======================================================
REM  DILITHION TESTNET - ONE-CLICK MINING
REM =======================================================
REM  This script starts mining Dilithion testnet instantly
REM  No configuration needed - just double-click!
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
echo  - Seed Node: 170.64.203.134:18444
echo  - Mining: ENABLED (auto-detecting CPU threads)
echo.
echo  EXPECT 2 WINDOWS FIREWALL PROMPTS:
echo    - Port 18444 (P2P) - Click "Allow access"
echo    - Port 18332 (RPC) - Click "Allow access"
echo.
echo  Performing startup checks...
echo.
timeout /t 2 /nobreak >nul

REM =======================================================
REM CRITICAL FIX #4: Check if running from inside ZIP file
REM =======================================================
echo %CD% | findstr /I "Temp\\Rar Temp\\7z Temp\\zip" >nul
if %errorlevel% equ 0 (
    color 0C
    cls
    echo.
    echo  ================================================
    echo    ERROR: Running from inside ZIP file
    echo  ================================================
    echo.
    echo  You must EXTRACT the complete ZIP file first!
    echo.
    echo  Steps to fix:
    echo    1. Right-click the ZIP file
    echo    2. Select "Extract All..."
    echo    3. Choose a destination (e.g., C:\Dilithion)
    echo    4. Wait for extraction to complete
    echo    5. Navigate to extracted folder
    echo    6. Run START-MINING.bat from there
    echo.
    echo  Current location: %CD%
    echo.
    echo  ================================================
    echo.
    pause
    exit /b 1
)

REM =======================================================
REM Check if current directory is writable (using mkdir)
REM =======================================================
if not exist ".dilithion-testnet" (
    mkdir ".dilithion-testnet" 2>nul
    if errorlevel 1 (
        color 0C
        echo.
        echo  ================================================
        echo    ERROR: Cannot create directories
        echo  ================================================
        echo.
        echo  Mining software needs write access to:
        echo  %CD%
        echo.
        echo  To fix:
        echo    1. Right-click START-MINING.bat
        echo    2. Select "Run as Administrator"
        echo    3. Click "Yes" on the UAC prompt
        echo.
        echo  ================================================
        echo.
        pause
        exit /b 1
    )
    rmdir ".dilithion-testnet" 2>nul
)

REM =======================================================
REM CRITICAL FIX #5: Check available disk space (IMPROVED)
REM =======================================================
REM Using wmic instead of dir for more reliable parsing
set "FREE_GB=unknown"
for /f "skip=1 tokens=2" %%a in ('wmic logicaldisk where "DeviceID='%CD:~0,2%'" get FreeSpace 2^>nul') do (
    set FREE_BYTES=%%a
    goto :got_free_bytes_quick
)
:got_free_bytes_quick

REM If wmic failed, try alternative method using dir
if "%FREE_BYTES%"=="" (
    for /f "tokens=3" %%a in ('dir /-c "%CD:~0,2%\" 2^>nul ^| findstr /C:"bytes free"') do set FREE_BYTES=%%a
)

REM If we got bytes, convert to GB
if not "%FREE_BYTES%"=="" (
    if not "%FREE_BYTES%"=="unknown" (
        REM Remove any commas from the number
        set FREE_BYTES=%FREE_BYTES:,=%
        REM Calculate GB (divide by 1073741824)
        set /a FREE_GB=%FREE_BYTES:~0,-9% 2>nul
    )
)

REM Check if we got a valid result
if "%FREE_GB%"=="unknown" (
    echo    WARNING: Could not detect disk space (continuing anyway)
    goto :skip_disk_check_quick
)

if %FREE_GB% lss 1 (
    color 0C
    echo.
    echo  ================================================
    echo    WARNING: Low disk space
    echo  ================================================
    echo.
    echo  Available space: %FREE_GB% GB
    echo  Recommended: At least 1 GB free
    echo.
    echo  The blockchain database requires disk space.
    echo  Please free up space before continuing.
    echo.
    echo  ================================================
    echo.
    pause
    exit /b 1
)

echo    Disk space OK (%FREE_GB% GB available)
:skip_disk_check_quick

REM =======================================================
REM SECURITY: Check if binary exists before execution
REM =======================================================
if not exist "dilithion-node.exe" (
    color 0C
    echo.
    echo  ================================================
    echo    ERROR: dilithion-node.exe not found
    echo  ================================================
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
    echo    - Miners use CPU (triggers false positives)
    echo.
    echo  Current directory: %CD%
    echo.
    echo  For support: https://discord.gg/dilithion
    echo  ================================================
    echo.
    pause
    exit /b 1
)

echo    Binary found (OK)

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
    echo  ================================================
    echo    ERROR: Missing DLL files
    echo  ================================================
    echo.
    echo  Required files are missing:
    echo  %MISSING_DLLS%
    echo.
    echo  Please ensure you:
    echo    1. Extracted the COMPLETE zip file
    echo    2. Did not move/delete any files
    echo    3. Downloaded official Windows release
    echo.
    echo  Current directory: %CD%
    echo.
    echo  ================================================
    echo.
    pause
    exit /b 1
)

echo    DLL dependencies OK

REM =======================================================
REM Check if another instance is already running
REM =======================================================
tasklist /FI "IMAGENAME eq dilithion-node.exe" 2>NUL | find /I /N "dilithion-node.exe">NUL
if %errorlevel% equ 0 (
    color 0E
    echo.
    echo  ================================================
    echo    WARNING: Dilithion node already running
    echo  ================================================
    echo.
    echo  Another instance is already running.
    echo  You cannot run multiple instances on the
    echo  same data directory.
    echo.
    echo  Options:
    echo    - Close this window (recommended)
    echo    - Stop the other instance first
    echo.
    echo  ================================================
    echo.
    choice /C YN /M "Stop the other instance and continue"
    if errorlevel 2 (
        exit /b 0
    )
    taskkill /IM dilithion-node.exe /F >nul 2>&1
    timeout /t 2 /nobreak >nul
    echo.
    echo    Previous instance terminated.
    echo.
)

echo    No duplicate instances (OK)

REM =======================================================
REM CRITICAL FIX #2: Check for stale lock file
REM =======================================================
if exist ".dilithion-testnet\blocks\LOCK" (
    color 0E
    echo.
    echo  ================================================
    echo    WARNING: Stale lock file detected
    echo  ================================================
    echo.
    echo  A LOCK file exists from a previous session.
    echo  This happens if the node crashed or was
    echo  force-stopped.
    echo.
    echo  It is safe to delete this file if you are
    echo  sure no other node instance is running.
    echo.
    echo  ================================================
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
    echo    Lock file deleted (OK)
    echo.
)

REM =======================================================
REM CRITICAL FIX #3: Check if required ports are available
REM =======================================================
echo    Checking port availability...

netstat -an | findstr ":18444 " >nul 2>&1
if %errorlevel% equ 0 (
    color 0C
    echo.
    echo  ================================================
    echo    ERROR: Port 18444 already in use
    echo  ================================================
    echo.
    echo  Dilithion testnet requires port 18444 for P2P.
    echo.
    echo  Common causes:
    echo    - Another Dilithion node is running
    echo    - Different crypto software using same port
    echo    - Firewall or proxy conflict
    echo.
    echo  To fix:
    echo    1. Close any other Dilithion instances
    echo    2. Check Task Manager for dilithion-node.exe
    echo    3. Restart your computer
    echo.
    echo  ================================================
    echo.
    pause
    exit /b 1
)

netstat -an | findstr ":18332 " >nul 2>&1
if %errorlevel% equ 0 (
    color 0C
    echo.
    echo  ================================================
    echo    ERROR: Port 18332 already in use
    echo  ================================================
    echo.
    echo  Dilithion testnet requires port 18332 for RPC.
    echo  See troubleshooting steps above.
    echo.
    echo  ================================================
    echo.
    pause
    exit /b 1
)

echo    Ports 18444 and 18332 available (OK)

REM =======================================================
REM Create data directory structure if it doesn't exist
REM =======================================================
if not exist ".dilithion-testnet" mkdir ".dilithion-testnet"
if not exist ".dilithion-testnet\blocks" mkdir ".dilithion-testnet\blocks"

REM Verify directories were created successfully
if not exist ".dilithion-testnet\blocks\" (
    color 0C
    echo.
    echo  ================================================
    echo    ERROR: Failed to create data directory
    echo  ================================================
    echo.
    echo  Could not create: %CD%\.dilithion-testnet\blocks
    echo.
    echo  Possible causes:
    echo    - Insufficient permissions
    echo    - Path contains unsupported characters
    echo    - Disk is full or read-only
    echo.
    echo  ================================================
    echo.
    pause
    exit /b 1
)

echo    Data directory ready (OK)
echo.
echo  ================================================
echo    All checks passed - Starting node...
echo  ================================================
echo.
echo  Press Ctrl+C to stop mining anytime.
echo.
timeout /t 2 /nobreak >nul

REM =======================================================
REM CRITICAL FIX #1: Execute node and capture exit code
REM =======================================================
dilithion-node.exe --testnet --addnode=170.64.203.134:18444 --mine --threads=auto
set NODE_EXIT_CODE=%errorlevel%

REM Check if node exited with error
if %NODE_EXIT_CODE% neq 0 (
    color 0C
    echo.
    echo  ================================================
    echo    ERROR: Node failed (Exit Code: %NODE_EXIT_CODE%)
    echo  ================================================
    echo.
    echo  Common causes:
    echo    - Database corruption
    echo    - Port conflict
    echo    - Another instance running
    echo    - Antivirus interference
    echo.
    echo  To fix database corruption:
    echo    1. Close all Dilithion windows
    echo    2. Delete folder: .dilithion-testnet
    echo    3. Run START-MINING.bat again
    echo.
    echo  For support: https://discord.gg/dilithion
    echo  ================================================
    echo.
    pause
    exit /b %NODE_EXIT_CODE%
)

REM Normal exit (Ctrl+C)
echo.
echo  ================================================
echo    Mining stopped normally
echo  ================================================
echo.
echo  To start mining again, run START-MINING.bat
echo.
pause
