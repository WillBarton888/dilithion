@echo off
REM =======================================================
REM  DILITHION TESTNET - SETUP WIZARD (NO COLOR VERSION)
REM =======================================================

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

cls
echo.
echo  ========================================================
echo    SYSTEM CHECK: Validating installation
echo  ========================================================
echo.

REM Check if running from ZIP
echo %CD% | findstr /I /C:"Temp\Rar" /C:"Temp\7z" /C:"Temp\Zip" >nul
if errorlevel 1 goto :not_in_zip
    echo.
    echo  ERROR: Running from inside ZIP file!
    echo  You must extract the complete ZIP file first.
    echo.
    pause
    exit /b 1
:not_in_zip
echo  [OK] Extraction verified

REM Check write permission
if not exist ".dilithion-testnet" (
    mkdir ".dilithion-testnet" 2>nul
    if errorlevel 1 (
        echo  [FAIL] No write permission
        pause
        exit /b 1
    )
    rmdir ".dilithion-testnet" 2>nul
)
echo  [OK] Write permissions OK

REM Check disk space
for /f "tokens=3" %%a in ('dir /-c . ^| findstr /C:"bytes free"') do set FREE_BYTES=%%a
set /a FREE_GB=%FREE_BYTES:~0,-9%
if %FREE_GB% lss 1 (
    echo  [FAIL] Low disk space: %FREE_GB% GB
    pause
    exit /b 1
)
echo  [OK] Disk space OK (%FREE_GB% GB available)

REM Check binary
if not exist "dilithion-node.exe" (
    echo.
    echo  ========================================================
    echo    ERROR: dilithion-node.exe not found
    echo  ========================================================
    echo.
    echo  ANTIVIRUS QUARANTINED THE FILE!
    echo.
    echo  Fix:
    echo    1. Open Windows Security
    echo    2. Go to "Virus and threat protection"
    echo    3. Click "Protection history"
    echo    4. Find dilithion-node.exe
    echo    5. Click "Restore"
    echo.
    echo  Then run: FIX-WINDOWS-DEFENDER.bat (as Administrator)
    echo.
    pause
    exit /b 1
)
echo  [OK] Binary found

REM Check all 6 DLLs
set "MISSING_DLLS="
if not exist "libgcc_s_seh-1.dll" set "MISSING_DLLS=%MISSING_DLLS% libgcc_s_seh-1.dll"
if not exist "libstdc++-6.dll" set "MISSING_DLLS=%MISSING_DLLS% libstdc++-6.dll"
if not exist "libwinpthread-1.dll" set "MISSING_DLLS=%MISSING_DLLS% libwinpthread-1.dll"
if not exist "libleveldb.dll" set "MISSING_DLLS=%MISSING_DLLS% libleveldb.dll"
if not exist "libcrypto-3-x64.dll" set "MISSING_DLLS=%MISSING_DLLS% libcrypto-3-x64.dll"
if not exist "libssl-3-x64.dll" set "MISSING_DLLS=%MISSING_DLLS% libssl-3-x64.dll"

if not "%MISSING_DLLS%"=="" (
    echo  [FAIL] Missing DLLs:%MISSING_DLLS%
    pause
    exit /b 1
)
echo  [OK] All 6 DLLs found

REM Check duplicate instance
tasklist /FI "IMAGENAME eq dilithion-node.exe" 2>NUL | find /I /N "dilithion-node.exe">NUL
if %errorlevel% equ 0 (
    echo  [WARN] Dilithion node already running
    choice /C YN /M "Stop it and continue"
    if errorlevel 2 exit /b 0
    taskkill /IM dilithion-node.exe /F >nul 2>&1
    timeout /t 2 /nobreak >nul
)
echo  [OK] No duplicate instances

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
set /p threads="Enter CPU cores to use (or press ENTER for auto): "

if "%threads%"=="" set threads=auto
echo %threads% | findstr /i /x "auto" >nul
if %errorlevel% equ 0 set threads=auto

cls
echo.
echo  ========================================================
echo    STEP 2: READY TO START
echo  ========================================================
echo.
echo  Network: TESTNET
echo  Mining: ENABLED
echo  CPU Threads: %threads%
echo.
pause

cls
echo.
echo  ========================================================
echo    STARTING DILITHION NODE
echo  ========================================================
echo.

REM Create data directory
if not exist ".dilithion-testnet\blocks" mkdir ".dilithion-testnet\blocks"

REM Check for stale lock
if exist ".dilithion-testnet\blocks\LOCK" (
    echo  WARNING: Stale lock file detected
    choice /C YN /M "Delete lock file and continue"
    if errorlevel 2 exit /b 0
    del ".dilithion-testnet\blocks\LOCK" >nul 2>&1
)

echo  Starting node...
echo  Press Ctrl+C to stop mining
echo.
timeout /t 2 /nobreak >nul

dilithion-node.exe --testnet --mine --threads=%threads%
set NODE_EXIT_CODE=%errorlevel%

if %NODE_EXIT_CODE% neq 0 (
    echo.
    echo  ERROR: Node failed with exit code %NODE_EXIT_CODE%
    echo.
    pause
)

echo.
pause
