@echo off
setlocal enabledelayedexpansion
set LOGFILE=%~dp0ULTRA-DEBUG-LOG.txt

echo ===== ULTRA DEBUG START ===== > "%LOGFILE%"
echo [%TIME%] Session started >> "%LOGFILE%"

cls
color 0B
echo.
echo  ========================================================
echo    DILITHION TESTNET - ULTRA DEBUG MODE
echo  ========================================================
echo.
echo  This will log EVERY SINGLE LINE to ULTRA-DEBUG-LOG.txt
echo.
echo  Press Enter to continue...
pause >nul

echo [%TIME%] First pause completed >> "%LOGFILE%"

cls
echo.
echo  ========================================================
echo    SYSTEM CHECK: Validating installation
echo  ========================================================
echo.

echo [%TIME%] Starting validation checks >> "%LOGFILE%"

REM ZIP extraction check
echo [%TIME%] CHECK 1: ZIP extraction >> "%LOGFILE%"
echo %CD% | findstr /I "Temp\\Rar Temp\\7z Temp\\zip" >nul
if %errorlevel% equ 0 (
    echo [%TIME%] FAILED: Running from temp directory >> "%LOGFILE%"
    echo    ERROR: Running from inside ZIP
    pause
    exit /b 1
)
echo [%TIME%] PASSED: Not in temp directory >> "%LOGFILE%"
echo    Extraction verified (OK)

REM Write permission check
echo [%TIME%] CHECK 2: Write permissions >> "%LOGFILE%"
if not exist ".dilithion-testnet" (
    echo [%TIME%] Creating test directory >> "%LOGFILE%"
    mkdir ".dilithion-testnet" 2>>"%LOGFILE%"
    if errorlevel 1 (
        echo [%TIME%] FAILED: Cannot create directory >> "%LOGFILE%"
        echo    ERROR: Cannot create directories
        pause
        exit /b 1
    )
    echo [%TIME%] Test directory created >> "%LOGFILE%"
    rmdir ".dilithion-testnet" 2>>"%LOGFILE%"
    echo [%TIME%] Test directory removed >> "%LOGFILE%"
)
echo [%TIME%] PASSED: Write permissions OK >> "%LOGFILE%"
echo    Write permissions OK

REM Disk space check - ULTRA VERBOSE
echo [%TIME%] CHECK 3: Disk space >> "%LOGFILE%"
set "FREE_GB=unknown"
echo [%TIME%] Initial FREE_GB=[%FREE_GB%] >> "%LOGFILE%"

echo [%TIME%] Attempting WMIC method >> "%LOGFILE%"
set "FREE_BYTES="
for /f "skip=1 tokens=2" %%a in ('wmic logicaldisk where "DeviceID='%CD:~0,2%'" get FreeSpace 2^>nul') do (
    echo [%TIME%] WMIC returned: [%%a] >> "%LOGFILE%"
    set FREE_BYTES=%%a
    goto :got_free_bytes
)
:got_free_bytes

echo [%TIME%] After WMIC loop, FREE_BYTES=[%FREE_BYTES%] >> "%LOGFILE%"

if "%FREE_BYTES%"=="" (
    echo [%TIME%] WMIC failed, trying DIR fallback >> "%LOGFILE%"
    for /f "tokens=3" %%a in ('dir /-c "%CD:~0,2%\\" 2^>nul ^| findstr /C:"bytes free"') do (
        echo [%TIME%] DIR returned: [%%a] >> "%LOGFILE%"
        set FREE_BYTES=%%a
    )
    echo [%TIME%] After DIR fallback, FREE_BYTES=[%FREE_BYTES%] >> "%LOGFILE%"
)

echo [%TIME%] Before processing, FREE_BYTES=[%FREE_BYTES%] >> "%LOGFILE%"

if not "%FREE_BYTES%"=="" (
    if not "%FREE_BYTES%"=="unknown" (
        echo [%TIME%] Removing commas and spaces >> "%LOGFILE%"
        set FREE_BYTES=!FREE_BYTES:,=!
        echo [%TIME%] After comma removal: [!FREE_BYTES!] >> "%LOGFILE%"
        set FREE_BYTES=!FREE_BYTES: =!
        echo [%TIME%] After space removal: [!FREE_BYTES!] >> "%LOGFILE%"

        echo [%TIME%] Attempting arithmetic division >> "%LOGFILE%"
        set /a "FREE_GB=FREE_BYTES / 1073741824" 2>>"%LOGFILE%"
        if errorlevel 1 (
            echo [%TIME%] Arithmetic failed, setting to unknown >> "%LOGFILE%"
            set FREE_GB=unknown
        ) else (
            echo [%TIME%] Arithmetic succeeded >> "%LOGFILE%"
        )
    )
)

echo [%TIME%] After processing, FREE_GB=[%FREE_GB%] >> "%LOGFILE%"

REM Validation check 1
echo [%TIME%] VALIDATION 1: Checking if FREE_GB equals 'unknown' >> "%LOGFILE%"
if "%FREE_GB%"=="unknown" (
    echo [%TIME%] FREE_GB is unknown, skipping disk check >> "%LOGFILE%"
    echo    WARNING: Could not detect disk space (continuing anyway)
    goto :skip_disk_check
)
echo [%TIME%] VALIDATION 1 PASSED: FREE_GB is not 'unknown' >> "%LOGFILE%"

REM Validation check 2
echo [%TIME%] VALIDATION 2: Checking if FREE_GB is empty >> "%LOGFILE%"
if "%FREE_GB%"=="" (
    echo [%TIME%] FREE_GB is empty, skipping disk check >> "%LOGFILE%"
    echo    WARNING: Could not detect disk space (continuing anyway)
    goto :skip_disk_check
)
echo [%TIME%] VALIDATION 2 PASSED: FREE_GB is not empty, value=[%FREE_GB%] >> "%LOGFILE%"

REM Validation check 3
echo [%TIME%] VALIDATION 3: Testing numeric validity >> "%LOGFILE%"
set /a TEST_GB=%FREE_GB% 2>>"%LOGFILE%"
if errorlevel 1 (
    echo [%TIME%] Numeric test failed, skipping disk check >> "%LOGFILE%"
    echo    WARNING: Invalid disk space value (continuing anyway)
    goto :skip_disk_check
)
echo [%TIME%] VALIDATION 3 PASSED: TEST_GB=[%TEST_GB%] >> "%LOGFILE%"

REM The actual comparison
echo [%TIME%] FINAL COMPARISON: About to check if %FREE_GB% is less than 1 >> "%LOGFILE%"
echo [%TIME%] Command will be: if %FREE_GB% lss 1 >> "%LOGFILE%"

if %FREE_GB% lss 1 (
    echo [%TIME%] Disk space is low >> "%LOGFILE%"
    color 0C
    echo.
    echo  ========================================================
    echo    WARNING: LOW DISK SPACE
    echo  ========================================================
    echo.
    echo    Available space: %FREE_GB% GB
    echo    Required space: At least 1 GB
    echo.
    pause
    exit /b 1
)

echo [%TIME%] PASSED: Sufficient disk space (%FREE_GB% GB) >> "%LOGFILE%"
echo    Disk space OK (%FREE_GB% GB available)
goto :after_disk_check

:skip_disk_check
echo [%TIME%] Disk check skipped >> "%LOGFILE%"

:after_disk_check

REM Binary check
echo [%TIME%] CHECK 4: Binary existence >> "%LOGFILE%"
if not exist "dilithion-node.exe" (
    echo [%TIME%] FAILED: dilithion-node.exe not found >> "%LOGFILE%"
    echo    ERROR: dilithion-node.exe not found
    pause
    exit /b 1
)
echo [%TIME%] PASSED: Binary exists >> "%LOGFILE%"
echo    Binary found (OK)

echo.
echo  ========================================================
echo    ALL VALIDATION CHECKS PASSED!
echo  ========================================================
echo.
echo  Script completed successfully!
echo  Check ULTRA-DEBUG-LOG.txt for complete execution trace.
echo.
echo [%TIME%] Script completed successfully >> "%LOGFILE%"

pause
