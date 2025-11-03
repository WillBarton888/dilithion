@echo off
echo DEBUG: Script starting... > debug.log
echo DEBUG: Current directory: %CD% >> debug.log
echo.
echo ========================================================
echo   DILITHION DEBUG TEST
echo ========================================================
echo.
echo Current directory: %CD%
echo.
echo Testing checks one by one...
echo.

REM Check 1: ZIP detection
echo DEBUG: Testing ZIP detection... >> debug.log
echo %CD% | findstr /I "Temp\\Rar Temp\\7z Temp\\zip" >nul
if %errorlevel% equ 0 (
    echo [FAIL] Running from ZIP/Temp directory
    echo DEBUG: ZIP check FAILED >> debug.log
) else (
    echo [PASS] Not running from ZIP
    echo DEBUG: ZIP check PASSED >> debug.log
)
echo.

REM Check 2: Write permission
echo DEBUG: Testing write permission... >> debug.log
echo test > ".dilithion-test-write.tmp" 2>nul
if errorlevel 1 (
    echo [FAIL] No write permission
    echo DEBUG: Write check FAILED >> debug.log
) else (
    echo [PASS] Write permission OK
    echo DEBUG: Write check PASSED >> debug.log
    del ".dilithion-test-write.tmp" 2>nul
)
echo.

REM Check 3: Disk space
echo DEBUG: Testing disk space... >> debug.log
set "FREE_GB=unknown"
for /f "tokens=3" %%a in ('dir /-c . ^| findstr /C:"bytes free"') do set FREE_BYTES=%%a
if not "%FREE_BYTES%"=="" (
    set FREE_BYTES=%FREE_BYTES:,=%
    set FREE_BYTES=%FREE_BYTES: =%
    set /a "FREE_GB=FREE_BYTES / 1073741824" 2>nul
    if errorlevel 1 set FREE_GB=unknown
)
echo DEBUG: Free space: %FREE_GB% GB >> debug.log
if "%FREE_GB%"=="unknown" (
    echo [WARN] Could not detect disk space
    echo DEBUG: Disk space check SKIPPED >> debug.log
) else (
    if "%FREE_GB%"=="" (
        echo [WARN] Could not detect disk space (empty)
        echo DEBUG: Disk space check SKIPPED >> debug.log
    ) else (
        set /a TEST_GB=%FREE_GB% 2>nul
        if errorlevel 1 (
            echo [WARN] Invalid disk space value
            echo DEBUG: Disk space check SKIPPED >> debug.log
        ) else (
            if %FREE_GB% lss 1 (
                echo [FAIL] Low disk space: %FREE_GB% GB
                echo DEBUG: Disk space check FAILED >> debug.log
            ) else (
                echo [PASS] Disk space OK: %FREE_GB% GB
                echo DEBUG: Disk space check PASSED >> debug.log
            )
        )
    )
)
echo.

REM Check 4: Binary exists
echo DEBUG: Testing binary exists... >> debug.log
if not exist "dilithion-node.exe" (
    echo [FAIL] dilithion-node.exe not found
    echo DEBUG: Binary check FAILED >> debug.log
) else (
    echo [PASS] dilithion-node.exe found
    echo DEBUG: Binary check PASSED >> debug.log
)
echo.

REM Check 5: DLLs exist
echo DEBUG: Testing DLL files... >> debug.log
set "MISSING_DLLS="
if not exist "libgcc_s_seh-1.dll" set "MISSING_DLLS=%MISSING_DLLS% libgcc_s_seh-1.dll"
if not exist "libstdc++-6.dll" set "MISSING_DLLS=%MISSING_DLLS% libstdc++-6.dll"
if not exist "libwinpthread-1.dll" set "MISSING_DLLS=%MISSING_DLLS% libwinpthread-1.dll"
if not "%MISSING_DLLS%"=="" (
    echo [FAIL] Missing DLLs:%MISSING_DLLS%
    echo DEBUG: DLL check FAILED:%MISSING_DLLS% >> debug.log
) else (
    echo [PASS] All DLLs found
    echo DEBUG: DLL check PASSED >> debug.log
)
echo.

REM Check 6: Duplicate instance
echo DEBUG: Testing duplicate instance... >> debug.log
tasklist /FI "IMAGENAME eq dilithion-node.exe" 2>NUL | find /I /N "dilithion-node.exe">NUL
if %errorlevel% equ 0 (
    echo [WARN] Dilithion node already running
    echo DEBUG: Duplicate instance check FAILED >> debug.log
) else (
    echo [PASS] No duplicate instance
    echo DEBUG: Duplicate instance check PASSED >> debug.log
)
echo.

REM Check 7: Port availability
echo DEBUG: Testing port availability... >> debug.log
netstat -an | findstr ":18444 " >nul 2>&1
if %errorlevel% equ 0 (
    echo [FAIL] Port 18444 already in use
    echo DEBUG: Port 18444 check FAILED >> debug.log
) else (
    echo [PASS] Port 18444 available
    echo DEBUG: Port 18444 check PASSED >> debug.log
)
echo.

netstat -an | findstr ":18332 " >nul 2>&1
if %errorlevel% equ 0 (
    echo [FAIL] Port 18332 already in use
    echo DEBUG: Port 18332 check FAILED >> debug.log
) else (
    echo [PASS] Port 18332 available
    echo DEBUG: Port 18332 check PASSED >> debug.log
)
echo.

echo ========================================================
echo   All checks completed - see debug.log for details
echo ========================================================
echo.
pause
