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
if exist ".dilithion-test-write.tmp" (
    echo [PASS] Write permission OK
    echo DEBUG: Write check PASSED >> debug.log
    del ".dilithion-test-write.tmp" 2>nul
) else (
    echo [FAIL] No write permission
    echo DEBUG: Write check FAILED >> debug.log
)
echo.

REM Check 3: Disk space (simplified - just show available space)
echo DEBUG: Testing disk space... >> debug.log
for /f "tokens=3" %%a in ('dir /-c . 2^>nul ^| findstr /C:"bytes free"') do set FREE_BYTES=%%a
if defined FREE_BYTES (
    echo [PASS] Disk space available
    echo DEBUG: Disk space check PASSED >> debug.log
) else (
    echo [WARN] Could not detect disk space
    echo DEBUG: Disk space check SKIPPED >> debug.log
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

REM Check 5: DLLs exist (ALL 5 required DLLs)
echo DEBUG: Testing DLL files... >> debug.log
set "MISSING_DLLS="
REM MinGW runtime DLLs
if not exist "libgcc_s_seh-1.dll" set "MISSING_DLLS=%MISSING_DLLS% libgcc_s_seh-1.dll"
if not exist "libstdc++-6.dll" set "MISSING_DLLS=%MISSING_DLLS% libstdc++-6.dll"
if not exist "libwinpthread-1.dll" set "MISSING_DLLS=%MISSING_DLLS% libwinpthread-1.dll"
REM Database and cryptography DLLs
if not exist "libleveldb.dll" set "MISSING_DLLS=%MISSING_DLLS% libleveldb.dll"
if not exist "libcrypto-3-x64.dll" set "MISSING_DLLS=%MISSING_DLLS% libcrypto-3-x64.dll"
if not "%MISSING_DLLS%"=="" (
    echo [FAIL] Missing DLLs:%MISSING_DLLS%
    echo DEBUG: DLL check FAILED:%MISSING_DLLS% >> debug.log
) else (
    echo [PASS] All 5 DLLs found
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
