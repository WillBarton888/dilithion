@echo off
REM ================================================================
REM  DILITHION - PACKAGE DIAGNOSTIC TOOL
REM ================================================================
REM  This script tests if the downloaded package works correctly
REM ================================================================

color 0B
cls
echo.
echo ================================================================
echo   DILITHION PACKAGE DIAGNOSTIC TOOL
echo ================================================================
echo.
echo This will test the downloaded v1.0.9 Windows package
echo.
pause

REM Download and extract the package
echo.
echo [1/5] Downloading v1.0.9 from GitHub...
curl -sL https://github.com/dilithion/dilithion/releases/download/v1.0.9/dilithion-testnet-v1.0.9-windows-x64.zip -o %TEMP%\dilithion-test.zip
if errorlevel 1 (
    echo ERROR: Download failed
    pause
    exit /b 1
)
echo    Done!

echo.
echo [2/5] Verifying SHA256 checksum...
certutil -hashfile %TEMP%\dilithion-test.zip SHA256 | findstr /v "hash" > %TEMP%\actual-hash.txt
set /p ACTUAL_HASH=<%TEMP%\actual-hash.txt
echo Expected: 618f7319042b386d3c1c48d7cf4fa044ef31e930d07ccb8a998a899fb34a4f81
echo Actual:   %ACTUAL_HASH%
echo %ACTUAL_HASH% | findstr "618f7319042b386d3c1c48d7cf4fa044ef31e930d07ccb8a998a899fb34a4f81" >nul
if errorlevel 1 (
    color 0C
    echo    MISMATCH! Package may be corrupted!
    pause
    exit /b 1
)
echo    Match! Package is authentic.

echo.
echo [3/5] Extracting to temporary directory...
if exist %TEMP%\dilithion-test rmdir /s /q %TEMP%\dilithion-test
mkdir %TEMP%\dilithion-test
cd %TEMP%\dilithion-test
powershell -command "Expand-Archive -Path '%TEMP%\dilithion-test.zip' -DestinationPath '.' -Force"
cd dilithion-testnet-v1.0.9-windows-x64
echo    Done!

echo.
echo [4/5] Checking for required DLL files...
set "MISSING_DLLS="
set "DLL_COUNT=0"

for %%D in (libgcc_s_seh-1.dll libstdc++-6.dll libwinpthread-1.dll libleveldb.dll libcrypto-3-x64.dll libssl-3-x64.dll) do (
    if exist "%%D" (
        echo    [32mOK[0m %%D
        set /a DLL_COUNT+=1
    ) else (
        echo    [31mMISSING[0m %%D
        set "MISSING_DLLS=!MISSING_DLLS! %%D"
    )
)

if not "%MISSING_DLLS%"=="" (
    color 0C
    echo.
    echo ERROR: Missing DLL files:%MISSING_DLLS%
    pause
    exit /b 1
)

echo.
echo    All 6 DLLs present!

echo.
echo [5/5] Testing executable...
echo.
echo Running: dilithion-node.exe --version
echo.
dilithion-node.exe --version 2>&1
set EXIT_CODE=%errorlevel%

echo.
echo Exit code: %EXIT_CODE%
echo.

if %EXIT_CODE% equ 0 (
    color 0A
    echo ================================================================
    echo   DIAGNOSTIC PASSED - Package is functional!
    echo ================================================================
) else (
    color 0C
    echo ================================================================
    echo   DIAGNOSTIC FAILED - Exit code %EXIT_CODE%
    echo ================================================================
    echo.
    echo The executable failed to run. This could mean:
    echo   1. Missing DLL dependency not in the package
    echo   2. Corrupted binary
    echo   3. Antivirus blocking execution
    echo   4. Windows version incompatibility
    echo.
    echo Please run this diagnostic on the machine that's having issues.
)

echo.
pause
