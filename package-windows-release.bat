@echo off
REM ================================================================
REM  DILITHION - PACKAGE WINDOWS RELEASE
REM ================================================================
REM  This script packages the Windows binary release
REM ================================================================

set VERSION=v1.0.9
set RELEASE_NAME=dilithion-testnet-%VERSION%-windows-x64
set RELEASE_DIR=releases\%RELEASE_NAME%

echo.
echo ================================================================
echo   PACKAGING DILITHION WINDOWS RELEASE
echo ================================================================
echo.
echo Version: %VERSION%
echo Package: %RELEASE_NAME%.zip
echo.

REM Create release directory
echo [1/5] Creating release directory...
if exist releases\%RELEASE_NAME% rmdir /s /q releases\%RELEASE_NAME%
mkdir releases\%RELEASE_NAME%

REM Copy binaries (Windows .exe files)
echo [2/5] Copying binaries...
copy dilithion-node.exe %RELEASE_DIR%\ >nul
copy check-wallet-balance.exe %RELEASE_DIR%\ >nul
copy genesis_gen.exe %RELEASE_DIR%\ >nul

REM Copy required DLLs
echo [3/5] Copying runtime libraries (DLLs)...
copy libwinpthread-1.dll %RELEASE_DIR%\ >nul
copy libgcc_s_seh-1.dll %RELEASE_DIR%\ >nul
copy libleveldb.dll %RELEASE_DIR%\ >nul
copy libstdc++-6.dll %RELEASE_DIR%\ >nul

REM Copy launcher scripts
echo [4/5] Copying launcher scripts and documentation...
copy START-MINING.bat %RELEASE_DIR%\ >nul
copy SETUP-AND-START.bat %RELEASE_DIR%\ >nul

REM Copy documentation
copy README-WINDOWS.txt %RELEASE_DIR%\README.txt
copy TESTNET-SETUP-GUIDE.md %RELEASE_DIR%\TESTNET-GUIDE.md

REM Create the ZIP archive
echo [5/5] Creating ZIP archive...
cd releases
powershell -command "Compress-Archive -Path '%RELEASE_NAME%' -DestinationPath '%RELEASE_NAME%.zip' -Force"
cd ..

REM Show results
echo.
echo ================================================================
echo   PACKAGING COMPLETE!
echo ================================================================
echo.
echo Release package created:
echo   releases\%RELEASE_NAME%.zip
echo.
echo Package contents:
dir /b releases\%RELEASE_NAME%
echo.
echo Size:
dir releases\%RELEASE_NAME%.zip | find ".zip"
echo.
echo Ready to upload to GitHub release!
echo.
pause
