@echo off
REM ================================================================
REM  DILITHION - PACKAGE WINDOWS RELEASE
REM ================================================================
REM  This script packages the Windows binary release
REM ================================================================

set VERSION=v1.0.0
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
echo [1/4] Creating release directory...
if exist releases\%RELEASE_NAME% rmdir /s /q releases\%RELEASE_NAME%
mkdir releases\%RELEASE_NAME%

REM Copy binaries (Windows .exe files)
echo [2/4] Copying binaries...
copy dilithion-node.exe %RELEASE_DIR%\ >nul
copy check-wallet-balance.exe %RELEASE_DIR%\ >nul
copy genesis_gen.exe %RELEASE_DIR%\ >nul

REM Copy launcher scripts
echo [3/4] Copying launcher scripts and documentation...
copy START-MINING.bat %RELEASE_DIR%\ >nul
copy SETUP-AND-START.bat %RELEASE_DIR%\ >nul

REM Copy documentation
copy README-WINDOWS.txt %RELEASE_DIR%\README.txt
copy TESTNET-SETUP-GUIDE.md %RELEASE_DIR%\TESTNET-GUIDE.md

REM Create the ZIP archive
echo [4/4] Creating ZIP archive...
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
