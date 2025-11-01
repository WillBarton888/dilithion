@echo off
REM ================================================================
REM  Create Self-Extracting Archive for Dilithion Windows Release
REM ================================================================
REM  This script creates a .exe that auto-extracts when run
REM  Requires: 7-Zip installed (free from 7-zip.org)
REM ================================================================

echo.
echo ================================================================
echo   DILITHION - Create Windows Self-Extracting Package
echo ================================================================
echo.

REM Check if 7-Zip is installed
set SEVENZIP="C:\Program Files\7-Zip\7z.exe"
if not exist %SEVENZIP% (
    set SEVENZIP="C:\Program Files (x86)\7-Zip\7z.exe"
)

if not exist %SEVENZIP% (
    echo ERROR: 7-Zip not found!
    echo.
    echo Please install 7-Zip from: https://www.7-zip.org/
    echo.
    pause
    exit /b 1
)

echo Found 7-Zip: %SEVENZIP%
echo.

REM Set version
set VERSION=v1.0.0-testnet

REM Create temporary directory for package contents
set TEMP_DIR=temp_sfx
if exist %TEMP_DIR% rd /s /q %TEMP_DIR%
mkdir %TEMP_DIR%

echo Copying files to package...
echo.

REM Copy binaries
copy dilithion-node.exe %TEMP_DIR%\ >nul
copy check-wallet-balance.exe %TEMP_DIR%\ >nul
copy genesis_gen.exe %TEMP_DIR%\ >nul

REM Copy scripts
copy START-MINING.bat %TEMP_DIR%\ >nul
copy SETUP-AND-START.bat %TEMP_DIR%\ >nul

REM Copy documentation
copy README-WINDOWS.txt %TEMP_DIR%\README.txt >nul
copy LICENSE %TEMP_DIR%\ >nul

REM Copy dependencies (if packaged)
if exist leveldb.dll copy leveldb.dll %TEMP_DIR%\ >nul

echo Creating self-extracting archive...
echo.

REM Create SFX config file
echo ;!@Install@!UTF-8! > config.txt
echo Title="Dilithion Testnet %VERSION%" >> config.txt
echo BeginPrompt="This will extract Dilithion cryptocurrency testnet files.\n\nClick 'OK' to continue." >> config.txt
echo ExtractTitle="Extracting Dilithion Testnet..." >> config.txt
echo ExtractDialogText="Please wait while Dilithion files are extracted..." >> config.txt
echo Progress="yes" >> config.txt
echo OverwriteMode="2" >> config.txt
echo GUIFlags="8+32+64+256+4096" >> config.txt
echo RunProgram="README.txt" >> config.txt
echo ;!@InstallEnd@! >> config.txt

REM Create the archive
%SEVENZIP% a -t7z temp.7z .\%TEMP_DIR%\* -mx9 >nul

REM Get SFX module
set SFX_MODULE="C:\Program Files\7-Zip\7z.sfx"
if not exist %SFX_MODULE% (
    set SFX_MODULE="C:\Program Files (x86)\7-Zip\7z.sfx"
)

REM Create self-extracting archive
copy /b %SFX_MODULE% + config.txt + temp.7z "dilithion-testnet-%VERSION%-windows-x64-installer.exe" >nul

REM Cleanup
del temp.7z >nul
del config.txt >nul
rd /s /q %TEMP_DIR% >nul

echo.
echo ================================================================
echo   SUCCESS! Created: dilithion-testnet-%VERSION%-windows-x64-installer.exe
echo ================================================================
echo.
echo File size:
dir /b "dilithion-testnet-%VERSION%-windows-x64-installer.exe" | find ".exe"
for %%A in ("dilithion-testnet-%VERSION%-windows-x64-installer.exe") do echo Size: %%~zA bytes
echo.
echo Users can now:
echo   1. Download the .exe file
echo   2. Double-click to auto-extract
echo   3. Files will be extracted to chosen folder
echo   4. README will open automatically
echo.
echo Upload this file to GitHub Releases!
echo.
pause
