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

REM Copy binaries (Windows .exe files + wallet CLI)
echo [2/5] Copying binaries and wallet tools...
copy release-binaries\windows\dilithion-node.exe %RELEASE_DIR%\ || goto :copy_error
copy release-binaries\windows\check-wallet-balance.exe %RELEASE_DIR%\ || goto :copy_error
copy release-binaries\windows\genesis_gen.exe %RELEASE_DIR%\ || goto :copy_error
copy dilithion-wallet.bat %RELEASE_DIR%\ || goto :copy_error
echo    - All binaries copied successfully

REM Copy required DLLs
echo [3/5] Copying runtime libraries (DLLs)...
echo    - Copying MinGW runtime DLLs from local...
copy libwinpthread-1.dll %RELEASE_DIR%\ || (echo FAILED: libwinpthread-1.dll && goto :copy_error)
copy libgcc_s_seh-1.dll %RELEASE_DIR%\ || (echo FAILED: libgcc_s_seh-1.dll && goto :copy_error)
copy libleveldb.dll %RELEASE_DIR%\ || (echo FAILED: libleveldb.dll && goto :copy_error)
echo    - Copying MinGW/OpenSSL DLLs from Git installation...
copy "C:\Program Files\Git\mingw64\bin\libstdc++-6.dll" %RELEASE_DIR%\ || (echo FAILED: libstdc++-6.dll && goto :copy_error)
copy "C:\Program Files\Git\mingw64\bin\libcrypto-3-x64.dll" %RELEASE_DIR%\ || (echo FAILED: libcrypto-3-x64.dll && goto :copy_error)
copy "C:\Program Files\Git\mingw64\bin\libssl-3-x64.dll" %RELEASE_DIR%\ || (echo FAILED: libssl-3-x64.dll && goto :copy_error)
echo    [SUCCESS] All 6 DLLs copied successfully

REM Copy launcher scripts and debug tools
echo [4/5] Copying launcher scripts and documentation...
copy SETUP-AND-START.bat %RELEASE_DIR%\ || goto :copy_error
copy START-MINING.bat %RELEASE_DIR%\ || goto :copy_error
copy SETUP-AND-START-NO-COLOR.bat %RELEASE_DIR%\ || goto :copy_error
copy TEST-DEBUG.bat %RELEASE_DIR%\ || goto :copy_error
copy ULTRA-DEBUG.bat %RELEASE_DIR%\ || goto :copy_error
copy FIX-WINDOWS-DEFENDER.bat %RELEASE_DIR%\ || goto :copy_error
copy README-WINDOWS.txt %RELEASE_DIR%\README.txt || goto :copy_error
copy TESTNET-GUIDE.md %RELEASE_DIR%\TESTNET-GUIDE.md || goto :copy_error
copy ANTIVIRUS-SOLUTION.md %RELEASE_DIR%\ || goto :copy_error
echo    - All scripts and documentation copied successfully

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
goto :eof

:copy_error
color 0C
echo.
echo ================================================================
echo   ERROR: File copy failed!
echo ================================================================
echo.
echo A required file could not be copied to the release directory.
echo.
echo Common causes:
echo   1. Source file does not exist
echo   2. Permission denied
echo   3. Disk space full
echo.
echo Please check that all required files exist and try again.
echo.
pause
exit /b 1
