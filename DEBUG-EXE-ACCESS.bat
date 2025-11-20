@echo off
echo ========================================
echo DEBUGGING EXECUTABLE ACCESS
echo ========================================
echo.
echo Current directory: %CD%
echo.
echo [1] Checking if dilithion-node.exe exists...
if exist "dilithion-node.exe" (
    echo    [OK] File exists
    dir dilithion-node.exe | find "dilithion-node.exe"
) else (
    echo    [FAIL] File NOT found
)
echo.
echo [2] Attempting to run dilithion-node.exe --version...
dilithion-node.exe --version 2>&1
set EXIT_CODE=%errorlevel%
echo    Exit code: %EXIT_CODE%
echo.
echo [3] Checking if dilithion-node.exe still exists after run attempt...
if exist "dilithion-node.exe" (
    echo    [OK] File still exists
) else (
    echo    [FAIL] File DISAPPEARED after execution attempt!
    echo    This means antivirus removed it during execution.
)
echo.
echo [4] Checking Windows Defender real-time protection status...
powershell -Command "Get-MpPreference | Select-Object DisableRealtimeMonitoring"
echo.
echo [5] Checking for exclusions on this folder...
powershell -Command "Get-MpPreference | Select-Object -ExpandProperty ExclusionPath"
echo.
pause
