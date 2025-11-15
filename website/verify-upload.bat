@echo off
REM Verification script to check if dilithion.org has been updated

echo ============================================
echo Dilithion.org Update Verification Script
echo ============================================
echo.

echo Checking website version...
echo.

REM Use curl to fetch the website and check for v1.0.7
curl -s https://dilithion.org/ | findstr "v1.0.7" > nul
if %errorlevel% equ 0 (
    echo [SUCCESS] Website shows v1.0.7
) else (
    echo [FAIL] Website does NOT show v1.0.7
    echo.
    echo Current version on website:
    curl -s https://dilithion.org/ | findstr "LATEST VERSION"
)

echo.
echo Checking for old seed node (170.64.203.134)...
curl -s https://dilithion.org/ | findstr "170.64.203.134" > nul
if %errorlevel% equ 0 (
    echo [FAIL] Old seed node 170.64.203.134 still present!
) else (
    echo [SUCCESS] Old seed node removed
)

echo.
echo Checking for new seed nodes...
curl -s https://dilithion.org/ | findstr "134.122.4.164" > nul
if %errorlevel% equ 0 (
    echo [SUCCESS] NYC seed node (134.122.4.164) found
) else (
    echo [FAIL] NYC seed node NOT found
)

echo.
echo ============================================
echo.
echo If you see FAIL messages, the cache hasn't cleared yet.
echo Try the cache troubleshooting steps in CACHE-TROUBLESHOOTING.md
echo.
pause
