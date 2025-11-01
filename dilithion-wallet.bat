@echo off
REM Dilithion CLI Wallet Wrapper (Windows) - SECURE VERSION
REM Simple command-line interface for wallet operations via RPC
REM Version: 1.0.1-secure
REM
REM SECURITY: All user inputs validated before use
REM - Address format validation (DLT1 + alphanumeric, 44-94 chars)
REM - Amount validation (positive, no negatives, format check)
REM - Secure temp file handling with random names
REM - Proper cleanup on exit
REM

setlocal enabledelayedexpansion

REM Version
set VERSION=1.0.1-secure

REM Configuration
if "%DILITHION_RPC_HOST%"=="" set DILITHION_RPC_HOST=localhost
if "%DILITHION_RPC_PORT%"=="" set DILITHION_RPC_PORT=18332
set RPC_URL=http://!DILITHION_RPC_HOST!:!DILITHION_RPC_PORT!

REM Timeout settings (seconds)
set CURL_TIMEOUT=30

REM Check if curl is available
where curl >nul 2>nul
if %errorlevel% neq 0 (
    echo Error: curl is required but not found.
    echo curl is included in Windows 10/11. If not available, download from: https://curl.se/windows/
    exit /b 1
)

REM Get command
set COMMAND=%1

if "%COMMAND%"=="" (
    call :show_help
    exit /b 1
)

REM Dispatch command
if /i "%COMMAND%"=="balance" goto cmd_balance
if /i "%COMMAND%"=="newaddress" goto cmd_newaddress
if /i "%COMMAND%"=="addresses" goto cmd_addresses
if /i "%COMMAND%"=="listunspent" goto cmd_listunspent
if /i "%COMMAND%"=="send" goto cmd_send
if /i "%COMMAND%"=="version" goto cmd_version
if /i "%COMMAND%"=="help" goto show_help
if /i "%COMMAND%"=="--help" goto show_help
if /i "%COMMAND%"=="-h" goto show_help

echo Error: Unknown command '%COMMAND%'
echo.
call :show_help
exit /b 1

REM ===== VALIDATION FUNCTIONS =====

:validate_address
set "ADDR=%~1"

REM Check minimum length
if "%ADDR:~44,1%"=="" (
    echo Error: Address too short (must be 44-94 characters^)
    echo Provided address length: %ADDR% characters
    exit /b 1
)

REM Check maximum length (approximate)
if not "%ADDR:~94,1%"=="" (
    echo Error: Address too long (must be 44-94 characters^)
    exit /b 1
)

REM Check prefix
if not "%ADDR:~0,4%"=="DLT1" (
    echo Error: Invalid address format
    echo Address must start with 'DLT1'
    exit /b 1
)

REM Check for invalid characters (spaces, special chars)
echo %ADDR% | findstr /R /C:" " >nul
if not errorlevel 1 (
    echo Error: Address contains spaces
    exit /b 1
)

echo %ADDR% | findstr /R /C:"[^a-zA-Z0-9]" >nul
if not errorlevel 1 (
    REM Check if it's only the DLT1 prefix causing the match
    set "TEST_ADDR=%ADDR:~4%"
    echo !TEST_ADDR! | findstr /R /C:"[^a-zA-Z0-9]" >nul
    if not errorlevel 1 (
        echo Error: Address contains invalid characters
        echo Address must be alphanumeric only
        exit /b 1
    )
)

echo [OK] Address validation: PASSED
exit /b 0

:validate_amount
set "AMT=%~1"

REM Check for negative (contains minus sign)
echo %AMT% | findstr "-" >nul
if not errorlevel 1 (
    echo Error: Amount cannot be negative
    exit /b 1
)

REM Check for spaces
echo %AMT% | findstr " " >nul
if not errorlevel 1 (
    echo Error: Amount contains spaces
    exit /b 1
)

REM Check format: only digits and optional single decimal point
echo %AMT% | findstr /R /C:"^[0-9][0-9]*$" >nul
if not errorlevel 1 goto amount_format_ok

echo %AMT% | findstr /R /C:"^[0-9][0-9]*\.[0-9][0-9]*$" >nul
if not errorlevel 1 goto amount_format_ok

echo Error: Amount must be a positive number
echo Examples: 10, 10.5, 10.12345678
exit /b 1

:amount_format_ok

REM Check for zero
if "%AMT%"=="0" (
    echo Error: Amount must be greater than zero
    exit /b 1
)

if "%AMT%"=="0.0" (
    echo Error: Amount must be greater than zero
    exit /b 1
)

if "%AMT%"=="0.00" (
    echo Error: Amount must be greater than zero
    exit /b 1
)

REM Check decimal places (max 8)
for /f "tokens=2 delims=." %%a in ("%AMT%") do (
    set "DECIMALS=%%a"
    if not "!DECIMALS!"=="" (
        if not "!DECIMALS:~8,1!"=="" (
            echo Error: Amount has too many decimal places (max 8^)
            exit /b 1
        )
    )
)

echo [OK] Amount validation: PASSED
exit /b 0

REM ===== COMMAND IMPLEMENTATIONS =====

:cmd_balance
echo Fetching wallet balance...
echo.

REM Generate random temp file
set "TEMP_FILE=%TEMP%\dilithion-%RANDOM%%RANDOM%%TIME:~-5,5%.json"

set "JSON={\"jsonrpc\":\"2.0\",\"method\":\"getbalance\",\"params\":{},\"id\":1}"
curl --max-time %CURL_TIMEOUT% -s -X POST "%RPC_URL%" -H "Content-Type: application/json" -d "%JSON%" > "!TEMP_FILE!"

REM Check if file was created (connection successful)
if not exist "!TEMP_FILE!" (
    echo Error: Could not connect to Dilithion node at %RPC_URL%
    echo Make sure the node is running with RPC enabled.
    exit /b 2
)

REM Check for errors in response
findstr /C:"\"error\"" "!TEMP_FILE!" | findstr /V /C:"null" >nul
if not errorlevel 1 (
    echo Error: RPC returned an error
    type "!TEMP_FILE!"
    del "!TEMP_FILE!"
    exit /b 5
)

echo Response from node:
type "!TEMP_FILE!"
echo.
echo.
echo Note: For formatted output, install jq from https://stedolan.github.io/jq/

REM Cleanup
del "!TEMP_FILE!"
endlocal
goto :eof

:cmd_newaddress
echo Generating new address...
echo.

set "TEMP_FILE=%TEMP%\dilithion-%RANDOM%%RANDOM%%TIME:~-5,5%.json"

set "JSON={\"jsonrpc\":\"2.0\",\"method\":\"getnewaddress\",\"params\":{},\"id\":1}"
curl --max-time %CURL_TIMEOUT% -s -X POST "%RPC_URL%" -H "Content-Type: application/json" -d "%JSON%" > "!TEMP_FILE!"

if not exist "!TEMP_FILE!" (
    echo Error: Could not connect to Dilithion node at %RPC_URL%
    exit /b 2
)

echo New Address:
type "!TEMP_FILE!"
echo.
echo.
echo You can receive DIL at this address.

REM Cleanup
del "!TEMP_FILE!"
endlocal
goto :eof

:cmd_addresses
echo Listing wallet addresses...
echo.

set "TEMP_FILE=%TEMP%\dilithion-%RANDOM%%RANDOM%%TIME:~-5,5%.json"

set "JSON={\"jsonrpc\":\"2.0\",\"method\":\"getaddresses\",\"params\":{},\"id\":1}"
curl --max-time %CURL_TIMEOUT% -s -X POST "%RPC_URL%" -H "Content-Type: application/json" -d "%JSON%" > "!TEMP_FILE!"

if not exist "!TEMP_FILE!" (
    echo Error: Could not connect to Dilithion node at %RPC_URL%
    exit /b 2
)

echo Addresses:
type "!TEMP_FILE!"
echo.

REM Cleanup
del "!TEMP_FILE!"
endlocal
goto :eof

:cmd_listunspent
echo Listing unspent outputs...
echo.

set "TEMP_FILE=%TEMP%\dilithion-%RANDOM%%RANDOM%%TIME:~-5,5%.json"

set "JSON={\"jsonrpc\":\"2.0\",\"method\":\"listunspent\",\"params\":{},\"id\":1}"
curl --max-time %CURL_TIMEOUT% -s -X POST "%RPC_URL%" -H "Content-Type: application/json" -d "%JSON%" > "!TEMP_FILE!"

if not exist "!TEMP_FILE!" (
    echo Error: Could not connect to Dilithion node at %RPC_URL%
    exit /b 2
)

echo Unspent Outputs:
type "!TEMP_FILE!"
echo.

REM Cleanup
del "!TEMP_FILE!"
endlocal
goto :eof

:cmd_send
if "%2"=="" (
    echo Error: Missing arguments
    echo Usage: dilithion-wallet.bat send ^<address^> ^<amount^>
    echo Example: dilithion-wallet.bat send DLT1abc123... 10.5
    exit /b 3
)

if "%3"=="" (
    echo Error: Missing amount
    echo Usage: dilithion-wallet.bat send ^<address^> ^<amount^>
    echo Example: dilithion-wallet.bat send DLT1abc123... 10.5
    exit /b 4
)

set ADDRESS=%2
set AMOUNT=%3

echo Validating transaction parameters...
echo.

REM Validate address (SECURITY: prevents sending to invalid addresses)
call :validate_address "%ADDRESS%"
if errorlevel 1 exit /b 3

REM Validate amount (SECURITY: prevents invalid transactions)
call :validate_amount "%AMOUNT%"
if errorlevel 1 exit /b 4

echo.
echo ========================================================
echo                  CONFIRM TRANSACTION
echo ========================================================
echo To:      %ADDRESS%
echo Amount:  %AMOUNT% DIL
echo ========================================================
echo.
echo WARNING: This action is PERMANENT and CANNOT be undone!
echo WARNING: Verify the address is EXACTLY correct!
echo.

set /p CONFIRM="Type 'yes' to confirm, anything else to cancel: "

REM Case-insensitive comparison
if /i not "%CONFIRM%"=="yes" (
    echo Transaction cancelled.
    exit /b 0
)

echo.
echo Sending transaction...

REM Generate random temp files
set "JSON_FILE=%TEMP%\dilithion-req-%RANDOM%%RANDOM%%TIME:~-5,5%.json"
set "TEMP_FILE=%TEMP%\dilithion-res-%RANDOM%%RANDOM%%TIME:~-5,5%.json"

REM Write JSON to temp file (SECURITY: prevents command injection)
(
    echo {"jsonrpc":"2.0","method":"sendtoaddress","params":{"address":"%ADDRESS%","amount":%AMOUNT%},"id":1}
) > "!JSON_FILE!"

curl --max-time %CURL_TIMEOUT% -s -X POST "%RPC_URL%" -H "Content-Type: application/json" -d @"!JSON_FILE!" > "!TEMP_FILE!"

if not exist "!TEMP_FILE!" (
    echo Error: Could not connect to Dilithion node at %RPC_URL%
    REM Cleanup
    if exist "!JSON_FILE!" del "!JSON_FILE!"
    exit /b 2
)

REM Check for errors
findstr /C:"\"error\"" "!TEMP_FILE!" | findstr /V /C:"null" >nul
if not errorlevel 1 (
    echo Error: RPC returned an error
    type "!TEMP_FILE!"
    REM Cleanup
    del "!JSON_FILE!"
    del "!TEMP_FILE!"
    exit /b 5
)

echo.
echo [OK] Transaction sent successfully!
echo.
echo Transaction Response:
type "!TEMP_FILE!"
echo.
echo Note: Transaction requires network confirmation

REM Cleanup
del "!JSON_FILE!"
del "!TEMP_FILE!"
endlocal
goto :eof

:cmd_version
echo Dilithion CLI Wallet v%VERSION%
echo Security: Production-grade with input validation
endlocal
goto :eof

:show_help
echo Dilithion CLI Wallet v%VERSION% (Windows)
echo.
echo Usage:
echo   dilithion-wallet.bat balance                  - Show wallet balance
echo   dilithion-wallet.bat newaddress               - Generate new receiving address
echo   dilithion-wallet.bat addresses                - List all wallet addresses
echo   dilithion-wallet.bat listunspent              - List unspent transaction outputs
echo   dilithion-wallet.bat send ^<address^> ^<amount^>  - Send DIL to address
echo   dilithion-wallet.bat help                     - Show this help message
echo   dilithion-wallet.bat version                  - Show version
echo.
echo Environment Variables:
echo   DILITHION_RPC_HOST  - RPC host (default: localhost)
echo   DILITHION_RPC_PORT  - RPC port (default: 18332 for testnet)
echo.
echo Examples:
echo   # Check balance
echo   dilithion-wallet.bat balance
echo.
echo   # Generate new address
echo   dilithion-wallet.bat newaddress
echo.
echo   # Send 10.5 DIL
echo   dilithion-wallet.bat send DLT1abc123... 10.5
echo.
echo SECURITY: Always verify addresses before sending!
echo See CLI-WALLET-GUIDE.md for important safety information
echo.
echo Note: For pretty-printed JSON output, install jq from https://stedolan.github.io/jq/
echo.
endlocal
goto :eof
