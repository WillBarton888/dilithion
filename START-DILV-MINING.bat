@echo off
REM ========================================================
REM  DilV MAINNET - QUICK START MINER
REM ========================================================

title DilV Miner - Running

echo.
echo  ========================================================
echo    DilV MAINNET - VDF MINER
echo  ========================================================
echo.
echo  Starting DilV VDF miner...
echo.
echo  Seed nodes:
echo    NYC:       138.197.68.128:9444
echo    London:    167.172.56.119:9444
echo    Singapore: 165.22.103.114:9444
echo    Sydney:    134.199.159.83:9444
echo.
echo  Note: VDF mining is single-threaded by design.
echo  Your CPU participates in a provably fair lottery.
echo.
echo  Press Ctrl+C to stop mining.
echo.

dilv-node.exe --mine
