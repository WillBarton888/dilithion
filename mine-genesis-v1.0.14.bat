@echo off
echo Mining Dilithion Testnet Genesis v1.0.14
echo Difficulty: 0x1f010000 (6x harder)
echo Expected time: ~60 seconds at 600 H/s
echo.
genesis_gen.exe --testnet --mine > genesis-v1.0.14-output.txt 2>&1
type genesis-v1.0.14-output.txt
pause
