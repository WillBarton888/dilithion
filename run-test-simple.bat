@echo off
cd /d C:\Users\will\dilithion
dilithion-node.exe --testnet --mine --mining-threads=20 --testnet-wipe-if-bad-genesis > test-simple-output.txt 2>&1
