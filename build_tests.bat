@echo off
set PATH=C:\msys64\mingw64\bin;%PATH%
cd /d c:\Users\will\dilithion
mingw32-make test_dilithion -j4 CXX=C:/msys64/mingw64/bin/g++.exe CC=C:/msys64/mingw64/bin/gcc.exe
