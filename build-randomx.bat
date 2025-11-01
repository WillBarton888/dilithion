@echo off
echo Building RandomX library for Windows...
echo.

REM Set MSYS2 environment
set PATH=C:\msys64\mingw64\bin;C:\msys64\usr\bin;%PATH%

REM Navigate to RandomX build directory
cd /d "C:\Users\will\dilithion\depends\randomx\build"

echo Cleaning previous build...
C:\msys64\mingw64\bin\mingw32-make.exe clean

echo.
echo Configuring RandomX with CMake...
C:\msys64\mingw64\bin\cmake.exe .. -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release

if errorlevel 1 (
    echo.
    echo ERROR: CMake configuration failed!
    pause
    exit /b 1
)

echo.
echo Building RandomX library...
C:\msys64\mingw64\bin\mingw32-make.exe

if errorlevel 1 (
    echo.
    echo ERROR: Build failed!
    pause
    exit /b 1
)

echo.
echo SUCCESS! RandomX library built successfully.
echo Library location: C:\Users\will\dilithion\depends\randomx\build\librandomx.a
echo.
pause
