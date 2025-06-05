@echo off
echo [*] Compiling resource file zephyr.rc...

windres zephyr.rc -O coff -o zephyr_res.o
if errorlevel 1 (
    echo [!] Resource compilation failed.
    pause
    exit /b 1
)

echo [*] Compiling zephyr.cpp with icon...

g++ zephyr.cpp zephyr_res.o -o zephyr.exe ^
  -static -static-libgcc -static-libstdc++ ^
  -liphlpapi -lws2_32 -lsetupapi -lcfgmgr32 -lwinhttp ^
  -lole32 -lshell32 -luuid -lnetapi32 -lwininet

if errorlevel 1 (
    echo [!] Compilation failed.
    pause
    exit /b 1
)

echo [✓] Compilation succeeded.
echo [*] Running zephyr.exe as administrator...
powershell -Command "Start-Process zephyr.exe -Verb RunAs"

pause
