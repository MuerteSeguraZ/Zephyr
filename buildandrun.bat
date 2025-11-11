@echo off
echo [*] Compiling the Zephyr resource file...

windres zephyr.rc -O coff -o zephyr_res.o
if errorlevel 1 (
    echo [!] Compilation of the resource file failed.
    pause
    exit /b 1
)

echo [*] Compiling Zephyr with the icon...

g++ zephyr.cpp bigcommands/inspect.cpp list/list.cpp http/http.cpp diagnostics/diagnostics.cpp zephyr_res.o -o zephyr.exe ^
  -static -static-libgcc -static-libstdc++ ^
  -liphlpapi -lws2_32 -lsetupapi -lcfgmgr32 -lwinhttp ^
  -lole32 -loleaut32 -lwbemuuid -lshell32 -luuid -lnetapi32 -lwininet ^
  -luserenv -ladvapi32 -lwtsapi32 -lpsapi -lpdh -lz -lwinmm ^
  -lwevtapi -lshlwapi -lwintrust -ltaskschd

if errorlevel 1 (
    echo [!] Compilation failed.
    pause
    exit /b 1
)

echo [✓] Compilation successful!
echo [*] Executing Zephyr with administrative privileges...
powershell -Command "Start-Process zephyr.exe -Verb RunAs"

pause