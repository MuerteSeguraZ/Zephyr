@echo off
echo [*] Compilant el fitxer de recursos zephyr.rc...

windres zephyr.rc -O coff -o zephyr_res.o
if errorlevel 1 (
    echo [!] Compilació dels recursos fallada.
    pause
    exit /b 1
)

echo [*] Compilant zephyr.cpp amb la icona...

g++ zephyr.cpp bigcommands/inspect.cpp list/list.cpp http/http.cpp diagnostics/diagnostics.cpp zephyr_res.o -o zephyr.exe ^
  -static -static-libgcc -static-libstdc++ ^
  -liphlpapi -lws2_32 -lsetupapi -lcfgmgr32 -lwinhttp ^
  -lole32 -loleaut32 -lwbemuuid -lshell32 -luuid -lnetapi32 -lwininet ^
  -luserenv -ladvapi32 -lwtsapi32 -lpsapi -lpdh -lz -lwinmm ^
  -lwevtapi -lshlwapi -lwintrust

if errorlevel 1 (
    echo [!] Compilació fallada.
    pause
    exit /b 1
)

echo [✓] Compilació exitosa.
echo [*] Executant zephyr.exe com a administrador...
powershell -Command "Start-Process zephyr.exe -Verb RunAs"

pause