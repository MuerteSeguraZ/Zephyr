@echo off

git add --all

set MSG=%1
if "%MSG%"=="" set MSG=Added DHCPv6 to linkup.

git commit -m "%MSG%"

git push origin main

pause
