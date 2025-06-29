@echo off

git add --all

set MSG=%1
if "%MSG%"=="" set MSG=Better BIOSInfo and you can run .ps1, .exe and .vbs scripts now

git commit -m "%MSG%"

git push origin main

pause
