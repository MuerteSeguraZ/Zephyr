@echo off

git add --all

set MSG=%1
if "%MSG%"=="" set MSG=New large command (usermgmt) and some bugfixes

git commit -m "%MSG%"

git push origin main

pause
