@echo off

git add --all

set MSG=%1
if "%MSG%"=="" set MSG=HTTP Client (in http folder)

git commit -m "%MSG%"

git push origin main

pause
