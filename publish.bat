@echo off

git add --all

set MSG=%1
if "%MSG%"=="" set MSG=Buffed linkup & usermgmt more.

git commit -m "%MSG%"

git push origin main

pause
