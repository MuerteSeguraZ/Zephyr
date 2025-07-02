@echo off

git add --all

set MSG=%1
if "%MSG%"=="" set MSG=New features in HTTP Client, better parsing.

git commit -m "%MSG%"

git push origin main

pause
