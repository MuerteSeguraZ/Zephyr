@echo off

git add --all

set MSG=%1
if "%MSG%"=="" set MSG=Added PATH and PATHEXT reading, so you can do, for example: "java --version" anywhere.

git commit -m "%MSG%"

git push origin main

pause
