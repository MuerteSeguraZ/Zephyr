@echo off

git add --all

set MSG=%1
if "%MSG%"=="" set MSG=Added a few more WebDAV HTTP commands and some info commands, like meminfo and motherbinfo.

git commit -m "%MSG%"

git push origin main

pause
