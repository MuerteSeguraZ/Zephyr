@echo off

git add --all

set "MSG=%~1"
if "%MSG%"=="" set "MSG=more diagnostic commands (drivers fix, defender, tasks)"

git status

git commit -m "%MSG%"

git push origin main

pause
