@echo off

git add --all

set "MSG=%~1"
if "%MSG%"=="" set "MSG=Added folder support for fzap"

git status

git commit -m "%MSG%"

git push origin main

pause
