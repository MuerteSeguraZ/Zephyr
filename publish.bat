@echo off

git add --all

set "MSG=%~1"
if "%MSG%"=="" set "MSG=Added more WebDAV commands: bind, rebind, unbind, proppatch, patchform"

git status

git commit -m "%MSG%"

git push origin main

pause
