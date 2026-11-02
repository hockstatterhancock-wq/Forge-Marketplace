@echo off
setlocal
cd /d "%~dp0"
where node >nul 2>nul
if errorlevel 1 (
  echo Node.js is required. Install the current LTS version from https://nodejs.org/ and try again.
  pause
  exit /b 1
)
node "%~dp0backend\server.js"
if errorlevel 1 (
  echo ForgeMarket stopped because the backend could not start.
  pause
)
