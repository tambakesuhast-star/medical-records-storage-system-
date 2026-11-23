@echo off
title Medical Records Storage System - Public Internet Tunnel
echo =========================================================================
echo   PUBLIC INTERNET ACCESS TUNNEL
echo   St. Luke's Medical Records Storage System
echo =========================================================================
echo.
echo Your Local Network Access: http://172.20.3.86:5000
echo.
echo Connecting to public reverse tunnel gateway...
echo Once connected, a public HTTPS URL will appear below.
echo You can share that URL with anyone on the internet!
echo.
echo -------------------------------------------------------------------------
ssh -o StrictHostKeyChecking=no -R 80:127.0.0.1:5000 nokey@localhost.run
echo.
echo If localhost.run disconnects, trying alternate tunnel (a.pinggy.io)...
ssh -o StrictHostKeyChecking=no -p 443 -R0:localhost:5000 a.pinggy.io
pause
