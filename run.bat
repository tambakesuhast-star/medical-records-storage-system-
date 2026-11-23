@echo off
title St. Luke's Health Cloud - Medical Records Storage System (Suhas & Sujan)
echo =========================================================================
echo   ST. LUKE'S HEALTH CLOUD - MEDICAL RECORDS STORAGE SYSTEM
echo   Assignment 15: Suhas & Sujan (Healthcare Domain)
echo   Cloud VM + Azure Blob Storage (AES-256) + IP Restrictions (192.168.10.0/24)
echo =========================================================================
echo.
echo Initializing Database and Encrypted Storage Blobs...
python init_db.py
echo.
echo Running Automated Security Verification Suite...
python test_security.py
echo.
echo Starting Flask Web Application Server on all interfaces (0.0.0.0)...
echo.
echo   Localhost Access:     http://127.0.0.1:5000
echo   Local Wi-Fi Network:  http://172.20.3.86:5000
echo.
echo For worldwide public internet access, open a second terminal and run:
echo   public_tunnel.bat
echo.
python app.py
pause
