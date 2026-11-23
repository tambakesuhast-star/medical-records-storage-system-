@echo off
title Upload Medical Records Storage System to GitHub
cd /d "%~dp0"
cls
echo =========================================================================
echo    UPLOAD MEDICAL RECORDS STORAGE SYSTEM TO GITHUB
echo    Target: https://github.com/tambakesuhast-star/medical-records-storage-system-
echo =========================================================================
echo.
echo NOTE: Your Windows system is currently signed in as "patilvikas7892-coder".
echo Because this repository belongs to "tambakesuhast-star", GitHub requires
echo authorization for tambakesuhast-star.
echo.
echo Please choose an option:
echo.
echo [1] Push using GitHub Personal Access Token (Recommended - Instant)
echo [2] Clear cached login and sign in as tambakesuhast-star in browser
echo [3] Try pushing with currently cached account
echo.
set /p choice="Enter choice (1, 2, or 3): "

if "%choice%"=="1" goto USE_TOKEN
if "%choice%"=="2" goto CLEAR_LOGIN
if "%choice%"=="3" goto PUSH_CURRENT
goto END

:USE_TOKEN
echo.
echo -------------------------------------------------------------------------
echo How to get a token:
echo 1. Go to: https://github.com/settings/tokens/new
echo 2. Check the 'repo' scope checkbox.
echo 3. Click 'Generate token' and copy it.
echo -------------------------------------------------------------------------
echo.
set /p token="Paste your GitHub Personal Access Token here: "
if "%token%"=="" (
    echo Token cannot be empty.
    pause
    exit /b
)
echo.
echo Uploading project to GitHub...
git push "https://tambakesuhast-star:%token%@github.com/tambakesuhast-star/medical-records-storage-system-.git" main
goto CHECK_RESULT

:CLEAR_LOGIN
echo.
echo Removing old cached credentials for patilvikas7892-coder...
cmdkey /delete:LegacyGeneric:target=git:https://github.com
echo.
echo Pushing to GitHub... (A browser window will open to sign in as tambakesuhast-star)
git push -u origin main
goto CHECK_RESULT

:PUSH_CURRENT
echo.
echo Pushing with current account...
git push -u origin main
goto CHECK_RESULT

:CHECK_RESULT
if %errorlevel% equ 0 (
    echo.
    echo =========================================================================
    echo   SUCCESS! All files have been uploaded to your GitHub repository!
    echo   View online: https://github.com/tambakesuhast-star/medical-records-storage-system-
    echo =========================================================================
) else (
    echo.
    echo =========================================================================
    echo   Push failed. 
    echo   Tip: On github.com, you can also add 'patilvikas7892-coder' as a collaborator
    echo   in Settings -^> Collaborators -^> Add people, then try again!
    echo =========================================================================
)

:END
echo.
pause
