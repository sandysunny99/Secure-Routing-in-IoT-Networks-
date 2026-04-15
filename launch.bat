@echo off
TITLE Secure RPL Routing Simulation - Launcher
color 0f

echo ========================================================
echo   Secure RPL Routing Simulation - Launcher
echo ========================================================
echo.
echo Installing/Verifying dependencies...
py -m pip install -r requirements.txt
if %errorlevel% neq 0 (
    echo.
    echo Failed to install dependencies. Please check the pip output above.
    pause
    exit /b %errorlevel%
)

echo.
echo Starting the Streamlit Dashboard...
echo The dashboard should be available at:
if exist nul (echo http://localhost:8501)
echo Press CTRL+C in this window to stop the server when you are done.
echo ========================================================
echo.

py -m streamlit run dashboard/app.py

pause
