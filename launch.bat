@echo off
TITLE Secure RPL Routing Simulation - Launcher
color 0f

echo ========================================================
echo   Secure RPL Routing Simulation - Launcher
echo ========================================================
echo.
echo Installing/Verifying dependencies...
py -m pip install -r requirements.txt >nul 2>&1

echo.
echo Starting the Streamlit Dashboard...
echo The dashboard will automatically open in your default browser.
echo Press CTRL+C in this window to stop the server when you are done.
echo ========================================================
echo.

py -m streamlit run dashboard/app.py

pause
