@echo off
REM ThreatOps SIEM - Local Development Startup Script (Windows)

echo ========================================
echo   ThreatOps SIEM - Local Dev Server
echo ========================================
echo.

echo Activating virtual environment...
call venv\Scripts\activate.bat

echo Setting Python path...
set PYTHONPATH=%CD%

echo.
echo Starting Flask server...
echo Server will be at: http://127.0.0.1:5000
echo Login: rajesh_kumar / ADM123
echo.
echo Press Ctrl+C to stop
echo ----------------------------------------
echo.

REM Run the Flask application
python threatops\app.py
