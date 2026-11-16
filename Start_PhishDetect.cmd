@echo off
setlocal
cd /d "%~dp0"
title PhishDetect - keep this window open
if not exist ".venv\Scripts\python.exe" (
    echo Python environment missing. Follow README.md installation instructions.
    pause
    exit /b 1
)
if not exist "models\phish_model.joblib" (
    echo Trained model missing. Run python tasks.py train first.
    pause
    exit /b 1
)
echo Starting PhishDetect at http://127.0.0.1:8000/
echo Keep this window open while using the app. Press Ctrl+C to stop.
echo.
".venv\Scripts\python.exe" -m uvicorn phishdetect.api:app --app-dir src --host 127.0.0.1 --port 8000
echo.
echo Server stopped. Any startup error is displayed above.
pause
