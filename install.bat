@echo off
REM CyberShield Installer for Windows
REM ====================================

echo.
echo ============================================
echo    CyberShield - Security Toolkit Installer
echo ============================================
echo.

REM Check Python
where python >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] Python not found! Please install Python 3.8+
    echo Download from: https://www.python.org/downloads/
    pause
    exit /b 1
)

echo [INFO] Using Python:
python --version

REM Upgrade pip
echo.
echo [INFO] Upgrading pip...
python -m pip install --upgrade pip

REM Install requirements
echo.
echo [INFO] Installing dependencies...
python -m pip install -r requirements.txt

REM Install package
echo.
echo [INFO] Installing CyberShield...
python -m pip install -e .

echo.
echo ============================================
echo    Installation Complete!
echo ============================================
echo.
echo Usage:
echo   cybershield full https://example.com
echo   cybershield phishing https://example.com
echo   cybershield vuln https://example.com
echo   cybershield serve
echo   cybershield check
echo.
echo Web Dashboard:
echo   cybershield serve --port 5000
echo   Then open: http://localhost:5000
echo.

pause
