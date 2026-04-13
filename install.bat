@echo off
echo ====================================
echo Smart Contract Analyzer - Installer
echo ====================================
echo.

echo Verificando Python...
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python no está instalado
    echo Por favor, instale Python desde https://python.org
    pause
    exit /b 1
)

echo Python encontrado
echo.

echo Instalando dependencias...
python -m pip install requests

echo.
echo Iniciando Smart Contract Analyzer...
echo.

start "" "dist\SmartContractAnalyzer.exe"

echo.
echo ====================================
echo ¡INSTALACIÓN COMPLETADA!
echo ====================================
echo.
echo El programa se está iniciando...
echo Si no se abre automáticamente, ejecute:
echo dist\SmartContractAnalyzer.exe
echo.
pause
