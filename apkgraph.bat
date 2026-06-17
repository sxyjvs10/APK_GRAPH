@echo off
setlocal
if not exist "venv\Scripts\python.exe" (
    echo [!] Error: Virtual environment not found.
    echo [!] Please run: 
    echo     python -m venv venv
    echo     .\venv\Scripts\pip install -r requirements.txt
    echo     .\venv\Scripts\pip install .
    exit /b 1
)

set PYTHONPATH=%PYTHONPATH%;%CD%
venv\Scripts\python.exe -m apkgraph.apkgraph %*
endlocal
