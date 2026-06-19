@echo off
setlocal

:: Detect Python executable
set PYTHON_EXE=
python --version >nul 2>&1
if %errorlevel% equ 0 goto set_python
py --version >nul 2>&1
if %errorlevel% equ 0 goto set_py
goto check_fail

:set_python
set PYTHON_EXE=python
goto continue_setup

:set_py
set PYTHON_EXE=py
goto continue_setup

:check_fail
echo [!] Python is not installed or not in your PATH.
echo [!] Please install Python 3.8+ and try again.
pause
exit /b 1

:continue_setup
:: Check if virtual environment exists
if not exist "venv\Scripts\python.exe" (
    echo [*] First time setup: Creating Python virtual environment...
    %PYTHON_EXE% -m venv venv
    if %errorlevel% neq 0 (
        echo [!] Failed to create virtual environment.
        pause
        exit /b 1
    )
    
    echo [*] Installing requirements...
    call venv\Scripts\python.exe -m pip install --upgrade pip
    call venv\Scripts\pip.exe install -r requirements.txt
    call venv\Scripts\pip.exe install .
    
    echo [*] Checking for optional tools ^(Frida, YARA^)...
    call venv\Scripts\pip.exe install frida-tools yara-python
    
    echo [+] Setup complete!
    echo ----------------------------------------------------
)

:: Run the tool
set PYTHONPATH=%PYTHONPATH%;%CD%
call venv\Scripts\python.exe -m apkgraph.apkgraph %*

if %errorlevel% neq 0 (
    echo.
    echo [!] APKGraph exited with an error. 
    echo [!] Try running "apkgraph.bat --help" for usage information.
)

endlocal
