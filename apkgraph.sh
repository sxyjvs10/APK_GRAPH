#!/bin/bash

# APKGraph v2.0 Launcher

# Exit on first error
set -e

# Check if Python 3 is installed
if ! command -v python3 &> /dev/null; then
    echo "[!] Python 3 is not installed or not in your PATH."
    echo "[!] Please install Python 3.8+ and try again."
    exit 1
fi

# Check if virtual environment exists
if [ ! -f "venv/bin/python3" ]; then
    echo "[*] First time setup: Creating Python virtual environment..."
    python3 -m venv venv
    
    echo "[*] Activating virtual environment..."
    source venv/bin/activate
    
    echo "[*] Upgrading pip..."
    pip install --upgrade pip
    
    echo "[*] Installing requirements..."
    pip install -r requirements.txt
    pip install .
    
    echo "[*] Installing optional advanced tool dependencies (Frida, YARA)..."
    pip install frida-tools yara-python
    
    echo "[+] Setup complete!"
    echo "----------------------------------------------------"
else
    source venv/bin/activate
fi

# Set PYTHONPATH and execute
export PYTHONPATH="${PYTHONPATH}:$(pwd)"
python3 -m apkgraph.apkgraph "$@"

EXIT_CODE=$?
if [ $EXIT_CODE -ne 0 ]; then
    echo ""
    echo "[!] APKGraph exited with an error (Code: $EXIT_CODE)."
    echo "[!] Try running './apkgraph.sh --help' for usage information."
fi

exit $EXIT_CODE
