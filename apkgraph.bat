@echo off
set PYTHONPATH=%PYTHONPATH%;%CD%
venv\Scripts\python.exe -m apkgraph.apkgraph %*
