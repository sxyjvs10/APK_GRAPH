#!/bin/bash
export PYTHONPATH=$PYTHONPATH:$(pwd)
./venv/bin/python3 -m apkgraph.apkgraph "$@"
