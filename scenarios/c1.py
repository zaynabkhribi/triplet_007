#!/usr/bin/env python3
"""Trigger for scenario c1. One command, one log file in ../logs.

    python scenarios/c1.py

Settings (broker address, keys) come from twin/config.json and twin/secrets.json."""
import os
import subprocess
import sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.exit(subprocess.call([sys.executable, os.path.join(ROOT, "twin", "src", "twin.py"), "run", "c1"], cwd=os.path.join(ROOT, "twin")))
