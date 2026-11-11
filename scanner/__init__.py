#!/usr/bin/env python3
"""ZDay Scanner - Legacy Scanner Module"""
# This is a legacy module kept for backward compatibility
# The main scanner is in src.core.scanner

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import main

if __name__ == "__main__":
    main.main()
