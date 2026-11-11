#!/usr/bin/env python3
"""
ZDay Scanner - Module Entry Point
Run as: python -m zday_scan -u https://example.com
"""
import sys
import os
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from main import main
import asyncio

if __name__ == "__main__":
    asyncio.run(main())