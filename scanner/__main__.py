# Entry point for: python -m scanner
import sys
import asyncio
sys.path.insert(0, str(__file__.replace('scanner/__main__.py', '')))

from main import main

if __name__ == "__main__":
    asyncio.run(main())
