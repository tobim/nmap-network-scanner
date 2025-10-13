#!/usr/bin/env python3
"""
Network Scanner API Launcher
Runs the FastAPI application from the src directory
"""

import sys
import os

# Add src directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

# Import and run the API
from api import app
import uvicorn

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8001)
