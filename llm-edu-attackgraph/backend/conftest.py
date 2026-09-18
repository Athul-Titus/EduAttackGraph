"""pytest configuration — sets up Python path for imports."""
import sys
import os

# Add the backend directory to sys.path so 'app' is importable
sys.path.insert(0, os.path.dirname(__file__))
