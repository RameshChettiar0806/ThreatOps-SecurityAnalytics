"""
Vercel Serverless Function Handler for ThreatOps SIEM
"""
import sys
import os

# Add parent directory to path so we can import backend
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from backend.app import app

# Export the Flask app for Vercel
# Vercel's Python runtime expects an 'app' variable
application = app
