"""Vercel serverless entrypoint for the Flask app."""

import sys
import os
from pathlib import Path

# Add parent directory to Python path FIRST
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

# Set Vercel environment flag BEFORE importing
os.environ["VERCEL"] = "1"

# Import the Flask app
try:
    from threatops.app import app
except ImportError as e:
    print(f"Import error: {e}", file=sys.stderr)
    print(f"Python path: {sys.path}", file=sys.stderr)
    print(f"Working directory: {os.getcwd()}", file=sys.stderr)
    raise

# Health check endpoint
@app.route('/health')
@app.route('/api/health')
def health_check():
    """Health check endpoint for Vercel deployment."""
    return {
        "status": "ok", 
        "message": "ThreatOps is running on Vercel",
        "python_version": sys.version,
    }, 200

# Error handler
@app.errorhandler(500)
def internal_error(error):
    """Handle internal server errors."""
    import traceback
    return {
        "error": "Internal Server Error",
        "message": str(error),
        "traceback": traceback.format_exc() if app.debug else None
    }, 500

# Vercel serverless handler - this is what Vercel calls
