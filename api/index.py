"""Vercel serverless entrypoint for the Flask app."""

from pathlib import Path
import sys
import os

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.append(str(ROOT_DIR))

# Set Vercel environment flag before importing app
os.environ["VERCEL"] = "1"

from threatops.app import app  # noqa: E402  pylint: disable=wrong-import-position

# DO NOT initialize database on serverless - database schema should be pre-initialized
# Vercel functions are ephemeral and stateless
# Database should be set up separately using: mysql -u user -p < threatops/schema.sql

@app.route('/api/health')
def health_check():
    """Health check endpoint for Vercel deployment."""
    return {"status": "ok", "message": "ThreatOps is running on Vercel"}, 200

# Vercel looks for the WSGI callable named `app`.
