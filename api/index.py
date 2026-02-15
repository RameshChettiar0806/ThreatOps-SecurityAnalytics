"""Vercel serverless entrypoint for the Flask app."""

from pathlib import Path
import sys
import os

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.append(str(ROOT_DIR))

# Set Vercel environment flag
os.environ["VERCEL"] = "1"

from threatops.app import app  # noqa: E402  pylint: disable=wrong-import-position

# Initialize database on cold start
try:
    from threatops.app import init_db
    init_db()
except Exception as e:
    print(f"Database initialization warning: {e}")
    # Continue even if DB init fails - better to show error page than 404

# Vercel looks for the WSGI callable named `app`.
