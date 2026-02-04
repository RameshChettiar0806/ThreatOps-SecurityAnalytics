"""Vercel serverless entrypoint for the Flask app."""

from pathlib import Path
import sys

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.append(str(ROOT_DIR))

from threatops.app import app  # noqa: E402  pylint: disable=wrong-import-position

# Vercel looks for the WSGI callable named `app`.
