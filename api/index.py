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

# Diagnostic endpoint for debugging
@app.route('/api/diagnostics')
def diagnostics():
    """Diagnostic endpoint to check Vercel configuration."""
    import os
    from sqlalchemy import text
    from threatops.database import DATABASE_URL, engine
    
    # Check environment variables (without exposing sensitive data)
    env_status = {
        "VERCEL": os.getenv("VERCEL") is not None,
        "DATABASE_URL_set": os.getenv("DATABASE_URL") is not None,
        "SECRET_KEY_set": os.getenv("SECRET_KEY") is not None,
        "DATABASE_URL_preview": DATABASE_URL[:30] + "..." if len(DATABASE_URL) > 30 else DATABASE_URL,
    }
    
    # Test database connection
    try:
        with engine.connect() as conn:
            result = conn.execute(text("SELECT 1")).fetchone()
            db_status = "✅ Connected"
            
            # Check if USERS table exists
            try:
                user_count = conn.execute(text("SELECT COUNT(*) FROM USERS")).fetchone()[0]
                db_status += f" | {user_count} users in database"
            except Exception as e:
                db_status += f" | ⚠️  USERS table not found: {str(e)}"
    except Exception as e:
        db_status = f"❌ Connection failed: {str(e)}"
    
    return {
        "status": "diagnostic",
        "environment": env_status,
        "database": db_status,
        "message": "Check full documentation at /vercel_deployment.md"
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
