"""Flask application for ThreatOps SIEM with Authentication & RBAC."""

import hashlib
import hmac
import logging
import os
import re
import secrets
from datetime import datetime
from functools import wraps
from pathlib import Path

from flask import Flask, jsonify, render_template, request, session, redirect, url_for, flash
from sqlalchemy import func, text
from sqlalchemy.exc import SQLAlchemyError
from werkzeug.security import check_password_hash, generate_password_hash

# Resolve frontend paths relative to this file
_BACKEND_DIR = Path(__file__).resolve().parent
_FRONTEND_DIR = _BACKEND_DIR.parent / "frontend"

# Use absolute imports for Vercel compatibility
try:
    from backend.database import Base, SessionLocal, engine
    from backend.models import (
        User, RawLog, MitreAttackTechnique, MitreDefendCountermeasure,
        ThreatCorrelation, Alert, AuditLog
    )
except ImportError:
    # Fallback for local development
    from database import Base, SessionLocal, engine
    from models import (
        User, RawLog, MitreAttackTechnique, MitreDefendCountermeasure,
        ThreatCorrelation, Alert, AuditLog
    )


# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(
    __name__,
    template_folder=str(_FRONTEND_DIR / "templates"),
    static_folder=str(_FRONTEND_DIR / "static"),
)
app.secret_key = os.getenv('SECRET_KEY', 'threatops_secret_key_change_in_production')
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = os.getenv('VERCEL') is not None  # Secure cookies in production

READ_ONLY_ROLES = {'Manager', 'Analyst', 'Responder', 'Hunter'}
ENGINEER_RESTRICTED_PREFIXES = {'GRANT', 'REVOKE', 'COMMIT', 'ROLLBACK', 'SAVEPOINT'}
BLOCKED_READ_ONLY_KEYWORDS = {
    'ALTER', 'CALL', 'CREATE', 'DELETE', 'DROP', 'GRANT',
    'INSERT', 'MERGE', 'REPLACE', 'REVOKE', 'TRUNCATE', 'UPDATE'
}
ALLOWED_ALERT_STATUSES = {'Open', 'In Progress', 'Resolved', 'False Positive'}
VALID_ROLES = {'Admin', 'Analyst', 'Manager', 'Engineer', 'Responder', 'Hunter'}


def _generate_csrf_token():
    """Return the per-session CSRF token, creating it lazily when needed."""
    token = session.get('_csrf_token')
    if not token:
        token = secrets.token_urlsafe(32)
        session['_csrf_token'] = token
    return token


def _request_csrf_token():
    """Read the token from either JSON headers or standard form data."""
    return (
        request.headers.get('X-CSRF-Token')
        or request.form.get('csrf_token')
        or request.headers.get('X-CSRFToken')
    )


def _enforce_csrf():
    """Validate CSRF tokens for state-changing requests."""
    session_token = session.get('_csrf_token')
    request_token = _request_csrf_token()
    if not session_token or not request_token:
        return False
    return hmac.compare_digest(session_token, request_token)


def _normalize_query(query):
    """Normalize incoming SQL so simple role checks stay reliable."""
    stripped = (query or '').strip()
    stripped = re.sub(r'^\s*(--[^\n]*\n|/\*.*?\*/\s*)+', '', stripped, flags=re.DOTALL)
    return stripped.strip()


def _first_sql_keyword(query):
    """Return the first SQL keyword, uppercased."""
    normalized = _normalize_query(query)
    if not normalized:
        return ''
    return normalized.split(None, 1)[0].rstrip(';').upper()


def _validate_query_permissions(role, query):
    """Validate a raw SQL query against the classroom demo role policy."""
    normalized = _normalize_query(query)
    if not normalized:
        return "Query cannot be empty."

    if ';' in normalized.rstrip(';'):
        return "Only one SQL statement can be executed at a time."

    query_upper = normalized.upper()
    first_keyword = _first_sql_keyword(normalized)

    if role in READ_ONLY_ROLES:
        if first_keyword != 'SELECT':
            return f"{role}s can only execute SELECT queries."
        for keyword in BLOCKED_READ_ONLY_KEYWORDS:
            if re.search(rf'\b{keyword}\b', query_upper):
                return f"Keyword '{keyword}' is not allowed for {role}s."

    if role == 'Engineer' and first_keyword in ENGINEER_RESTRICTED_PREFIXES:
        return f"Engineers cannot execute {first_keyword} statements."

    return None


def _is_legacy_sha256_hash(password_hash):
    """Return True when a stored password looks like the old unsalted SHA-256 hash."""
    return bool(re.fullmatch(r'[0-9a-f]{64}', (password_hash or '').lower()))


def _verify_password(stored_hash, password):
    """Check both modern Werkzeug hashes and the legacy SHA-256 classroom hashes."""
    if not stored_hash:
        return False
    if _is_legacy_sha256_hash(stored_hash):
        legacy_hash = hashlib.sha256(password.encode()).hexdigest()
        return hmac.compare_digest(stored_hash, legacy_hash)
    return check_password_hash(stored_hash, password)


app.jinja_env.globals['csrf_token'] = _generate_csrf_token


@app.before_request
def csrf_protect():
    """Apply CSRF protection to authenticated, state-changing routes."""
    if request.method not in {'POST', 'PUT', 'PATCH', 'DELETE'}:
        return None
    if request.endpoint in {'login'}:
        return None
    if 'user_id' not in session:
        return None
    if not _enforce_csrf():
        return jsonify({"error": "Invalid or missing CSRF token."}), 403
    return None


@app.context_processor
def inject_template_context():
    """Expose shared template helpers."""
    return {"csrf_token_value": _generate_csrf_token()}



def init_db():
    """Create database tables if they do not exist."""
    try:
        logger.info("Initializing database...")
        Base.metadata.create_all(bind=engine)
        ensure_default_users()
        logger.info("Database initialized successfully")
    except Exception as e:
        logger.error(f"Database initialization failed: {e}")
        raise


def ensure_default_users():
    """Seed SOC/CIRT team users displayed on the login page."""
    default_users = [
        # Admins
        {"username": "rajeshKumar",   "password": "ADM123",   "role": "Admin",     "email": "rajesh.kumar@threatops.local"},
        {"username": "deepakVerma",   "password": "ADM123",   "role": "Admin",     "email": "deepak.verma@threatops.local"},
        # Manager
        {"username": "priyaSharma",   "password": "MGR123",   "role": "Manager",   "email": "priya.sharma@threatops.local"},
        # Analysts
        {"username": "amitPatel",     "password": "ANLST123", "role": "Analyst",   "email": "amit.patel@threatops.local"},
        {"username": "snehaSingh",    "password": "ANLST123", "role": "Analyst",   "email": "sneha.singh@threatops.local"},
        {"username": "rohanGupta",    "password": "ANLST123", "role": "Analyst",   "email": "rohan.gupta@threatops.local"},
        {"username": "meeraKrishnan", "password": "ANLST123", "role": "Analyst",   "email": "meera.krishnan@threatops.local"},
        # Engineers
        {"username": "arjunReddy",    "password": "ENG123",   "role": "Engineer",  "email": "arjun.reddy@threatops.local"},
        {"username": "vikramDesai",   "password": "ENG123",   "role": "Engineer",  "email": "vikram.desai@threatops.local"},
        # Responders
        {"username": "kavyaIyer",     "password": "RESP123",  "role": "Responder", "email": "kavya.iyer@threatops.local"},
        {"username": "sanjayRao",     "password": "RESP123",  "role": "Responder", "email": "sanjay.rao@threatops.local"},
        # Hunter
        {"username": "ananyaNair",    "password": "HUNT123",  "role": "Hunter",    "email": "ananya.nair@threatops.local"},
    ]

    db = SessionLocal()
    try:
        for user_data in default_users:
            existing_user = db.query(User).filter(
                func.lower(User.username) == user_data["username"].lower()
            ).first()
            if existing_user:
                # Keep demo credentials valid while avoiding unnecessary rehashes on each boot.
                if not _verify_password(existing_user.password_hash, user_data["password"]):
                    existing_user.password_hash = hash_password(user_data["password"])
                existing_user.is_active = True
                continue

            db.add(
                User(
                    username=user_data["username"],
                    password_hash=hash_password(user_data["password"]),
                    role=user_data["role"],
                    email=user_data["email"],
                    is_active=True,
                )
            )

        db.commit()
    except Exception as e:
        db.rollback()
        logger.error(f"Default user seeding failed: {e}")
        raise
    finally:
        db.close()


def hash_password(password):
    """Hash password with Werkzeug's adaptive KDF."""
    return generate_password_hash(password)


def login_required(f):
    """Decorator to require login for routes."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login to access this page.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    """Decorator to require admin role."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login to access this page.', 'danger')
            return redirect(url_for('login'))
        if session.get('role') != 'Admin':
            flash('Admin privileges required.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function


def manager_or_admin_required(f):
    """Decorator to require manager or admin role."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login to access this page.', 'danger')
            return redirect(url_for('login'))
        if session.get('role') not in ['Admin', 'Manager']:
            flash('Manager or Admin privileges required.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function


def log_audit(user_id, action_type, action_details, ip_address=None, status='Success'):
    """Log user actions to audit trail."""
    try:
        db = SessionLocal()
        audit = AuditLog(
            user_id=user_id,
            action_type=action_type,
            action_details=action_details,
            ip_address=ip_address or request.remote_addr,
            status=status
        )
        db.add(audit)
        db.commit()
        db.close()
    except Exception as e:
        logger.error(f"Audit logging failed: {e}")


def format_indian_currency(value):
    """Format number as Indian currency with simplified notation."""
    if value is None:
        return "₹0.00"
    
    try:
        num = abs(float(value))
        is_negative = float(value) < 0
        
        # Simplified formatting with abbreviations
        if num >= 10000000:  # Crores
            formatted = f"₹{num/10000000:.2f} Cr"
        elif num >= 100000:  # Lakhs
            formatted = f"₹{num/100000:.2f} L"
        elif num >= 1000:  # Thousands
            formatted = f"₹{num/1000:.2f} K"
        else:
            formatted = f"₹{num:,.2f}"
        
        return f"-{formatted}" if is_negative else formatted
    except (ValueError, TypeError):
        return "₹0.00"


# Register the filter with Jinja2
app.jinja_env.filters['indian_currency'] = format_indian_currency


@app.route("/health")
def health():
    """Lightweight liveness check for classroom demos and deployment probes."""
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return jsonify({"status": "ok", "database": "connected"})
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return jsonify({"status": "error", "database": "unavailable"}), 503


# ================================================================
# AUTHENTICATION ROUTES
# ================================================================

@app.route("/")
def index():
    """Landing page."""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route("/login", methods=["GET", "POST"])
def login():
    """User login page."""
    if request.method == "GET":
        return render_template("login.html")
    
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()
    
    if not username or not password:
        flash("Username and password are required.", "danger")
        return render_template("login.html")
    
    db = SessionLocal()
    try:
        user = db.query(User).filter(
            func.lower(User.username) == username.lower(),
            User.is_active == True
        ).first()
        
        if user and _verify_password(user.password_hash, password):
            if _is_legacy_sha256_hash(user.password_hash):
                user.password_hash = hash_password(password)
            # Update last login
            user.last_login = datetime.now()
            db.commit()
            
            # Set session
            session['user_id'] = user.user_id
            session['username'] = user.username
            session['role'] = user.role
            session['_csrf_token'] = session.get('_csrf_token') or secrets.token_urlsafe(32)
            
            # Log successful login
            log_audit(user.user_id, 'LOGIN', f'User {username} logged in successfully')
            
            flash(f'Welcome, {user.username}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            # Log failed login attempt
            log_audit(None, 'LOGIN', f'Failed login attempt for username: {username}', status='Failure')
            flash('Invalid username or password.', 'danger')
            return render_template("login.html")
    except Exception as e:
        logger.error(f"Login error: {e}")
        flash("An error occurred during login.", "danger")
        return render_template("login.html")
    finally:
        db.close()



@app.route("/logout")
@login_required
def logout():
    """User logout."""
    user_id = session.get('user_id')
    username = session.get('username')
    
    # Log logout
    log_audit(user_id, 'LOGOUT', f'User {username} logged out')
    
    session.clear()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('login'))


# ================================================================
# DASHBOARD ROUTES
# ================================================================

@app.route("/dashboard")
@login_required
def dashboard():
    """Main dashboard with threat intelligence."""
    db = SessionLocal()
    try:
        # Use the THREAT_INTELLIGENCE_DASHBOARD view
        query = text("""
            SELECT * FROM THREAT_INTELLIGENCE_DASHBOARD 
            LIMIT 100
        """)
        result = db.execute(query)
        logs = [dict(row._mapping) for row in result]
        
        # Get summary statistics using aggregations
        stats_query = text("""
            SELECT 
                COUNT(DISTINCT rl.log_id) AS total_logs,
                COUNT(DISTINCT CASE WHEN rl.severity = 'Critical' THEN rl.log_id END) AS critical_logs,
                COUNT(DISTINCT CASE WHEN rl.severity = 'High' THEN rl.log_id END) AS high_logs,
                COUNT(DISTINCT CASE WHEN rl.severity = 'Low' THEN rl.log_id END) AS low_logs,
                COUNT(DISTINCT tc.correlation_id) AS total_correlations,
                COUNT(DISTINCT a.alert_id) AS total_alerts,
                COUNT(DISTINCT CASE WHEN a.status = 'Open' THEN a.alert_id END) AS open_alerts
            FROM RAW_LOGS rl
            LEFT JOIN THREAT_CORRELATION tc ON rl.log_id = tc.log_id
            LEFT JOIN ALERTS a ON tc.correlation_id = a.correlation_id
        """)
        stats_result = db.execute(stats_query).first()
        stats = dict(stats_result._mapping) if stats_result else {}
        
        db.close()
        return render_template("dashboard.html", logs=logs, stats=stats)
    except Exception as e:
        logger.error(f"Dashboard error: {e}")
        db.close()
        flash("Error loading dashboard.", "danger")
        return render_template("dashboard.html", logs=[], stats={})


@app.route("/analytics")
@login_required
def analytics():
    """Advanced analytics with complex SQL queries."""
    db = SessionLocal()
    try:
        # QUERY 1: Severity Distribution with GROUP BY and HAVING
        severity_dist = text("""
            SELECT 
                severity,
                COUNT(*) AS count,
                ROUND(COUNT(*) * 100.0 / (SELECT COUNT(*) FROM RAW_LOGS), 2) AS percentage
            FROM RAW_LOGS
            GROUP BY severity
            HAVING COUNT(*) > 0
            ORDER BY count DESC
        """)
        severity_data = [dict(row._mapping) for row in db.execute(severity_dist)]
        
        # QUERY 2: Technique Distribution with JOIN
        technique_dist = text("""
            SELECT 
                mat.technique_name,
                mat.tactic,
                COUNT(tc.correlation_id) AS occurrences,
                mat.severity
            FROM MITRE_ATTACK_TECHNIQUES mat
            LEFT JOIN THREAT_CORRELATION tc ON mat.technique_id = tc.technique_id
            GROUP BY mat.technique_id, mat.technique_name, mat.tactic, mat.severity
            HAVING COUNT(tc.correlation_id) > 0
            ORDER BY occurrences DESC
            LIMIT 10
        """)
        technique_data = [dict(row._mapping) for row in db.execute(technique_dist)]
        
        # QUERY 3: User Activity with Subquery
        user_activity = text("""
            SELECT * FROM USER_ACTIVITY_SUMMARY
            ORDER BY total_actions DESC
        """)
        user_data = [dict(row._mapping) for row in db.execute(user_activity)]
        
        # QUERY 4: Mitigation Cost Summary with Aggregation
        cost_summary = text("""
            SELECT 
                mdc.category,
                COUNT(DISTINCT mdc.countermeasure_id) AS countermeasure_count,
                SUM(mdc.implementation_cost) AS total_cost,
                AVG(mdc.implementation_cost) AS avg_cost,
                mdc.effectiveness_rating
            FROM MITRE_DEFEND_COUNTERMEASURES mdc
            LEFT JOIN THREAT_CORRELATION tc ON mdc.countermeasure_id = tc.countermeasure_id
            GROUP BY mdc.category, mdc.effectiveness_rating
            HAVING SUM(mdc.implementation_cost) > 0
            ORDER BY total_cost DESC
        """)
        cost_data = [dict(row._mapping) for row in db.execute(cost_summary)]
        
        # QUERY 5: Alert Status Distribution
        alert_status = text("""
            SELECT 
                status,
                severity,
                COUNT(*) AS count
            FROM ALERTS
            GROUP BY status, severity
            ORDER BY count DESC
        """)
        alert_data = [dict(row._mapping) for row in db.execute(alert_status)]
        
        db.close()
        return render_template("analytics.html",
                             severity_data=severity_data,
                             technique_data=technique_data,
                             user_data=user_data,
                             cost_data=cost_data,
                             alert_data=alert_data)
    except Exception as e:
        logger.error(f"Analytics error: {e}")
        db.close()
        flash("Error loading analytics.", "danger")
        return render_template("analytics.html")


# ================================================================
# VISUALIZATION ROUTES
# ================================================================

@app.route("/visualize")
@login_required
def visualize():
    """Render visualization page."""
    return render_template("visualize.html")


@app.route("/chart_data")
@login_required
def chart_data():
    """Return data for chart visualization."""
    field = request.args.get("field", "severity")
    
    db = SessionLocal()
    try:
        if field == "severity":
            query = text("""
                SELECT severity AS label, COUNT(*) AS count
                FROM RAW_LOGS
                GROUP BY severity
                ORDER BY count DESC
            """)
        elif field == "protocol":
            query = text("""
                SELECT protocol AS label, COUNT(*) AS count
                FROM RAW_LOGS
                GROUP BY protocol
                ORDER BY count DESC
                LIMIT 10
            """)
        elif field == "technique":
            query = text("""
                SELECT mat.technique_name AS label, COUNT(tc.correlation_id) AS count
                FROM MITRE_ATTACK_TECHNIQUES mat
                LEFT JOIN THREAT_CORRELATION tc ON mat.technique_id = tc.technique_id
                GROUP BY mat.technique_name
                HAVING COUNT(tc.correlation_id) > 0
                ORDER BY count DESC
                LIMIT 10
            """)
        elif field == "alert_type":
            query = text("""
                SELECT alert_type AS label, COUNT(*) AS count
                FROM ALERTS
                GROUP BY alert_type
                ORDER BY count DESC
            """)
        else:
            db.close()
            return jsonify({"error": "Invalid field"}), 400
        
        result = db.execute(query)
        data = [dict(row._mapping) for row in result]
        
        labels = [row['label'] for row in data]
        counts = [int(row['count']) for row in data]
        
        db.close()
        return jsonify({"labels": labels, "counts": counts})
    except Exception as e:
        logger.error(f"Chart data error: {e}")
        db.close()
        return jsonify({"error": str(e)}), 500


# ================================================================
# SQL EXECUTION PANEL
# ================================================================

@app.route("/sql_panel")
@login_required
def sql_panel():
    """SQL query execution panel."""
    return render_template("sql_panel.html")


@app.route("/run_query", methods=["POST"])
@login_required
def run_query():
    """Execute SQL query based on user role."""
    data = request.get_json(silent=True) or {}
    query = (data.get("query") or "").strip()
    
    if not query:
        return jsonify({"error": "Query cannot be empty."}), 400
    
    user_id = session.get('user_id')
    role = session.get('role')

    validation_error = _validate_query_permissions(role, query)
    if validation_error:
        return jsonify({"error": validation_error}), 403
    
    db = SessionLocal()
    try:
        result = db.execute(text(query))
        
        # Check if query returns results
        if result.returns_rows:
            columns = list(result.keys())
            rows = [dict(row._mapping) for row in result.fetchall()]
        else:
            columns = []
            rows = []
            db.commit()  # Commit DML/DDL operations
        
        # Log query execution
        log_audit(user_id, 'QUERY_EXECUTION', f'Executed: {query[:200]}...')
        
        db.close()
        return jsonify({
            "columns": columns,
            "rows": rows,
            "message": f"Query executed successfully. {len(rows)} rows returned."
        })
        
    except Exception as e:
        db.rollback()
        db.close()
        logger.error(f"Query execution error: {e}")
        
        # Log failed query
        log_audit(user_id, 'QUERY_EXECUTION', f'Failed query: {query[:200]}...', status='Failure')
        
        return jsonify({"error": f"Query failed: {str(e)}"}), 400


# ================================================================
# ADMIN ROUTES
# ================================================================

@app.route("/admin/users")
@admin_required
def admin_users():
    """User management page (Admin only)."""
    db = SessionLocal()
    try:
        users = db.query(User).all()
        db.close()
        return render_template("admin_users.html", users=users)
    except Exception as e:
        logger.error(f"Admin users error: {e}")
        db.close()
        flash("Error loading users.", "danger")
        return redirect(url_for('dashboard'))


@app.route("/admin/change_role", methods=["POST"])
@admin_required
def change_user_role():
    """Change user role (Admin only)."""
    data = request.get_json(silent=True) or {}
    user_id = data.get("user_id")
    new_role = data.get("new_role")
    
    if not user_id or not new_role:
        return jsonify({"error": "Missing user_id or new_role"}), 400
    
    # Validate role
    if new_role not in VALID_ROLES:
        return jsonify({"error": "Invalid role"}), 400
    
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.user_id == user_id).first()
        if not user:
            db.close()
            return jsonify({"error": "User not found"}), 404
        
        old_role = user.role
        user.role = new_role
        db.commit()
        
        # Log the role change
        log_audit(
            session.get('user_id'),
            'USER_MANAGEMENT',
            f"Changed role for user '{user.username}' from {old_role} to {new_role}",
            status='Success'
        )
        
        db.close()
        return jsonify({"message": f"Role changed successfully to {new_role}"})
    except Exception as e:
        db.rollback()
        db.close()
        logger.error(f"Change role error: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/admin/toggle_status", methods=["POST"])
@admin_required
def toggle_user_status():
    """Activate/deactivate user (Admin only)."""
    data = request.get_json(silent=True) or {}
    user_id = data.get("user_id")
    is_active = data.get("is_active")
    
    if not user_id or is_active is None:
        return jsonify({"error": "Missing user_id or is_active"}), 400
    
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.user_id == user_id).first()
        if not user:
            db.close()
            return jsonify({"error": "User not found"}), 404
        
        user.is_active = is_active
        db.commit()
        
        # Log the status change
        status_text = "activated" if is_active else "deactivated"
        log_audit(
            session.get('user_id'),
            'USER_MANAGEMENT',
            f"User '{user.username}' has been {status_text}",
            status='Success'
        )
        
        db.close()
        return jsonify({"message": f"User {status_text} successfully"})
    except Exception as e:
        db.rollback()
        db.close()
        logger.error(f"Toggle status error: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/admin/audit_logs")
@manager_or_admin_required
def admin_audit_logs():
    """View audit logs (Admin/Manager only)."""
    db = SessionLocal()
    try:
        # Get recent audit logs with user information
        query = text("""
            SELECT 
                al.audit_id,
                al.timestamp,
                u.username,
                al.action_type,
                al.action_details,
                al.ip_address,
                al.status
            FROM AUDIT_LOGS al
            LEFT JOIN USERS u ON al.user_id = u.user_id
            ORDER BY al.timestamp DESC
            LIMIT 200
        """)
        logs = [dict(row._mapping) for row in db.execute(query)]
        db.close()
        return render_template("audit_logs.html", logs=logs)
    except Exception as e:
        logger.error(f"Audit logs error: {e}")
        db.close()
        flash("Error loading audit logs.", "danger")
        return redirect(url_for('dashboard'))


# ================================================================
# ALERTS MANAGEMENT
# ================================================================

@app.route("/alerts")
@login_required
def alerts():
    """View and manage alerts."""
    db = SessionLocal()
    try:
        # Complex query joining multiple tables
        query = text("""
            SELECT 
                a.alert_id,
                a.alert_type,
                a.severity,
                a.status,
                a.created_at,
                a.description,
                u.role AS assigned_to_role,
                mat.technique_name,
                rl.source_ip,
                rl.destination_ip
            FROM ALERTS a
            JOIN THREAT_CORRELATION tc ON a.correlation_id = tc.correlation_id
            JOIN RAW_LOGS rl ON tc.log_id = rl.log_id
            JOIN MITRE_ATTACK_TECHNIQUES mat ON tc.technique_id = mat.technique_id
            LEFT JOIN USERS u ON a.assigned_to = u.user_id
            ORDER BY a.created_at DESC
            LIMIT 100
        """)
        alerts_data = [dict(row._mapping) for row in db.execute(query)]
        db.close()
        return render_template("alerts.html", alerts=alerts_data)
    except Exception as e:
        logger.error(f"Alerts error: {e}")
        db.close()
        flash("Error loading alerts.", "danger")
        return render_template("alerts.html", alerts=[])


@app.route("/alerts/update_status", methods=["POST"])
@login_required
def update_alert_status():
    """Update alert status."""
    data = request.get_json(silent=True) or {}
    alert_id = data.get("alert_id")
    new_status = data.get("status")
    
    if not alert_id or not new_status:
        return jsonify({"error": "Missing alert_id or status"}), 400
    if new_status not in ALLOWED_ALERT_STATUSES:
        return jsonify({"error": "Invalid alert status"}), 400
    
    db = SessionLocal()
    try:
        alert = db.query(Alert).filter(Alert.alert_id == alert_id).first()
        if not alert:
            db.close()
            return jsonify({"error": "Alert not found"}), 404
        
        alert.status = new_status
        if new_status in ['Resolved', 'False Positive']:
            alert.resolved_at = datetime.now()
        
        db.commit()
        db.close()
        
        # Log the update
        log_audit(session.get('user_id'), 'DATA_MODIFICATION', 
                 f'Updated alert {alert_id} status to {new_status}')
        
        return jsonify({"message": "Alert status updated successfully"})
    except Exception as e:
        db.rollback()
        db.close()
        logger.error(f"Update alert error: {e}")
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    init_db()
    app.run(debug=True, host="0.0.0.0", port=5000)
