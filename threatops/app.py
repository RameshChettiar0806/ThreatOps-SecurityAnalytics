"""Flask application for ThreatOps SIEM."""

import csv
import re
from datetime import datetime
from io import TextIOWrapper
from pathlib import Path

from flask import Flask, jsonify, render_template, request
from sqlalchemy import func, text

from database import Base, SessionLocal, engine
from models import Log


app = Flask(__name__)

SAMPLE_CSV_PATH = Path(__file__).parent / "sample_logs.csv"

REQUIRED_HEADERS = [
    "timestamp",
    "source_ip",
    "destination_ip",
    "protocol",
    "event_description",
    "attack_type",
]

MITRE_MAP = {
    "Brute Force": ("T1110", "Brute Force", "Credential Hardening"),
    "Port Scan": ("T1046", "Network Service Scanning", "Network Intrusion Prevention"),
    "DoS": ("T1499", "Endpoint Denial of Service", "Traffic Filtering"),
    "Malware": ("T1059", "Command and Scripting Interpreter", "Execution Prevention"),
}


def init_db():
    """Create database tables if they do not exist."""
    Base.metadata.create_all(bind=engine)


@app.route("/")
def index():
    """Render the landing page."""
    return render_template("index.html")


@app.route("/dashboard")
def dashboard():
    """Render the main dashboard with log data."""
    session = SessionLocal()
    logs = session.query(Log).order_by(Log.timestamp.desc()).all()
    session.close()
    return render_template("dashboard.html", logs=logs)


@app.route("/upload", methods=["GET", "POST"])
def upload():
    """Upload and parse a custom CSV file."""
    if request.method == "GET":
        return render_template("upload.html")

    uploaded_file = request.files.get("file")
    if not uploaded_file or not uploaded_file.filename:
        return render_template("upload.html", error="Please select a CSV file to upload.")

    if not uploaded_file.filename.lower().endswith(".csv"):
        return render_template("upload.html", error="Only CSV files are supported.")

    try:
        wrapper = TextIOWrapper(uploaded_file.stream, encoding="utf-8")
        reader = csv.DictReader(wrapper)
        headers = reader.fieldnames or []
        if any(header not in headers for header in REQUIRED_HEADERS):
            return render_template(
                "upload.html",
                error=(
                    "Invalid CSV headers. Required headers: "
                    f"{', '.join(REQUIRED_HEADERS)}."
                ),
            )

        session = SessionLocal()
        for row in reader:
            log = build_log_from_row(row)
            session.add(log)
        session.commit()
        session.close()
    except Exception as exc:  # pylint: disable=broad-except
        return render_template("upload.html", error=f"Upload failed: {exc}")

    return render_template("upload.html", success="CSV uploaded successfully!")


@app.route("/load_sample_dataset", methods=["POST"])
def load_sample_dataset():
    """Load sample logs from the bundled CSV file."""
    if not SAMPLE_CSV_PATH.exists():
        return jsonify({"message": "Sample dataset not found."}), 404

    session = SessionLocal()
    with SAMPLE_CSV_PATH.open("r", encoding="utf-8") as sample_file:
        reader = csv.DictReader(sample_file)
        for row in reader:
            log = build_log_from_row(row)
            session.add(log)
    session.commit()
    session.close()

    return jsonify({"message": "Sample dataset loaded successfully."})


@app.route("/visualize")
def visualize():
    """Render the visualization page."""
    return render_template("visualize.html")


@app.route("/chart_data")
def chart_data():
    """Return grouped counts for a selected field."""
    field = request.args.get("field", "attack_type")
    allowed_fields = {
        "attack_type": Log.attack_type,
        "protocol": Log.protocol,
        "source_ip": Log.source_ip,
        "mitre_attack_id": Log.mitre_attack_id,
    }

    if field not in allowed_fields:
        return jsonify({"error": "Invalid field."}), 400

    session = SessionLocal()
    results = (
        session.query(allowed_fields[field], func.count(Log.id))
        .group_by(allowed_fields[field])
        .all()
    )
    session.close()

    labels = [row[0] for row in results]
    counts = [row[1] for row in results]
    return jsonify({"labels": labels, "counts": counts})


@app.route("/sql_panel")
def sql_panel():
    """Render the SQL query panel page."""
    return render_template("sql_panel.html")


@app.route("/run_query", methods=["POST"])
def run_query():
    """Execute a safe SELECT query and return results."""
    data = request.get_json(silent=True) or {}
    query = (data.get("query") or "").strip()

    validation_error = validate_select_query(query)
    if validation_error:
        return jsonify({"error": validation_error}), 400

    try:
        session = SessionLocal()
        result = session.execute(text(query))
        columns = result.keys()
        rows = [dict(zip(columns, row)) for row in result.fetchall()]
        session.close()
    except Exception as exc:  # pylint: disable=broad-except
        return jsonify({"error": f"Query failed: {exc}"}), 400

    return jsonify({"columns": list(columns), "rows": rows})


def build_log_from_row(row):
    """Convert a CSV row to a Log instance with MITRE mappings."""
    attack_type = row.get("attack_type", "").strip()
    mitre_attack_id, mitre_attack_name, d3fend = MITRE_MAP.get(
        attack_type,
        ("T0000", "Unknown", "Not Mapped"),
    )

    return Log(
        timestamp=parse_timestamp(row.get("timestamp", "")),
        source_ip=row.get("source_ip", "Unknown"),
        destination_ip=row.get("destination_ip", "Unknown"),
        protocol=row.get("protocol", "Unknown"),
        event_description=row.get("event_description", ""),
        attack_type=attack_type or "Unknown",
        mitre_attack_id=mitre_attack_id,
        mitre_attack_name=mitre_attack_name,
        mitre_d3fend_technique=d3fend,
    )


def parse_timestamp(raw_timestamp):
    """Parse timestamp strings into datetime objects."""
    try:
        return datetime.strptime(raw_timestamp.strip(), "%Y-%m-%d %H:%M")
    except ValueError:
        return datetime.utcnow()


def validate_select_query(query):
    """Validate incoming SQL queries to block unsafe statements."""
    if not query:
        return "Query cannot be empty."

    if any(token in query for token in [";", "--", "/*", "*/"]):
        return "Query contains disallowed tokens."

    pattern = re.compile(
        r"^select\s+(distinct\s+)?[\w\s,.*]+\s+from\s+logs"
        r"(\s+where\s+[\w\s=><'\".%()-]+)?"
        r"(\s+group\s+by\s+[\w\s,]+)?"
        r"(\s+having\s+[\w\s=><'\".%()-]+)?"
        r"(\s+order\s+by\s+[\w\s,]+)?"
        r"(\s+limit\s+\d+)?$",
        re.IGNORECASE,
    )

    if not pattern.match(query.strip()):
        return (
            "Only SELECT queries on the logs table are allowed. "
            "Supported clauses: WHERE, LIKE, ORDER BY, GROUP BY, HAVING, DISTINCT, LIMIT."
        )

    forbidden_keywords = [
        "insert",
        "update",
        "delete",
        "drop",
        "alter",
        "create",
        "join",
        "union",
    ]
    lowered_query = query.lower()
    if any(keyword in lowered_query for keyword in forbidden_keywords):
        return "Query contains disallowed keywords."

    return None


if __name__ == "__main__":
    init_db()
    app.run(debug=True, host="0.0.0.0", port=5000)
