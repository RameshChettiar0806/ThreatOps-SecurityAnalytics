# ThreatOps – Web-Based SIEM Platform

ThreatOps is a beginner-friendly SIEM-like platform built with Flask, SQLAlchemy ORM, and MySQL. It supports loading simulated datasets, uploading custom CSV files, running safe SQL queries, and visualizing logs mapped to MITRE ATT&CK and MITRE D3FEND frameworks.

## Features

- ✅ Load and manage security logs from CSV files
- ✅ Interactive dashboard with log exploration
- ✅ Safe SQL query execution with injection protection
- ✅ Real-time data visualization with Chart.js
- ✅ MITRE ATT&CK and D3FEND threat mapping
- ✅ Sample dataset for quick testing

## Project Structure

```
threatops/
├── app.py                 # Flask application and routes
├── models.py              # SQLAlchemy ORM models
├── database.py            # Database configuration
├── requirements.txt       # Python dependencies
├── schema.sql             # Database schema
├── sample_logs.csv        # Sample security logs
├── templates/             # HTML templates
│   ├── index.html        # Landing page
│   ├── dashboard.html    # Log dashboard
│   ├── upload.html       # CSV upload interface
│   ├── visualize.html    # Chart visualization
│   └── sql_panel.html    # SQL query interface
└── static/               # Static assets
    ├── style.css         # Stylesheet
    └── script.js         # Frontend JavaScript
```

## Prerequisites

- Python 3.8+
- MySQL 5.7+
- pip (Python package manager)

## Installation & Setup

### 1. Clone the Repository

```bash
git clone <repository-url>
cd ThreatOps-SecurityAnalytics
```

### 2. Create Python Virtual Environment

A virtual environment isolates project dependencies and prevents conflicts with other Python projects.

**Windows:**
```bash
python -m venv venv
venv\Scripts\activate
pip install -r threatops/requirements.txt
```

**Linux/Mac:**
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r threatops/requirements.txt
```

**Deactivate (when done):**
```bash
deactivate
```

### 3. Configure MySQL Database

1. Ensure MySQL is running on your system
2. Create the database and tables:
   ```bash
   mysql -u root -p < threatops/schema.sql
   ```
3. Update database credentials in `threatops/database.py` if needed:
   - Default: `mysql+mysqlconnector://root:password@localhost:3306/threatops`
   - Override with environment variable:
     ```bash
     export DATABASE_URL="mysql+mysqlconnector://username:password@localhost:3306/threatops"
     ```

### 4. Run the Application

```bash
cd threatops
python app.py
```

Open your browser and navigate to: **http://localhost:5000**

## Usage Guide

### Loading Sample Dataset

1. Navigate to the **Home** or **Dashboard** page
2. Click **"Load Sample Dataset"**
3. Sample logs from `sample_logs.csv` will be inserted into the database

### Uploading Custom CSV Files

1. Go to **Upload CSV** page
2. Select your CSV file with the following required headers:
   - `timestamp` (format: YYYY-MM-DD HH:MM)
   - `source_ip`
   - `destination_ip`
   - `protocol` (TCP, UDP, ICMP, etc.)
   - `event_description`
   - `attack_type` (Brute Force, Port Scan, DoS, Malware)
3. The application validates headers and displays confirmation

### Exploring Logs

1. Open the **Dashboard** page
2. View all security logs in a sortable table
3. Filter by attack type, protocol, or IP addresses

### Running Safe SQL Queries

1. Open **SQL Panel**
2. Enter a SELECT query, for example:
   ```sql
   SELECT * FROM logs WHERE protocol='TCP' LIMIT 10
   ```
3. Click **Execute Query** to see results

**Security Notes:**
- Only SELECT queries are allowed
- Dangerous tokens (`;`, `--`, `/*`, `*/`) are blocked
- Keywords like INSERT, UPDATE, DELETE, DROP are forbidden

### Generating Visualizations

1. Go to **Visualize** page
2. Select a field to analyze:
   - Attack Type
   - Protocol
   - Source IP
   - MITRE ATT&CK ID
3. Choose a chart type:
   - Bar Chart
   - Pie Chart
   - Line Chart
   - Doughnut Chart
   - Stacked Bar Chart
4. Click **Generate Chart** to view the visualization

## MITRE Threat Framework Mapping

The application maps detected attacks to MITRE ATT&CK techniques and D3FEND countermeasures:

| Attack Type | MITRE ID | MITRE Technique | D3FEND Strategy |
|---|---|---|---|
| Brute Force | T1110 | Brute Force | Credential Hardening |
| Port Scan | T1046 | Network Service Scanning | Network Intrusion Prevention |
| DoS | T1499 | Endpoint Denial of Service | Traffic Filtering |
| Malware | T1059 | Command and Scripting Interpreter | Execution Prevention |

## Troubleshooting

### MySQL Connection Error
- Ensure MySQL is running: `sudo service mysql status`
- Verify credentials in `database.py`
- Check that the database exists: `mysql -u root -p -e "SHOW DATABASES;"`

### Port Already in Use
- Change the port in `app.py`: `app.run(host="0.0.0.0", port=5001)`
- Or kill the existing process using port 5000

### CSV Upload Fails
- Verify all required headers are present
- Ensure timestamps are in `YYYY-MM-DD HH:MM` format
- Check that attack types match the defined categories

## Project Technologies

- **Backend:** Flask (Python web framework)
- **ORM:** SQLAlchemy
- **Database:** MySQL
- **Frontend:** HTML5, CSS3, JavaScript
- **Visualization:** Chart.js
- **Frameworks:** MITRE ATT&CK, MITRE D3FEND

## License

MIT License – Feel free to use, modify, and distribute this project.
