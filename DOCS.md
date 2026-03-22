# ThreatOps - Complete Documentation

## Table of Contents
1. [Quick Start](#quick-start)
2. [Features](#features)
3. [Installation](#installation)
4. [Usage Guide](#usage-guide)
5. [Role Management](#role-management)
6. [Database Schema](#database-schema)
7. [API Reference](#api-reference)
8. [Troubleshooting](#troubleshooting)

---

## Quick Start

### Prerequisites
- Python 3.8+
- MySQL 5.7+ or 8.0+
- pip (Python package manager)

### Setup (4 Steps)

```bash
# 1. Clone and navigate
git clone https://github.com/RameshChettiar0806/ThreatOps-SecurityAnalytics.git
cd ThreatOps-SecurityAnalytics

# 2. Setup Python environment
python -m venv venv
# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate

pip install -r threatops/requirements.txt

# 3. Initialize database
mysql -u root -p < threatops/schema.sql
# Enter your MySQL root password when prompted

# 4. Run application
cd threatops
python app.py
```

**Access:** http://localhost:5000/login

### Default Credentials

| Username | Password | Role | Access Level |
|----------|----------|------|--------------|
| **rajesh_kumar** | **ADM123** | Admin | Full system access, user management |
| **deepak_verma** | **ADM123** | Admin | Full system access, user management |
| **amit_patel** | **ANLST123** | Analyst | Read queries, alerts |
| **arjun_reddy** | **ENG123** | Engineer | System configuration, full queries |

> ⚠️ **Security Note:** Change default passwords in production! See [User Management](#user-management) section.

---

## Features

### Core Capabilities
- ✅ **Authentication & RBAC** - 6 roles with granular permissions
- ✅ **MITRE Integration** - ATT&CK & D3FEND frameworks
- ✅ **Auto-Correlation** - Stored procedures for threat mapping
- ✅ **Advanced SQL** - Views, procedures, triggers, complex queries
- ✅ **Analytics Dashboard** - 5 complex queries with visualizations
- ✅ **Alert Management** - Workflow with status tracking
- ✅ **Audit Logging** - Complete activity trail
- ✅ **SQL Panel** - Role-validated query execution
- ✅ **Data Visualization** - Interactive Chart.js charts

### Key Differentiators
- **Transaction Control** - ROLLBACK/COMMIT for data integrity
- **Stored Procedures** - Database-side threat correlation
- **Database Triggers** - Automatic audit logging
- **Indian Localization** - Rupee formatting, Indian names/data

---

## Installation

### Detailed Setup Instructions

#### 1. Install Prerequisites

**Python 3.8+**
```bash
# Windows: Download from python.org
# Linux: 
sudo apt-get install python3 python3-pip python3-venv
# Mac:
brew install python@3.11
```

**MySQL 8.0**
```bash
# Windows: Download MySQL Installer from mysql.com
# Linux:
sudo apt-get install mysql-server
sudo systemctl start mysql
# Mac:
brew install mysql
brew services start mysql
```

#### 2. Clone Repository
```bash
git clone https://github.com/RameshChettiar0806/ThreatOps-SecurityAnalytics.git
cd ThreatOps-SecurityAnalytics
```

#### 3. Create Virtual Environment
```bash
python -m venv venv

# Activate:
# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate
```

#### 4. Install Dependencies
```bash
pip install -r threatops/requirements.txt
```

**Required packages:**
- Flask 3.0.0
- SQLAlchemy 2.0.23
- mysql-connector-python 9.0.0

#### 5. Configure Database

**Edit `threatops/database.py` if needed:**
```python
DATABASE_URL = "mysql+mysqlconnector://root:YOUR_PASSWORD@localhost:3306/threatops"
```

Replace `YOUR_PASSWORD` with your MySQL root password.

#### 6. Initialize Database
```bash
mysql -u root -p < threatops/schema.sql
```

This creates:
- `threatops` database
- 7 tables with sample data
- 2 views for complex queries
- 2 stored procedures
- 2 triggers for audit logging

#### 7. Run Application
```bash
cd threatops
python app.py
```

**Success!** App runs on http://localhost:5000

---

## Usage Guide

### 1. Dashboard
**URL:** `/dashboard`

View threat intelligence with real-time statistics:
- Total logs, correlations, alerts
- Recent threats with MITRE mappings
- Multi-table JOIN queries

**SQL Behind the Scenes:**
```sql
SELECT * FROM THREAT_INTELLIGENCE_DASHBOARD LIMIT 100
```

### 2. SQL Panel
**URL:** `/sql_panel`

Execute SQL queries with role-based validation.

**Example Queries:**
```sql
-- View recent logs
SELECT * FROM RAW_LOGS LIMIT 10;

-- Severity distribution
SELECT severity, COUNT(*) AS count 
FROM RAW_LOGS 
GROUP BY severity;

-- Top attack techniques
SELECT technique_name, COUNT(*) as count 
FROM THREAT_CORRELATION tc 
JOIN MITRE_ATTACK_TECHNIQUES mat ON tc.technique_id = mat.technique_id 
GROUP BY technique_name 
ORDER BY count DESC 
LIMIT 5;
```

### 3. Analytics
**URL:** `/analytics`

5 pre-built complex SQL queries with visualizations:

1. **Severity Distribution** - GROUP BY with percentage calculation
2. **Top 10 Attack Techniques** - JOIN + GROUP BY + HAVING
3. **User Activity Summary** - View with aggregations
4. **Mitigation Cost Analysis** - SUM, AVG, COUNT by category
5. **Alert Status Distribution** - Multi-dimensional grouping

### 4. Visualize
**URL:** `/visualize`

Create interactive charts:
- **Chart Types:** Bar, Pie, Line, Stacked Bar
- **Fields:** Severity, Protocol, Alert Type, Attack Technique
- **Library:** Chart.js 4.4

### 5. Alerts
**URL:** `/alerts`

Manage security alerts with workflow:
- **Statuses:** Open → In Progress → Resolved/False Positive
- **Assignment:** Assign to users by role
- **Correlation:** Linked to logs and MITRE techniques
- **Actions:** Update status via dropdown

---

## Role Management

### Role Color Schemes

Each role has a unique color throughout the application:

| Role | Color | Hex | Purpose |
|------|-------|-----|---------|
| **Admin** | Red | `#dc3545` | Full system access |
| **Manager** | Cyan | `#0dcaf0` | SOC management |
| **Analyst** | Teal | `#17a2b8` | Security analysis |
| **Engineer** | Green | `#20c997` | Infrastructure |
| **Responder** | Orange | `#fd7e14` | Incident response |
| **Hunter** | Purple | `#6f42c1` | Threat hunting |

### User Management (Admin Only)
**URL:** `/admin/users`

**Features:**
1. **Change User Role**
   - Click "Change Role" button
   - Select new role from modal dropdown
   - Saves with audit log entry

2. **Activate/Deactivate Users**
   - Toggle user status
   - Prevents login when deactivated
   - Logged to audit trail

**Example: Promote Analyst to Manager**
1. Login as Admin
2. Go to Admin → User Management
3. Find analyst user
4. Click "Change Role"
5. Select "Manager"
6. Save changes

**API Endpoints:**
```javascript
// Change role
POST /admin/change_role
Body: { "user_id": 5, "new_role": "Engineer" }

// Toggle status
POST /admin/toggle_status
Body: { "user_id": 5, "is_active": false }
```

### Audit Logs (Admin/Manager)
**URL:** `/admin/audit_logs`

View system activity trail:
- User actions (LOGIN, LOGOUT, QUERY_EXECUTION)
- Timestamps and IP addresses
- Success/Failure status
- Detailed action descriptions

---

## Database Schema

### Tables (7)

#### 1. USERS
Authentication and role-based access control.
```sql
user_id, username, password_hash, role, email, created_at, last_login, is_active
```

#### 2. RAW_LOGS
Security event data.
```sql
log_id, timestamp, source_ip, destination_ip, protocol, port, 
event_description, severity, created_at
```

#### 3. MITRE_ATTACK_TECHNIQUES
ATT&CK framework mapping.
```sql
technique_id, technique_name, tactic, description, severity
```

#### 4. MITRE_DEFEND_COUNTERMEASURES
D3FEND defensive measures.
```sql
countermeasure_id, countermeasure_name, category, description, 
implementation_cost, effectiveness_rating
```

#### 5. THREAT_CORRELATION
Links logs to MITRE techniques.
```sql
correlation_id, log_id, technique_id, countermeasure_id, 
confidence_score, correlated_at, correlated_by
```

#### 6. ALERTS
Security alerts workflow.
```sql
alert_id, correlation_id, alert_type, severity, status, assigned_to, 
description, created_at, resolved_at
```

#### 7. AUDIT_LOGS
System activity trail.
```sql
audit_id, user_id, action_type, action_details, ip_address, timestamp, status
```

### Views (2)

#### 1. THREAT_INTELLIGENCE_DASHBOARD
Multi-table JOIN for dashboard.
```sql
CREATE VIEW THREAT_INTELLIGENCE_DASHBOARD AS
SELECT rl.*, mat.technique_name, mat.tactic, mdc.countermeasure_name
FROM RAW_LOGS rl
LEFT JOIN THREAT_CORRELATION tc ON rl.log_id = tc.log_id
LEFT JOIN MITRE_ATTACK_TECHNIQUES mat ON tc.technique_id = mat.technique_id
LEFT JOIN MITRE_DEFEND_COUNTERMEASURES mdc ON tc.countermeasure_id = mdc.countermeasure_id;
```

#### 2. USER_ACTIVITY_SUMMARY
User statistics aggregation.
```sql
CREATE VIEW USER_ACTIVITY_SUMMARY AS
SELECT u.*, COUNT(DISTINCT al.audit_id) AS total_actions
FROM USERS u
LEFT JOIN AUDIT_LOGS al ON u.user_id = al.user_id
GROUP BY u.user_id;
```

### Stored Procedures (2)

#### 1. CORRELATE_THREAT
Automatic threat-to-technique mapping.
```sql
CALL CORRELATE_THREAT(log_id, user_id);
```

#### 2. GENERATE_ALERT
Create security alert from correlation.
```sql
CALL GENERATE_ALERT(correlation_id, assigned_to);
```

### Triggers (1)

#### 1. AUDIT_ALERT_CREATION
Logs alert creation automatically.

---

## API Reference

### Authentication

#### POST `/login`
Login with username and password.

**Request:**
```json
{
  "username": "rajesh_kumar",
  "password": "ADM123"
}
```

**Response:**
```json
{
  "message": "Login successful",
  "role": "Admin"
}
```

#### GET `/logout`
Logout current user.

### Data Operations

#### POST `/run_query`
Execute SQL query.

**Request:**
```json
{
  "query": "SELECT * FROM RAW_LOGS LIMIT 10"
}
```

**Response:**
```json
{
  "columns": ["log_id", "timestamp", "source_ip", ...],
  "rows": [...]
}
```

#### GET `/chart_data?field=severity`
Get data for charts.

**Response:**
```json
{
  "labels": ["Critical", "High", "Medium", "Low"],
  "counts": [15, 32, 28, 10]
}
```

### Admin Operations

#### POST `/admin/change_role`
Change user role (Admin only).

**Request:**
```json
{
  "user_id": 5,
  "new_role": "Manager"
}
```

#### POST `/admin/toggle_status`
Activate/deactivate user (Admin only).

**Request:**
```json
{
  "user_id": 5,
  "is_active": false
}
```

#### POST `/update_alert_status`
Update alert status.

**Request:**
```json
{
  "alert_id": 10,
  "status": "Resolved"
}
```

---

## Troubleshooting

### Common Issues

#### 1. Authentication Failed
**Problem:** Cannot login with default credentials.

**Solution:**
```bash
# Verify users exist
mysql -u root -p
USE threatops;
SELECT username, role FROM USERS;
```

#### 2. MySQL Connection Error
**Problem:** `Can't connect to MySQL server`

**Solution:**
```bash
# Windows: Check MySQL service
net start MySQL80

# Linux: Check MySQL status
sudo systemctl status mysql
sudo systemctl start mysql

# Verify database exists
mysql -u root -p -e "SHOW DATABASES LIKE 'threatops';"
```

#### 3. Port Already in Use
**Problem:** `Port 5000 is already in use`

**Solution:**
Edit `threatops/app.py` line ~830:
```python
app.run(debug=True, host="0.0.0.0", port=5001)
```

#### 4. Module Not Found
**Problem:** `ModuleNotFoundError: No module named 'flask'`

**Solution:**
```bash
# Ensure virtual environment is activated
# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate

# Reinstall dependencies
pip install -r threatops/requirements.txt
```

#### 5. SQL Query Denied
**Problem:** "Unauthorized query type" as Analyst.

**Solution:**
Analysts can only run SELECT queries. Login as Admin for full access.

### Database Reset

If you need to reset the database:
```bash
# Drop and recreate
mysql -u root -p -e "DROP DATABASE IF EXISTS threatops;"
mysql -u root -p < threatops/schema.sql
```

### Logs and Debugging

Enable detailed logging in `threatops/app.py`:
```python
logging.basicConfig(level=logging.DEBUG)
```

Check Flask debug output in terminal for error details.

---

## Project Structure

```
ThreatOps-SecurityAnalytics/
├── README.md              # Quick start guide
├── DOCS.md                # This file - complete documentation
├── LICENSE                # MIT License
├── requirements.txt       # Python dependencies
├── .gitignore            # Git exclusions
├── threatops/
│   ├── app.py            # Flask application
│   ├── models.py         # SQLAlchemy ORM models
│   ├── database.py       # Database configuration
│   ├── schema.sql        # Complete SQL schema with data
│   ├── requirements.txt  # Local dependencies
│   ├── static/
│   │   ├── style.css     # Custom styles + role colors
│   │   └── script.js     # Frontend JavaScript
│   └── templates/
│       ├── index.html    # Landing page
│       ├── login.html    # Login form
│       ├── navbar.html   # Navigation bar
│       ├── dashboard.html
│       ├── analytics.html
│       ├── visualize.html
│       ├── alerts.html
│       ├── sql_panel.html
│       ├── admin_users.html
│       └── audit_logs.html
└── api/
    └── index.py          # Vercel serverless API
```

---

## Technology Stack

- **Backend:** Flask 3.0.0, SQLAlchemy 2.0.23
- **Database:** MySQL 8.0
- **Frontend:** Bootstrap 5.3.3, Chart.js 4.4.1
- **Authentication:** Session-based with SHA256 hashing
- **ORM:** SQLAlchemy with declarative models

---

## Security Features

- ✅ **Password Hashing** - SHA256 for all passwords
- ✅ **Session Management** - HTTP-only cookies
- ✅ **SQL Injection Prevention** - Parameterized queries via ORM
- ✅ **Role-Based Access** - Decorator-enforced route protection
- ✅ **Audit Logging** - Complete activity trail
- ✅ **Transaction Control** - ROLLBACK on errors

---

## Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create feature branch
3. Make changes with tests
4. Submit pull request

---

## License

MIT License - See [LICENSE](LICENSE) file

---

## Contact & Support

**Repository:** https://github.com/RameshChettiar0806/ThreatOps-SecurityAnalytics

**Built for:** DBMS Lab | SRM Institute of Science and Technology

---

**Last Updated:** February 15, 2026
