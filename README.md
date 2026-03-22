# ThreatOps Security Analytics Platform

*A comprehensive SIEM platform with MITRE ATT&CK integration, role-based access control, and advanced SQL features*

---

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- MySQL 5.7+ or 8.0+ (for local development)
- pip

### Setup Steps

1. **Clone Repository**
   ```bash
   git clone https://github.com/RameshChettiar0806/ThreatOps-SecurityAnalytics.git
   cd ThreatOps-SecurityAnalytics
   ```

2. **Setup Environment**
   ```bash
   # Windows
   python -m venv venv
   venv\Scripts\activate
   pip install -r threatops/requirements.txt
   
   # Linux/Mac
   python3 -m venv venv
   source venv/bin/activate
   pip install -r threatops/requirements.txt
   ```

3. **Initialize Database**
   ```bash
   mysql -u root -p < threatops/schema.sql
   ```
   
   Configure your `.env` file:
   ```env
   DATABASE_URL=mysql+mysqlconnector://root:root@localhost:3306/threatops
   SECRET_KEY=dev-secret-key-change-in-production
   ```

4. **Run Application** (Easy Mode! 🎯)
   
   **Option A - PowerShell:**
   ```powershell
   .\run.ps1
   ```
   
   **Option B - Command Prompt:**
   ```cmd
   run.bat
   ```
   
   **Option C - Manual:**
   ```bash
   venv\Scripts\activate
   set PYTHONPATH=%CD%
   python threatops\app.py
   ```

**Access:** http://127.0.0.1:5000

### Default Credentials

| Username | Password | Role | Access |
|----------|----------|------|--------|
| admin | admin123 | Admin | Full access (DDL/DML/DQL/TCL/DCL) |
| analyst | analyst123 | Analyst | SELECT only |

---

## 📖 Documentation

For complete documentation, see **[DOCS.md](DOCS.md)**

- Installation & Setup
- User Guide
- Role Management
- Database Schema
- API Reference
- Troubleshooting

---

## 🔑 Key Features

- Role-based access control (6 roles with unique colors)
- MITRE ATT&CK/D3FEND integration
- Advanced SQL (views, procedures, triggers)
- Real-time threat correlation
- Interactive analytics & visualizations
- Session-based authentication
- SQL injection prevention via ORM
- Role-based route protection
- Complete audit logging

## 📝 License

MIT License - See [LICENSE](LICENSE)

---

**Built for DBMS Lab | SRM Institute of Science and Technology**
