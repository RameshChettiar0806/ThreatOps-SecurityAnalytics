# ThreatOps Security Analytics Platform

*A comprehensive SIEM platform with MITRE ATT&CK integration, role-based access control, and advanced SQL features*

---

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- MySQL 5.7+ or 8.0+
- pip

### Setup Steps

1. **Clone Repository**
   ```bash
   git clone <repository-url>
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

4. **Run Application**
   ```bash
   cd threatops
   python app.py
   ```

**Access:** http://localhost:5000/login

### Default Credentials

| Username | Password | Role | Access |
|----------|----------|------|--------|
| admin | admin123 | Admin | Full access (DDL/DML/DQL/TCL/DCL) |
| analyst | analyst123 | Analyst | SELECT only, CSV upload |

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
- CSV log upload with transaction control
- Session-based authentication
- SQL injection prevention via ORM
- Role-based route protection
- Complete audit logging

## 📝 License

MIT License - See [LICENSE](LICENSE)

---

**Built for DBMS Lab | SRM Institute of Science and Technology**
