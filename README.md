# ThreatOps Security Analytics Platform

ThreatOps is a classroom SIEM demo built with Flask, SQLAlchemy, Bootstrap, and PostgreSQL. It showcases RBAC, MITRE ATT&CK/D3FEND mappings, audit logging, dashboard analytics, and a role-aware SQL panel.

## Quick Start

### Prerequisites
- Python 3.10+
- PostgreSQL 14+
- pip

### Setup

```bash
git clone https://github.com/RameshChettiar0806/ThreatOps-SecurityAnalytics.git
cd ThreatOps-SecurityAnalytics

python -m venv venv
venv\Scripts\activate

pip install -r requirements.txt
copy .env.example .env
```

Create a PostgreSQL database named `threatops`, then load the schema:

```bash
psql -U postgres -d threatops -f backend/schema_supabase.sql
```

Update `.env` as needed:

```env
DATABASE_URL=postgresql://postgres:postgres@localhost:5432/threatops
SECRET_KEY=change-this-for-your-own-demo-instance
```

Run the app:

```bash
python backend/app.py
```

Open [http://127.0.0.1:5000/login](http://127.0.0.1:5000/login).

## Demo Credentials

These seeded accounts are meant for classroom presentation only:

| Username | Password | Role |
|----------|----------|------|
| rajeshKumar | ADM123 | Admin |
| deepakVerma | ADM123 | Admin |
| priyaSharma | MGR123 | Manager |
| amitPatel | ANLST123 | Analyst |
| snehaSingh | ANLST123 | Analyst |
| rohanGupta | ANLST123 | Analyst |
| meeraKrishnan | ANLST123 | Analyst |
| arjunReddy | ENG123 | Engineer |
| vikramDesai | ENG123 | Engineer |
| kavyaIyer | RESP123 | Responder |
| sanjayRao | RESP123 | Responder |
| ananyaNair | HUNT123 | Hunter |

## Notes

- This repo is optimized for a classroom demo, not for internet-facing production use.
- The SQL panel is intentionally powerful for teaching database concepts, but it still applies role-based restrictions.
- Passwords are now hashed with Werkzeug, authenticated POST routes use CSRF protection, and demo passwords are no longer embedded in the login page.

## Documentation

Full setup and walkthrough: [SETUP.md](</C:/Users/Ramesh/Personal Folders/College/SRM/SEMESTERS/SEMESTER-4/GitHub/ThreatOps-SecurityAnalytics/SETUP.md>)

## License

MIT License. See [LICENSE](</C:/Users/Ramesh/Personal Folders/College/SRM/SEMESTERS/SEMESTER-4/GitHub/ThreatOps-SecurityAnalytics/LICENSE>).
