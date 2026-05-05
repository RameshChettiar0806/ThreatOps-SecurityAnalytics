# ThreatOps Setup Guide

This guide matches the current repository layout. ThreatOps is a classroom demo that runs as a Flask app with PostgreSQL and a server-rendered Bootstrap frontend.

## Stack

- Backend: Flask, SQLAlchemy
- Database: PostgreSQL or Supabase PostgreSQL
- Frontend: Bootstrap, Chart.js
- Deployment adapter: `api/index.py` for Vercel

## Project Layout

```text
ThreatOps-SecurityAnalytics/
├── api/
│   └── index.py
├── backend/
│   ├── app.py
│   ├── database.py
│   ├── models.py
│   └── schema_supabase.sql
├── frontend/
│   ├── static/
│   │   ├── script.js
│   │   └── style.css
│   └── templates/
├── .env.example
├── README.md
├── requirements.txt
└── vercel.json
```

## Local Setup

### 1. Install prerequisites

- Python 3.10+
- PostgreSQL 14+

### 2. Create and activate a virtual environment

```bash
python -m venv venv
venv\Scripts\activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Create `.env`

```bash
copy .env.example .env
```

Recommended local values:

```env
DATABASE_URL=postgresql://postgres:postgres@localhost:5432/threatops
SECRET_KEY=change-this-for-your-own-demo-instance
```

### 5. Create the database and load the schema

```bash
createdb -U postgres threatops
psql -U postgres -d threatops -f backend/schema_supabase.sql
```

If `createdb` is unavailable, create the database in pgAdmin or the PostgreSQL shell first, then run the `psql` command.

### 6. Start the app

```bash
python backend/app.py
```

Open `http://127.0.0.1:5000/login`.

## Demo Accounts

These are seeded automatically on startup if they do not already exist:

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

## What Each Screen Does

- `/login`: session login for classroom demo accounts
- `/dashboard`: overview of logs, correlations, and alert status
- `/analytics`: prebuilt aggregate SQL results
- `/visualize`: Chart.js rendering for selected fields
- `/alerts`: alert workflow and status updates
- `/sql_panel`: role-aware SQL execution panel
- `/admin/users`: user role and activation controls
- `/admin/audit_logs`: audit trail review

## Security Notes

The app is still a demo, but the current code now adds a few practical safeguards:

- Passwords are hashed with Werkzeug instead of plain SHA-256
- Authenticated POST routes require a CSRF token
- Demo passwords are no longer exposed in the login page source
- SQL execution is restricted to one statement at a time
- Engineer restrictions are enforced server-side, not just described in the UI

## Troubleshooting

### PostgreSQL driver import fails

Run:

```bash
pip install -r requirements.txt
```

If your environment still cannot import `psycopg2`, recreate the virtual environment and reinstall.

### Database connection fails

Check that:

- PostgreSQL is running
- the `threatops` database exists
- `DATABASE_URL` in `.env` points to the right host, port, username, and password

### Login works but pages error later

That usually means the schema has not been loaded fully. Re-run:

```bash
psql -U postgres -d threatops -f backend/schema_supabase.sql
```

### Port 5000 is busy

Change the port in `backend/app.py` before starting the app.
