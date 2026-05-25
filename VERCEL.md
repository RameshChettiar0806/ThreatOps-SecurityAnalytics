# Vercel Deployment

ThreatOps deploys to Vercel through `api/index.py`, which imports the Flask app from `backend/app.py`.

## 1. Prepare Supabase

1. Open Supabase SQL Editor.
2. Run `backend/schema_supabase.sql`.
3. Confirm these tables exist: `users`, `raw_logs`, `mitre_attack_techniques`, `mitre_defend_countermeasures`, `threat_correlation`, `alerts`, `audit_logs`.

## 2. Add Vercel Environment Variables

In Vercel, open Project Settings > Environment Variables and add:

```env
DATABASE_URL=postgresql://postgres.[PROJECT_REF]:[PASSWORD]@aws-0-[REGION].pooler.supabase.com:6543/postgres?sslmode=require
SECRET_KEY=<generate-a-long-random-value>
FLASK_ENV=production
```

Use the Supabase pooler connection string for Vercel because Vercel functions are serverless.

## 3. Deploy

Connect the GitHub repo to Vercel and deploy the `main` branch.

After deployment, check:

```text
https://<your-vercel-domain>/health
https://<your-vercel-domain>/login
```

Expected health response:

```json
{"database":"connected","status":"ok"}
```

## 4. Demo Login

Use the seeded classroom demo accounts from `README.md`, for example:

```text
rajeshKumar / ADM123
```

## Troubleshooting

- `database=unavailable`: check `DATABASE_URL`, Supabase password, project region, and `sslmode=require`.
- Login fails after schema import: run `/health` first, then confirm the `users` table has seeded rows.
- Static files missing: confirm `frontend/static` is committed and `vercel.json` routes all traffic to `api/index.py`.
