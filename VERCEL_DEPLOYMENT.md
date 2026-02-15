# Vercel Deployment Guide

This guide helps you deploy ThreatOps to Vercel with a cloud MySQL database.

---

## Prerequisites

- GitHub account with this repository
- Vercel account (free tier works)
- Cloud MySQL database (PlanetScale/Railway recommended)

---

## Step 1: Set Up Cloud MySQL Database

### Option A: PlanetScale (Recommended - Free Tier Available)

1. Sign up at https://planetscale.com
2. Create new database: `threatops`
3. Click **Connect** → **Create password**
4. Copy the connection string (looks like: `mysql://user:pass@aws.connect.psdb.cloud/threatops`)
5. Import schema:
   ```bash
   pscale shell threatops main < threatops/schema.sql
   ```
   Or use PlanetScale's web console to execute SQL

**Note:** PlanetScale uses serverless MySQL optimized for Vercel!

### Option B: Railway.app

1. Sign up at https://railway.app
2. New Project → **Provision MySQL**
3. Copy the connection URL from **Variables** tab
4. Connect via MySQL client:
   ```bash
   mysql -h containers-us-west-123.railway.app -P 7654 -u root -p
   ```
5. Import schema:
   ```bash
   mysql -h HOST -P PORT -u root -p threatops < threatops/schema.sql
   ```

### Option C: AWS RDS / DigitalOcean / Other

1. Create MySQL database instance
2. Ensure it's publicly accessible
3. Note connection details
4. Import schema via MySQL client

---

## Step 2: Deploy to Vercel

### Method 1: Vercel Dashboard (Easiest)

1. Go to https://vercel.com/new
2. Import your GitHub repository: `RameshChettiar0806/ThreatOps-SecurityAnalytics`
3. Configure project:
   - **Framework Preset:** Other
   - **Root Directory:** `./`
   - **Build Command:** (leave empty)
   - **Output Directory:** (leave empty)

4. Add **Environment Variables:**
   - Name: `DATABASE_URL`
     Value: `mysql://user:pass@host/threatops` (your actual connection string)
   
   - Name: `SECRET_KEY`
     Value: (generate random string, e.g., `openssl rand -hex 32`)

5. Click **Deploy**

### Method 2: Vercel CLI

```bash
# Install Vercel CLI
npm i -g vercel

# Login to Vercel
vercel login

# Deploy
vercel

# Follow prompts, then add environment variables:
vercel env add DATABASE_URL
# Paste your database connection string

vercel env add SECRET_KEY
# Paste your secret key

# Deploy to production
vercel --prod
```

---

## Step 3: Verify Deployment

1. Visit your Vercel URL (e.g., `https://threat-ops-security-analytics.vercel.app`)
2. Check health endpoint: `https://your-app.vercel.app/api/health`
   - Should return: `{"status": "ok", "message": "ThreatOps is running on Vercel"}`
3. Access login page: `https://your-app.vercel.app/login`
4. Login with default credentials:
   - Admin: `admin` / `admin123`
   - Analyst: `analyst` / `analyst123`

---

## Troubleshooting

### Issue: "Database connection failed"

**Solution:**
- Verify `DATABASE_URL` environment variable is set correctly in Vercel
- Ensure database is publicly accessible
- Check database credentials
- For PlanetScale, make sure SSL is configured: `?ssl={"ssl_disabled": false}`

### Issue: "Internal Server Error 500"

**Solution:**
- Check Vercel function logs: https://vercel.com/your-project/logs
- Verify database schema was imported correctly
- Ensure `SECRET_KEY` is set in environment variables

### Issue: Static files (CSS/JS) not loading

**Solution:**
- Check `vercel.json` has correct static file routing
- Verify files exist in `threatops/static/`
- Clear browser cache

### Issue: "This site can't provide a secure connection"

**Solution:**
- Wait 1-2 minutes for SSL certificate provisioning
- Check Vercel deployment status
- Ensure custom domain is configured correctly (if using one)

---

## Database Schema Initialization

**IMPORTANT:** You must initialize the database schema BEFORE deploying to Vercel.

```bash
# For PlanetScale
pscale shell threatops main < threatops/schema.sql

# For Railway or other MySQL
mysql -h YOUR_HOST -P YOUR_PORT -u YOUR_USER -p threatops < threatops/schema.sql
```

This creates:
- ✅ 7 tables (USERS, RAW_LOGS, MITRE_ATTACK_TECHNIQUES, etc.)
- ✅ 2 views (THREAT_INTELLIGENCE_DASHBOARD, USER_ACTIVITY_SUMMARY)
- ✅ 2 stored procedures (CORRELATE_THREAT, GENERATE_ALERT)
- ✅ 2 triggers (AUDIT_CSV_UPLOAD, AUDIT_ALERT_CREATION)
- ✅ Default users (admin, analyst)
- ✅ MITRE ATT&CK/D3FEND data

---

## Environment Variables Reference

| Variable | Required | Description | Example |
|----------|----------|-------------|---------|
| `DATABASE_URL` | ✅ Yes | MySQL connection string | `mysql://user:pass@host/threatops` |
| `SECRET_KEY` | ✅ Yes | Flask session secret key | `random-32-char-string` |
| `VERCEL` | ⚙️ Auto | Serverless flag (auto-set) | `1` |
| `PYTHON_VERSION` | ⚙️ Auto | Python version (auto-set) | `3.11` |

---

## Custom Domain (Optional)

1. Go to Vercel project → **Settings** → **Domains**
2. Add your custom domain: `threatops.yourdomain.com`
3. Update DNS records as instructed
4. Wait for SSL certificate provisioning

---

## Cost Considerations

### Free Tier Limits (Vercel)
- ✅ Unlimited bandwidth
- ✅ 100GB bandwidth/month
- ✅ Serverless function execution
- ✅ Automatic HTTPS

### Database Costs
- **PlanetScale Free:** 5GB storage, 1 billion row reads/month
- **Railway Free:** $5 credit/month (enough for development)
- **AWS RDS Free Tier:** 750 hours/month for 12 months

**Recommended:** Start with PlanetScale free tier for development/demos.

---

## Local Development vs. Vercel

This codebase works seamlessly in both environments:

**Local Development:**
```bash
cd threatops
python app.py
# Runs on http://localhost:5000
```

**Vercel Deployment:**
- Serverless functions
- NullPool connections (no connection pooling)
- Optimized for cold starts
- Environment variables from Vercel dashboard

---

## Next Steps After Deployment

1. ✅ Change default passwords in database
2. ✅ Update `SECRET_KEY` to strong random value
3. ✅ Configure database backups
4. ✅ Set up monitoring (Vercel Analytics)
5. ✅ Add custom domain (optional)
6. ✅ Enable Vercel Firewall (optional)

---

## Support

- **Vercel Docs:** https://vercel.com/docs
- **PlanetScale Docs:** https://planetscale.com/docs
- **Railroad Docs:** https://docs.railway.app

---

**Ready to deploy?** Just push to GitHub and Vercel will auto-deploy! 🚀
