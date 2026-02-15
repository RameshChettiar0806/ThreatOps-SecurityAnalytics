# Fix Vercel Authentication Issues

**Your app is live on Vercel but authentication isn't working?** Follow these steps to fix it.

---

## Step 1: Check What's Wrong

Visit your Vercel app's diagnostic endpoint:

```
https://your-app.vercel.app/api/diagnostics
```

This will show you exactly what's missing.

---

## Step 2: Set Up Environment Variables in Vercel

### Go to Vercel Dashboard

1. Visit https://vercel.com/dashboard
2. Click on your **ThreatOps-SecurityAnalytics** project
3. Go to **Settings** tab
4. Click **Environment Variables** in the left sidebar

### Add These Variables

#### 1. DATABASE_URL (Required)

**For Quick Testing - Use Railway (5 minutes setup):**

1. Sign up at https://railway.app
2. Click **New Project** → **Provision MySQL**
3. Click on MySQL service → **Variables** tab
4. Copy the `DATABASE_URL` value
5. In Vercel, add:
   - **Name:** `DATABASE_URL`
   - **Value:** (paste the Railway URL)
   - **Environment:** Production, Preview, Development (check all)
   - Click **Save**

**For Production - Use PlanetScale (Free, Recommended):**

1. Sign up at https://planetscale.com
2. Create database: `threatops`
3. Click **Connect** → **Create password** → **Node.js**
4. Copy the connection string (looks like: `mysql://user:pass@region.aws.psdb.cloud/threatops`)
5. In Vercel, add:
   - **Name:** `DATABASE_URL`
   - **Value:** (paste PlanetScale URL)
   - **Environment:** Production, Preview, Development
   - Click **Save**

#### 2. SECRET_KEY (Required)

Generate a random secret key:

**Windows PowerShell:**
```powershell
-join ((65..90) + (97..122) + (48..57) | Get-Random -Count 32 | ForEach-Object {[char]$_})
```

**Linux/Mac:**
```bash
openssl rand -hex 32
```

In Vercel dashboard:
- **Name:** `SECRET_KEY`
- **Value:** (paste your generated key)
- **Environment:** Production, Preview, Development
- Click **Save**

---

## Step 3: Initialize Database Schema

### Option A: Railway Database

1. Install Railway CLI:
   ```bash
   npm i -g @railway/cli
   ```

2. Login and link project:
   ```bash
   railway login
   railway link
   ```

3. Connect to database:
   ```bash
   railway connect mysql
   ```

4. In MySQL shell, create database and exit:
   ```sql
   CREATE DATABASE IF NOT EXISTS threatops;
   EXIT;
   ```

5. Import schema from your local machine:
   ```bash
   # Get connection details from Railway dashboard
   mysql -h containers-us-west-XXX.railway.app -P XXXX -u root -p threatops < threatops/schema.sql
   ```

### Option B: PlanetScale Database

1. Install PlanetScale CLI:
   ```bash
   # Windows (PowerShell as Admin)
   scoop bucket add pscale https://github.com/planetscale/scoop-bucket
   scoop install pscale mysql
   
   # Mac
   brew install planetscale/tap/pscale mysql-client
   
   # Linux
   curl -fsSL https://github.com/planetscale/cli/releases/latest/download/pscale_linux_amd64.tar.gz | tar xz -C /usr/local/bin
   ```

2. Login and connect:
   ```bash
   pscale auth login
   pscale shell threatops main
   ```

3. In PlanetScale shell, paste contents of `threatops/schema.sql` (copy-paste the entire file content)

### Option C: Use PlanetScale Web Console

1. Go to your PlanetScale dashboard
2. Click on `threatops` database → **Console** tab
3. Open `threatops/schema.sql` in a text editor
4. Copy ALL the SQL content
5. Paste into PlanetScale console and execute
6. Takes ~30 seconds to complete

---

## Step 4: Redeploy Vercel App

After setting environment variables:

1. Go to Vercel dashboard → **Deployments** tab
2. Click the **⋯** (three dots) on latest deployment
3. Click **Redeploy**
4. Wait ~1 minute for deployment to complete

---

## Step 5: Test Authentication

1. Visit your app: `https://your-app.vercel.app/login`
2. Login with default credentials:
   - **Username:** `admin`
   - **Password:** `admin123`

**If it works:** ✅ You're done!

**If it still fails:** Continue to Step 6

---

## Step 6: Debug Authentication Issues

Visit the diagnostic endpoint again:
```
https://your-app.vercel.app/api/diagnostics
```

**Common Issues:**

### Issue: "DATABASE_URL_set: false"
**Fix:** You didn't add DATABASE_URL in Vercel environment variables. Go back to Step 2.

### Issue: "❌ Connection failed"
**Fix:** Check your database connection string is correct:
- For Railway: Make sure you copied the full `DATABASE_URL` from Variables tab
- For PlanetScale: Ensure you're using `mysql://` protocol (not `mysql+mysqlconnector://`)

### Issue: "⚠️ USERS table not found"
**Fix:** You didn't import the schema. Go back to Step 3.

### Issue: "0 users in database"
**Fix:** Schema imported but default users weren't created. Run this in your database:

```sql
-- Create admin user (password: admin123)
INSERT INTO USERS (username, password_hash, role, email, is_active) VALUES
('admin', '240be518fabd2724ddb6f04eeb1da5967448d7e831c08c8fa822809f74c720a9', 'Admin', 'admin@threatops.local', TRUE);

-- Create analyst user (password: analyst123)
INSERT INTO USERS (username, password_hash, role, email, is_active) VALUES
('analyst', '0b94850cb26dbf11cbc5dcabcb3f4e6ab2850e40c4299301f846c87f7827de6c', 'Analyst', 'analyst@threatops.local', TRUE);
```

---

## Step 7: Change Default Passwords (Important!)

**SECURITY WARNING:** The default passwords are publicly known!

After successful login, change passwords:

**Option 1: Via SQL**
```sql
-- Change admin password to 'NewPassword123'
UPDATE USERS 
SET password_hash = SHA2('NewPassword123', 256) 
WHERE username = 'admin';

-- Change analyst password
UPDATE USERS 
SET password_hash = SHA2('NewPassword456', 256) 
WHERE username = 'analyst';
```

**Option 2: Via App** (if you implement password change feature)

---

## Quick Reference

| Item | Value |
|------|-------|
| **Diagnostic URL** | `https://your-app.vercel.app/api/diagnostics` |
| **Health Check** | `https://your-app.vercel.app/api/health` |
| **Login Page** | `https://your-app.vercel.app/login` |
| **Admin User** | username: `admin` / password: `admin123` |
| **Analyst User** | username: `analyst` / password: `analyst123` |

---

## Environment Variables Summary

```env
# Required (Set in Vercel Dashboard → Settings → Environment Variables)
DATABASE_URL=mysql://user:pass@host/threatops
SECRET_KEY=your-random-32-character-secret-key

# Auto-set by Vercel (don't add these)
VERCEL=1
PYTHONPATH=/var/task
```

---

## Still Having Issues?

1. **Check Vercel Logs:** https://vercel.com/your-project/logs
2. **Test Database Connection:** Connect manually using MySQL client
3. **Verify Schema:** Make sure all 7 tables were created
4. **Check Firewall:** Ensure your database allows connections from Vercel IPs

---

## Success Criteria

✅ `/api/diagnostics` shows:
- `DATABASE_URL_set: true`
- `SECRET_KEY_set: true`
- `database: "✅ Connected | 2 users in database"`

✅ You can login at `/login` with admin/admin123

✅ Dashboard loads after login

---

**Need help?** Check the full deployment guide: [VERCEL_DEPLOYMENT.md](VERCEL_DEPLOYMENT.md)
