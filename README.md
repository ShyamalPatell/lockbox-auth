# Lockbox: a secure login website

A full account system: sign up, confirm your email, log in, log out, forgot password, and forgot username. Built with Node.js and Express, with security handled properly at every step.

## Features

- **Sign up** with a username, email, and password
- **Email confirmation**: you can't log in until you click the link in your inbox
- **Log in** with either your username or your email
- **Log out** (this device) or **log out of all devices**
- **Forgot password**: emails a one-time reset link
- **Forgot username**: emails you your username
- **Password rules**: at least 10 characters, with at least one special character
- **Unique usernames**: once a name is taken, nobody else can use it (`Shyamal` and `shyamal` count as the same name)

## Security, explained

| Threat | What stops it |
|---|---|
| Stolen database reveals passwords | Passwords are hashed with **scrypt** (OWASP settings) and a random salt. The real password is never stored. |
| Two people grab the same username at once | A `UNIQUE` constraint in the database itself, so it's impossible even in a race. Tested with 4 simultaneous signups. |
| Password guessing (brute force) | Account **locks for 15 minutes after 5 wrong passwords**, plus **per-IP rate limits** on every form. |
| SQL injection | Every query uses parameters (`$1`, `$2`). User input is never glued into SQL. |
| XSS (injected scripts) | Every value placed into a page is HTML-escaped, and a strict **Content-Security-Policy** blocks inline scripts. |
| CSRF (another site submitting forms as you) | Every form has a secret token that must match an HttpOnly cookie, plus `Origin` / `Sec-Fetch-Site` checks. |
| Session hijacking | Session IDs are 256-bit random values in **HttpOnly, Secure, SameSite** `__Host-` cookies. Only a hash is stored in the database. Sessions expire after 1 hour idle or 12 hours total. |
| Session fixation | A brand-new session ID is created at every login. |
| Logout that doesn't really log out | Logout deletes the session on the server, so a copied cookie stops working immediately. |
| Account enumeration ("is this email registered?") | Forgot-password, forgot-username, and resend pages give the identical answer for real and fake emails. Login gives the same error for "wrong password" and "no such user" and takes the same time. Signing up with an already-used email shows the normal "check your email" page and warns the real owner by email. |
| Reset / verification link abuse | Links are 256-bit random, **single use**, short-lived (30 min for reset, 24 h for verify), stored as SHA-256 hashes, and requesting a new one cancels the old one. |
| Someone resets your password | Every device is logged out and you get a "your password was changed" email. |
| Username squatting with fake emails | Unconfirmed accounts are deleted after 24 hours. |
| Host-header poisoning of email links | Links are built from a fixed `APP_URL`, never from the request. |
| Clickjacking, sniffing, caching | `helmet` sets `frame-ancestors 'none'`, `nosniff`, HSTS, and `Cache-Control: no-store` on account pages. |

## Run it on your computer

You need [Node.js 22](https://nodejs.org).

```bash
npm install
npm run dev
```

Open http://localhost:3000. Locally, emails aren't really sent; they're **printed in the terminal**, so copy the confirmation link from there.

Run the 25 automated security tests:

```bash
npm test
```

## Deploy it for free (Render + Neon + Brevo)

You'll set up three free accounts. Each one has a job:

- **GitHub** holds your code.
- **Neon** is the database (where accounts are saved). Render's free servers wipe their disk when they restart, so the database has to live somewhere else.
- **Brevo** sends the emails. Render's free plan blocks normal email (SMTP), so we use Brevo's web API instead.
- **Render** runs the website and gives you the public link.

### Step 1: Put the code on GitHub

1. Go to https://github.com/new, name the repo `lockbox-auth`, leave everything else alone, and click **Create repository**.
2. Easiest way: on the new repo's page click **uploading an existing file**, open this project folder on your computer, select everything inside it, drag it all onto the page, and click **Commit changes**. `package.json` must end up at the top level of the repo, not inside a `lockbox` folder.
3. Or, if you'd rather use git in a terminal, run this inside the project folder:

```bash
git init
git add .
git commit -m "Lockbox secure auth site"
git branch -M main
git remote add origin https://github.com/ShyamalPatell/lockbox-auth.git
git push -u origin main
```

The `.gitignore` file makes sure `node_modules` and any local database are not uploaded.

### Step 2: Create the database on Neon

1. Sign up at https://neon.tech (signing in with GitHub is fastest).
2. Create a project. Any name and the region closest to you (e.g. US East).
3. On the project dashboard click **Connect**, and copy the connection string. It looks like `postgresql://neondb_owner:...@ep-....neon.tech/neondb?sslmode=require`.
4. Keep it somewhere private. This is your `DATABASE_URL`. The app creates its tables automatically the first time it starts.

### Step 3: Set up email on Brevo

1. Sign up at https://www.brevo.com (free plan, 300 emails per day).
2. Go to **Senders, Domains & Dedicated IPs → Senders → Add a sender**. Enter your own email address and confirm it from your inbox. This is your `MAIL_FROM_EMAIL`.
3. Go to **SMTP & API → API Keys → Generate a new API key**. Copy it (it starts with `xkeysib-`). This is your `BREVO_API_KEY`.

### Step 4: Launch on Render

1. Sign up at https://render.com with your GitHub account.
2. Click **New → Web Service**, then pick your `lockbox-auth` repo.
3. Use these settings:
   - **Runtime:** Node
   - **Build Command:** `npm ci`
   - **Start Command:** `npm start`
   - **Instance Type:** Free
4. Under **Environment Variables**, add:

| Key | Value |
|---|---|
| `NODE_ENV` | `production` |
| `DATABASE_URL` | your Neon connection string |
| `BREVO_API_KEY` | your Brevo API key |
| `MAIL_FROM_EMAIL` | the sender email you confirmed in Brevo |

5. Click **Create Web Service**. After a couple of minutes the log says `Lockbox running at https://lockbox-auth-xxxx.onrender.com (db: postgres, mail: brevo)`. That URL at the top of the Render page is the link for your friend.

(Alternative: Render's **New → Blueprint** reads `render.yaml` and fills in the settings for you. You still paste the three secret values.)

### Step 5: Test it yourself before sending the link

1. Open the link and create an account with your real email.
2. Find the confirmation email. **Check your spam folder.** Emails sent from a Gmail address through Brevo often land there at first.
3. Click the link, log in, log out, then try "Forgot password" and "Forgot username".

### Things to know about the free tier

- **The first visit can take ~50 seconds.** Free Render servers fall asleep after 15 minutes of no visitors and wake up on the next visit. Tell your friend so they don't think it's broken.
- **Emails not arriving?** In Render, open your service → **Logs** and look for a line starting with `[mail] failed`. It will say what Brevo rejected (usually an unconfirmed sender or a typo in the API key).
- **`db: sqlite` in the log** means `DATABASE_URL` isn't set, and accounts will vanish when the server sleeps. Add the Neon string and redeploy.

## Project structure

```
src/
  server.js    starts the app
  app.js       all routes and the security middleware (CSRF, sessions, rate limits)
  security.js  password hashing, random tokens, input validation
  db.js        PostgreSQL / SQLite access with parameterized queries
  mailer.js    sends email through Brevo, Resend, SMTP, or the console
  views.js     HTML pages (auto-escaped to prevent XSS)
  config.js    settings and timeouts
public/        CSS, small form-helper JavaScript, icon
test/          25 automated security tests
```
