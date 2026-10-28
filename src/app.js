'use strict';

const path = require('node:path');
const express = require('express');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const { rateLimit } = require('express-rate-limit');

const config = require('./config');
const db = require('./db');
const sec = require('./security');
const mail = require('./mailer');
const views = require('./views');

// Only accept plain strings from forms. A crafted request could send an array
// (name=a&name=b); this turns anything unexpected into an empty string.
const str = (v) => (typeof v === 'string' ? v : '');

function createApp() {
  const app = express();
  app.set('trust proxy', config.trustProxy);

  // ---------- Security headers ----------
  // helmet sets headers like Strict-Transport-Security (always HTTPS),
  // X-Frame-Options (no clickjacking) and a Content-Security-Policy that only
  // allows scripts and styles from this site itself, so injected code can't run.
  app.use(helmet({
    contentSecurityPolicy: {
      useDefaults: false,
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'"],
        imgSrc: ["'self'", 'data:'],
        fontSrc: ["'self'"],
        connectSrc: ["'self'"],
        formAction: ["'self'"],
        frameAncestors: ["'none'"],
        baseUri: ["'none'"],
        objectSrc: ["'none'"],
        ...(config.isProd ? { upgradeInsecureRequests: [] } : {}),
      },
    },
    strictTransportSecurity: config.isProd ? { maxAge: 31536000, includeSubDomains: true } : false,
    referrerPolicy: { policy: 'no-referrer' },
  }));

  app.get('/healthz', (req, res) => res.type('text').send('ok'));
  app.use(express.static(path.join(__dirname, '..', 'public'), { index: false, maxAge: '1h' }));

  // Pages with account info must never be cached (e.g. by a shared computer's
  // browser "back" button after logging out).
  app.use((req, res, next) => { res.set('Cache-Control', 'no-store'); next(); });
  app.use(express.urlencoded({ extended: false, limit: '10kb', parameterLimit: 20 }));
  app.use(cookieParser());

  // ---------- CSRF protection ----------
  // A random secret lives in an HttpOnly cookie AND in a hidden field in every
  // form. Another website can make your browser submit a form to us, but it
  // can't read the secret, so the two won't match and we reject the request.
  // We also check the browser's Origin / Sec-Fetch-Site headers as a 2nd layer.
  function setCsrfCookie(res, token) {
    res.cookie(config.csrfCookie, token, { httpOnly: true, secure: config.cookieSecure, sameSite: 'strict', path: '/' });
  }
  function rotateCsrf(req, res) {
    req.csrf = sec.randomToken();
    setCsrfCookie(res, req.csrf);
  }
  app.use((req, res, next) => {
    let token = req.cookies[config.csrfCookie];
    if (!sec.isTokenShape(token)) { token = sec.randomToken(); setCsrfCookie(res, token); }
    req.csrf = token;
    if (req.method !== 'POST') return next();

    const site = req.get('sec-fetch-site');
    const origin = req.get('origin');
    const selfOrigin = `${req.protocol}://${req.get('host')}`;
    const crossSite = (site && !['same-origin', 'none'].includes(site)) ||
      (origin && origin !== 'null' && origin !== config.appOrigin && origin !== selfOrigin);
    const sent = str(req.body && req.body._csrf);
    if (crossSite || !sent || !sec.safeEqual(sent, token)) {
      return res.status(403).send(views.message({
        csrf: req.csrf, title: 'Form expired', tone: 'error',
        text: 'For your security this form couldn’t be submitted. Go back, refresh the page, and try again.',
        links: [['/', 'Go home']],
      }));
    }
    next();
  });

  // ---------- Sessions ----------
  // The cookie holds a long random ID. The database stores only a SHA-256
  // hash of it, so even someone reading the database can't hijack sessions.
  const sessionCookieOpts = { httpOnly: true, secure: config.cookieSecure, sameSite: 'lax', path: '/' };

  async function createSession(res, userId) {
    const { token, hash } = sec.newToken();
    const now = Date.now();
    await db.run('INSERT INTO sessions (id_hash, user_id, created_at, last_seen, expires_at) VALUES ($1, $2, $3, $4, $5)',
      [hash, userId, now, now, now + config.sessionAbsoluteMs]);
    res.cookie(config.sessionCookie, token, { ...sessionCookieOpts, maxAge: config.sessionAbsoluteMs });
  }

  async function destroySession(req, res) {
    const sid = req.cookies[config.sessionCookie];
    if (sid) await db.run('DELETE FROM sessions WHERE id_hash = $1', [sec.hashToken(sid)]);
    res.clearCookie(config.sessionCookie, sessionCookieOpts);
  }

  app.use(async (req, res, next) => {
    const sid = req.cookies[config.sessionCookie];
    if (!sid) return next();
    const now = Date.now();
    const s = sec.isTokenShape(sid) ? await db.get(
      `SELECT s.id_hash, s.last_seen, s.expires_at, u.id, u.username, u.email, u.created_at
         FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.id_hash = $1`, [sec.hashToken(sid)]) : null;
    if (!s || s.expires_at <= now || now - s.last_seen > config.sessionIdleMs) {
      if (s) await db.run('DELETE FROM sessions WHERE id_hash = $1', [s.id_hash]);
      res.clearCookie(config.sessionCookie, sessionCookieOpts);
      return next();
    }
    if (now - s.last_seen > 60 * 1000) await db.run('UPDATE sessions SET last_seen = $1 WHERE id_hash = $2', [now, s.id_hash]);
    req.user = { id: s.id, username: s.username, email: s.email, created_at: s.created_at };
    next();
  });

  const requireUser = (req, res, next) => (req.user ? next() : res.redirect(303, '/login'));
  const requireGuest = (req, res, next) => (req.user ? res.redirect(303, '/dashboard') : next());

  // ---------- Rate limiting ----------
  // Stops bots from hammering forms. Counted per IP address.
  const limiter = (limit, windowMin) => rateLimit({
    windowMs: windowMin * 60 * 1000,
    limit,
    standardHeaders: 'draft-7',
    legacyHeaders: false,
    handler: (req, res) => res.status(429).send(views.message({
      csrf: req.csrf, user: req.user, title: 'Slow down', tone: 'error',
      text: 'Too many attempts from your network. Please wait a few minutes and try again.',
      links: [['/', 'Go home']],
    })),
  });
  const loginLimiter = limiter(20, 15);
  const signupLimiter = limiter(10, 60);
  const emailLimiter = () => limiter(5, 15); // a separate bucket per email form

  // ---------- Helpers ----------
  async function issueToken(userId, purpose, ttlMs) {
    // Requesting a new link cancels any older unused link of the same kind.
    await db.run('DELETE FROM tokens WHERE user_id = $1 AND purpose = $2', [userId, purpose]);
    const { token, hash } = sec.newToken();
    await db.run('INSERT INTO tokens (token_hash, user_id, purpose, expires_at) VALUES ($1, $2, $3, $4)',
      [hash, userId, purpose, Date.now() + ttlMs]);
    return token;
  }

  // Checks a link token WITHOUT using it up (to show the reset form).
  async function peekToken(token, purpose) {
    if (!sec.isTokenShape(token)) return null;
    const row = await db.get(
      `SELECT t.user_id, u.username, u.email FROM tokens t JOIN users u ON u.id = t.user_id
        WHERE t.token_hash = $1 AND t.purpose = $2 AND t.used = 0 AND t.expires_at > $3`,
      [sec.hashToken(token), purpose, Date.now()]);
    return row || null;
  }

  // Uses a token up. A single UPDATE does the check and the "mark used" in
  // one atomic step, so even two simultaneous clicks can't use a link twice.
  async function consumeToken(token, purpose) {
    if (!sec.isTokenShape(token)) return null;
    const row = await db.get(
      `UPDATE tokens SET used = 1
        WHERE token_hash = $1 AND purpose = $2 AND used = 0 AND expires_at > $3
        RETURNING user_id`,
      [sec.hashToken(token), purpose, Date.now()]);
    return row ? row.user_id : null;
  }

  async function cleanup() {
    const now = Date.now();
    await db.run('DELETE FROM sessions WHERE expires_at <= $1 OR last_seen <= $2', [now, now - config.sessionIdleMs]);
    await db.run('DELETE FROM tokens WHERE expires_at <= $1 OR used = 1', [now]);
    // Unverified accounts are removed after 24h so nobody can "squat" a
    // username (or someone else's email) forever without proving ownership.
    await db.run('DELETE FROM users WHERE email_verified = 0 AND created_at <= $1', [now - config.unverifiedAccountTtlMs]);
  }
  app.locals.cleanup = cleanup;

  const genericEmailSent = (req, text) => views.message({
    csrf: req.csrf, title: 'Check your email', tone: 'success', text,
    links: [['/login', 'Back to log in']],
  });

  // ---------- Routes ----------
  app.get('/', (req, res) => (req.user ? res.redirect(303, '/dashboard') : res.send(views.home({ csrf: req.csrf }))));

  // ----- Sign up -----
  app.get('/signup', requireGuest, (req, res) => res.send(views.signup({ csrf: req.csrf })));

  app.post('/signup', requireGuest, signupLimiter, async (req, res) => {
    const username = str(req.body.username).trim();
    const email = str(req.body.email).trim();
    const password = str(req.body.password);
    const confirm = str(req.body.confirm);
    const values = { username, email };

    const errors = {};
    const uErr = sec.validateUsername(username); if (uErr) errors.username = uErr;
    const eErr = sec.validateEmail(email); if (eErr) errors.email = eErr;
    const pwProblems = sec.passwordProblems(password, { username, email });
    if (pwProblems.length) errors.password = pwProblems.join(' ');
    if (!errors.password && password !== confirm) errors.confirm = 'Passwords don’t match.';
    const fail = (status = 400) => res.status(status).send(views.signup({ csrf: req.csrf, values, errors }));
    if (Object.keys(errors).length) return fail();

    await cleanup();
    const usernameLower = username.toLowerCase();
    const emailLower = email.toLowerCase();

    if (await db.get('SELECT 1 AS x FROM users WHERE username_lower = $1', [usernameLower])) {
      errors.username = 'That username is already taken. Please choose another.';
      return fail(409);
    }

    // Hash BEFORE checking the email, so "new email" and "email already used"
    // take the same amount of time and look identical from the outside.
    const passwordHash = await sec.hashPassword(password);
    const checkEmailPage = genericEmailSent(req,
      `We sent a confirmation link to ${email}. Click it to activate your account, then log in. (Check your spam folder too.)`);

    const existing = await db.get('SELECT username FROM users WHERE email_lower = $1', [emailLower]);
    if (existing) {
      // Don't reveal that this email is registered. Tell the real owner instead.
      mail.send(email, 'alreadyRegistered', existing.username);
      return res.send(checkEmailPage);
    }

    let user;
    try {
      user = await db.get(
        `INSERT INTO users (username, username_lower, email, email_lower, password_hash, created_at)
         VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
        [username, usernameLower, email, emailLower, passwordHash, Date.now()]);
    } catch (err) {
      if (!db.isUniqueViolation(err)) throw err;
      // Someone grabbed the same username or email a split second earlier.
      if (await db.get('SELECT 1 AS x FROM users WHERE username_lower = $1', [usernameLower])) {
        errors.username = 'That username is already taken. Please choose another.';
        return fail(409);
      }
      return res.send(checkEmailPage);
    }

    const token = await issueToken(user.id, 'verify', config.verifyTokenTtlMs);
    mail.send(email, 'verify', username, `${config.appUrl}/verify-email?token=${token}`);
    res.send(checkEmailPage);
  });

  // ----- Email verification -----
  app.get('/verify-email', async (req, res) => {
    const userId = await consumeToken(str(req.query.token), 'verify');
    if (!userId) {
      return res.status(400).send(views.message({
        csrf: req.csrf, user: req.user, title: 'Link expired', tone: 'error',
        text: 'This confirmation link is invalid, already used, or expired.',
        links: [['/resend-verification', 'Send a new link'], ['/login', 'Log in']],
      }));
    }
    await db.run('UPDATE users SET email_verified = 1 WHERE id = $1', [userId]);
    res.send(views.message({
      csrf: req.csrf, user: req.user, title: 'Email confirmed', tone: 'success',
      text: 'Your email is confirmed and your account is active. You can log in now.',
      links: [['/login', 'Log in']],
    }));
  });

  app.get('/resend-verification', requireGuest, (req, res) =>
    res.send(views.emailForm({ csrf: req.csrf, kind: 'resend-verification' })));

  app.post('/resend-verification', requireGuest, emailLimiter(), async (req, res) => {
    const email = str(req.body.email).trim();
    const err = sec.validateEmail(email);
    if (err) return res.status(400).send(views.emailForm({ csrf: req.csrf, kind: 'resend-verification', values: { email }, error: err }));
    const user = await db.get('SELECT id, username, email_verified FROM users WHERE email_lower = $1', [email.toLowerCase()]);
    if (user && !user.email_verified) {
      const token = await issueToken(user.id, 'verify', config.verifyTokenTtlMs);
      mail.send(email, 'verify', user.username, `${config.appUrl}/verify-email?token=${token}`);
    }
    res.send(genericEmailSent(req, `If ${email} belongs to an account that still needs confirming, a new link is on its way.`));
  });

  // ----- Log in -----
  app.get('/login', requireGuest, (req, res) => {
    const info = req.query.loggedout ? 'You’ve been logged out safely.' : null;
    res.send(views.login({ csrf: req.csrf, info }));
  });

  app.post('/login', requireGuest, loginLimiter, async (req, res) => {
    const identifier = str(req.body.identifier).trim();
    const password = str(req.body.password);
    const generic = `Incorrect username/email or password. (After ${config.maxFailedLogins} wrong tries the account locks for ${config.lockoutMs / 60000} minutes.)`;
    const fail = (status = 401, extra = {}) => res.status(status).send(views.login({ csrf: req.csrf, values: { identifier }, error: generic, ...extra }));

    if (!identifier || !password || identifier.length > 254 || password.length > sec.PASSWORD_MAX) {
      await sec.burnTime(password);
      return fail();
    }

    const user = await db.get('SELECT * FROM users WHERE username_lower = $1 OR email_lower = $1', [identifier.toLowerCase()]);
    const now = Date.now();

    // Unknown user or locked account: do the same slow work, give the same answer.
    if (!user || user.locked_until > now) {
      await sec.burnTime(password);
      return fail();
    }

    if (!(await sec.verifyPassword(password, user.password_hash))) {
      const row = await db.get('UPDATE users SET failed_logins = failed_logins + 1 WHERE id = $1 RETURNING failed_logins', [user.id]);
      if (row.failed_logins >= config.maxFailedLogins) {
        await db.run('UPDATE users SET failed_logins = 0, locked_until = $1 WHERE id = $2', [now + config.lockoutMs, user.id]);
      }
      return fail();
    }

    if (!user.email_verified) {
      return res.status(403).send(views.login({
        csrf: req.csrf, values: { identifier }, showResend: true,
        error: 'Please confirm your email before logging in. Check your inbox (and spam folder) for the link.',
      }));
    }

    await db.run('UPDATE users SET failed_logins = 0, locked_until = 0 WHERE id = $1', [user.id]);
    // Brand-new session ID on every login (prevents "session fixation" attacks)
    // and a fresh CSRF secret too.
    await destroySession(req, res);
    await createSession(res, user.id);
    rotateCsrf(req, res);
    res.redirect(303, '/dashboard');
  });

  // ----- Account page -----
  app.get('/dashboard', requireUser, async (req, res) => {
    const { n } = await db.get('SELECT COUNT(*) AS n FROM sessions WHERE user_id = $1', [req.user.id]);
    res.send(views.dashboard({ csrf: req.csrf, user: req.user, sessionCount: Number(n) }));
  });

  // ----- Log out -----
  // Logout is a POST with a CSRF token, so a malicious link or image can't
  // log you out. The session is deleted on the server, not just the cookie.
  app.post('/logout', async (req, res) => {
    await destroySession(req, res);
    rotateCsrf(req, res);
    res.redirect(303, '/login?loggedout=1');
  });

  app.post('/logout-all', requireUser, async (req, res) => {
    await db.run('DELETE FROM sessions WHERE user_id = $1', [req.user.id]);
    res.clearCookie(config.sessionCookie, sessionCookieOpts);
    rotateCsrf(req, res);
    res.redirect(303, '/login?loggedout=1');
  });

  // ----- Forgot password -----
  app.get('/forgot-password', requireGuest, (req, res) =>
    res.send(views.emailForm({ csrf: req.csrf, kind: 'forgot-password' })));

  app.post('/forgot-password', requireGuest, emailLimiter(), async (req, res) => {
    const email = str(req.body.email).trim();
    const err = sec.validateEmail(email);
    if (err) return res.status(400).send(views.emailForm({ csrf: req.csrf, kind: 'forgot-password', values: { email }, error: err }));
    const user = await db.get('SELECT id, username FROM users WHERE email_lower = $1', [email.toLowerCase()]);
    if (user) {
      const token = await issueToken(user.id, 'reset', config.resetTokenTtlMs);
      mail.send(email, 'reset', user.username, `${config.appUrl}/reset-password?token=${token}`);
    }
    // Same message either way, so this page can't be used to test which emails have accounts.
    res.send(genericEmailSent(req, `If an account uses ${email}, a password reset link is on its way. It expires in 30 minutes.`));
  });

  const badResetLink = (req) => views.message({
    csrf: req.csrf, title: 'Link expired', tone: 'error',
    text: 'This reset link is invalid, already used, or expired. Reset links work once and last 30 minutes.',
    links: [['/forgot-password', 'Get a new link']],
  });

  app.get('/reset-password', async (req, res) => {
    const token = str(req.query.token);
    if (!(await peekToken(token, 'reset'))) return res.status(400).send(badResetLink(req));
    res.send(views.resetPassword({ csrf: req.csrf, token }));
  });

  app.post('/reset-password', async (req, res) => {
    const token = str(req.body.token);
    const password = str(req.body.password);
    const confirm = str(req.body.confirm);
    const info = await peekToken(token, 'reset');
    if (!info) return res.status(400).send(badResetLink(req));

    const errors = {};
    const problems = sec.passwordProblems(password, { username: info.username, email: info.email });
    if (problems.length) errors.password = problems.join(' ');
    else if (password !== confirm) errors.confirm = 'Passwords don’t match.';
    if (Object.keys(errors).length) return res.status(400).send(views.resetPassword({ csrf: req.csrf, token, errors }));

    const passwordHash = await sec.hashPassword(password);
    const userId = await consumeToken(token, 'reset');
    if (!userId) return res.status(400).send(badResetLink(req));

    // Clicking the email link proves they own the email, so mark it verified.
    await db.run('UPDATE users SET password_hash = $1, email_verified = 1, failed_logins = 0, locked_until = 0 WHERE id = $2', [passwordHash, userId]);
    await db.run('DELETE FROM sessions WHERE user_id = $1', [userId]); // kick out anyone using the old password
    await db.run('DELETE FROM tokens WHERE user_id = $1 AND purpose = $2', [userId, 'reset']);
    res.clearCookie(config.sessionCookie, sessionCookieOpts);
    rotateCsrf(req, res);
    mail.send(info.email, 'passwordChanged', info.username);
    res.send(views.login({ csrf: req.csrf, info: 'Your password has been changed. Log in with your new password.' }));
  });

  // ----- Forgot username -----
  app.get('/forgot-username', requireGuest, (req, res) =>
    res.send(views.emailForm({ csrf: req.csrf, kind: 'forgot-username' })));

  app.post('/forgot-username', requireGuest, emailLimiter(), async (req, res) => {
    const email = str(req.body.email).trim();
    const err = sec.validateEmail(email);
    if (err) return res.status(400).send(views.emailForm({ csrf: req.csrf, kind: 'forgot-username', values: { email }, error: err }));
    const user = await db.get('SELECT username FROM users WHERE email_lower = $1', [email.toLowerCase()]);
    if (user) mail.send(email, 'username', user.username);
    res.send(genericEmailSent(req, `If an account uses ${email}, we’ve emailed its username there.`));
  });

  // ---------- 404 + errors ----------
  app.use((req, res) => res.status(404).send(views.message({
    csrf: req.csrf, user: req.user, title: 'Page not found', tone: 'error',
    text: 'That page doesn’t exist.', links: [['/', 'Go home']],
  })));

  // Errors are logged privately and never shown to visitors, since stack traces
  // can reveal details about how the server works.
  // eslint-disable-next-line no-unused-vars
  app.use((err, req, res, next) => {
    if (err.type === 'entity.too.large' || err.type === 'parameters.too.many') {
      return res.status(413).send('Request too large');
    }
    console.error('[error]', err);
    res.status(500).send(views.message({
      csrf: req.csrf || '', title: 'Something went wrong', tone: 'error',
      text: 'An unexpected error happened. Please try again.', links: [['/', 'Go home']],
    }));
  });

  return app;
}

module.exports = { createApp };
