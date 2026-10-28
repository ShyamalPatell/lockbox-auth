'use strict';

// Automated security tests. Run with:  npm test
// Each test plays the role of a user (or an attacker) against a real running server.

process.env.MAIL_PROVIDER = 'memory';
process.env.SQLITE_PATH = ':memory:';
// Set TEST_DATABASE_URL to run the same tests against PostgreSQL.
if (process.env.TEST_DATABASE_URL) process.env.DATABASE_URL = process.env.TEST_DATABASE_URL;
else delete process.env.DATABASE_URL;

const test = require('node:test');
const assert = require('node:assert/strict');
const db = require('../src/db');
const mail = require('../src/mailer');
const { createApp } = require('../src/app');

// ---------- helpers ----------
async function startServer() {
  const app = createApp();
  const server = await new Promise((resolve) => { const s = app.listen(0, () => resolve(s)); });
  return { base: `http://127.0.0.1:${server.address().port}`, close: () => new Promise((r) => server.close(r)) };
}

class Browser {
  constructor(base) { this.base = base; this.cookies = new Map(); }
  async request(method, path, form, headers = {}) {
    const h = { ...headers };
    if (this.cookies.size) h.cookie = [...this.cookies].map(([k, v]) => `${k}=${v}`).join('; ');
    let body;
    if (form) { body = new URLSearchParams(form).toString(); h['content-type'] = 'application/x-www-form-urlencoded'; }
    const res = await fetch(this.base + path, { method, headers: h, body, redirect: 'manual' });
    const setCookies = res.headers.getSetCookie();
    for (const c of setCookies) {
      const [pair] = c.split(';');
      const i = pair.indexOf('=');
      const k = pair.slice(0, i).trim(); const v = pair.slice(i + 1);
      if (!v || /Expires=Thu, 01 Jan 1970/i.test(c)) this.cookies.delete(k); else this.cookies.set(k, v);
    }
    return { status: res.status, text: await res.text(), location: res.headers.get('location'), setCookies };
  }
  get(path) { return this.request('GET', path); }
  async post(path, form = {}, headers) {
    if (!this.cookies.get('csrf')) await this.get('/login');
    return this.request('POST', path, { _csrf: this.cookies.get('csrf'), ...form }, headers);
  }
}

let counter = 0;
const unique = () => `user${Date.now().toString(36)}${counter++}`;
const GOOD_PW = 'Correct-Horse-42!';
const lastMailTo = (to) => [...mail.outbox].reverse().find((m) => m.to === to);
const linkIn = (m) => m.text.match(/https?:\/\/\S+/)[0].replace(/^https?:\/\/[^/]+/, '');

async function signupAndVerify(base, opts = {}) {
  const username = opts.username || unique();
  const email = opts.email || `${username}@example.com`;
  const b = new Browser(base);
  const r = await b.post('/signup', { username, email, password: GOOD_PW, confirm: GOOD_PW });
  assert.equal(r.status, 200, 'signup should succeed');
  const v = await b.get(linkIn(lastMailTo(email)));
  assert.equal(v.status, 200, 'verification should succeed');
  return { username, email, browser: b };
}

test.before(async () => { await db.init(); });

// ---------- tests ----------
test('full happy path: sign up, verify email, log in, see dashboard, log out', async () => {
  const s = await startServer();
  const b = new Browser(s.base);
  const username = unique();
  const email = `${username}@example.com`;

  const r1 = await b.post('/signup', { username, email, password: GOOD_PW, confirm: GOOD_PW });
  assert.equal(r1.status, 200);
  assert.match(r1.text, /Check your email/);

  const m = lastMailTo(email);
  assert.ok(m, 'verification email was sent');
  assert.match(m.subject, /Confirm/);

  const r2 = await b.get(linkIn(m));
  assert.match(r2.text, /Email confirmed/);

  const r3 = await b.post('/login', { identifier: username, password: GOOD_PW });
  assert.equal(r3.status, 303);
  assert.equal(r3.location, '/dashboard');
  const sessionCookie = r3.setCookies.find((c) => c.startsWith('sid='));
  assert.match(sessionCookie, /HttpOnly/i);
  assert.match(sessionCookie, /SameSite=Lax/i);

  const r4 = await b.get('/dashboard');
  assert.equal(r4.status, 200);
  assert.match(r4.text, new RegExp(username));

  const stolenCookie = b.cookies.get('sid');
  const r5 = await b.post('/logout');
  assert.equal(r5.status, 303);
  assert.equal((await b.get('/dashboard')).status, 303, 'dashboard redirects to login after logout');

  // Even if someone copied the old cookie, it no longer works: the session was destroyed on the server.
  const thief = new Browser(s.base);
  thief.cookies.set('sid', stolenCookie);
  assert.equal((await thief.get('/dashboard')).status, 303);
  await s.close();
});

test('can log in with email instead of username (any capitalization)', async () => {
  const s = await startServer();
  const { email } = await signupAndVerify(s.base);
  const b = new Browser(s.base);
  const r = await b.post('/login', { identifier: email.toUpperCase(), password: GOOD_PW });
  assert.equal(r.status, 303);
  await s.close();
});

test('usernames are unique, ignoring capital letters', async () => {
  const s = await startServer();
  const { username } = await signupAndVerify(s.base);
  const b = new Browser(s.base);
  for (const name of [username, username.toUpperCase()]) {
    const r = await b.post('/signup', { username: name, email: `${unique()}@example.com`, password: GOOD_PW, confirm: GOOD_PW });
    assert.equal(r.status, 409);
    assert.match(r.text, /already taken/);
  }
  const { n } = await db.get('SELECT COUNT(*) AS n FROM users WHERE username_lower = $1', [username.toLowerCase()]);
  assert.equal(Number(n), 1);
  await s.close();
});

test('two people racing for the same username at the same instant: only one wins', async () => {
  const s = await startServer();
  const name = unique();
  const attempts = await Promise.all([1, 2, 3, 4].map((i) =>
    new Browser(s.base).post('/signup', { username: name, email: `${name}${i}@example.com`, password: GOOD_PW, confirm: GOOD_PW })));
  assert.equal(attempts.filter((r) => r.status === 200).length, 1);
  assert.equal(attempts.filter((r) => r.status === 409).length, 3);
  await s.close();
});

test('an email already in use: page looks identical, the real owner is warned, no duplicate account', async () => {
  const s = await startServer();
  const { email, username } = await signupAndVerify(s.base);
  const b = new Browser(s.base);
  const r = await b.post('/signup', { username: unique(), email, password: GOOD_PW, confirm: GOOD_PW });
  assert.equal(r.status, 200);
  assert.match(r.text, /Check your email/);
  const m = lastMailTo(email);
  assert.match(m.subject, /Sign-up attempt/);
  assert.match(m.text, new RegExp(username));
  const { n } = await db.get('SELECT COUNT(*) AS n FROM users WHERE email_lower = $1', [email.toLowerCase()]);
  assert.equal(Number(n), 1);
  await s.close();
});

test('password rules: 10+ characters and a special character are required', async () => {
  const s = await startServer();
  const b = new Browser(s.base);
  const cases = [
    ['Short1!', /at least 10 characters/],
    ['longpassword123', /special character/],
    ['abcdefghi', /at least 10 characters.*special character/s],
  ];
  for (const [pw, re] of cases) {
    const r = await b.post('/signup', { username: unique(), email: `${unique()}@example.com`, password: pw, confirm: pw });
    assert.equal(r.status, 400, `password "${pw}" should be rejected`);
    assert.match(r.text, re);
  }
  const name = unique();
  const r = await b.post('/signup', { username: name, email: `${unique()}@example.com`, password: `${name}!!!!`, confirm: `${name}!!!!` });
  assert.equal(r.status, 400);
  assert.match(r.text, /username in your password/);

  const mismatch = await b.post('/signup', { username: unique(), email: `${unique()}@example.com`, password: GOOD_PW, confirm: GOOD_PW + 'x' });
  assert.equal(mismatch.status, 400);
  assert.match(mismatch.text, /don’t match/);
  await s.close();
});

test('bad usernames and emails are rejected', async () => {
  const s = await startServer();
  const b = new Browser(s.base);
  for (const username of ['ab', 'has space', 'a'.repeat(21), 'Admin', '<script>']) {
    const r = await b.post('/signup', { username, email: `${unique()}@example.com`, password: GOOD_PW, confirm: GOOD_PW });
    assert.equal(r.status, 400, `username "${username}"`);
  }
  for (const email of ['nope', 'a@b', 'x@y.c', '<x>@evil.com']) {
    const r = await b.post('/signup', { username: unique(), email, password: GOOD_PW, confirm: GOOD_PW });
    assert.equal(r.status, 400, `email "${email}"`);
  }
  await s.close();
});

test('cannot log in before confirming email', async () => {
  const s = await startServer();
  const b = new Browser(s.base);
  const username = unique();
  await b.post('/signup', { username, email: `${username}@example.com`, password: GOOD_PW, confirm: GOOD_PW });
  const r = await b.post('/login', { identifier: username, password: GOOD_PW });
  assert.equal(r.status, 403);
  assert.match(r.text, /confirm your email/);
  assert.equal(b.cookies.has('sid'), false);
  await s.close();
});

test('wrong password and unknown user give the exact same error', async () => {
  const s = await startServer();
  const { username } = await signupAndVerify(s.base);
  const b = new Browser(s.base);
  const wrongPw = await b.post('/login', { identifier: username, password: 'Wrong-Password-1!' });
  const noUser = await b.post('/login', { identifier: unique(), password: 'Wrong-Password-1!' });
  assert.equal(wrongPw.status, 401);
  assert.equal(noUser.status, 401);
  const errorOf = (t) => t.match(/<div class="notice notice-error"[^>]*>(.*?)<\/div>/s)[1];
  assert.equal(errorOf(wrongPw.text), errorOf(noUser.text));
  await s.close();
});

test('account locks after 5 wrong passwords, even the right password is refused during lockout', async () => {
  const s = await startServer();
  const { username } = await signupAndVerify(s.base);
  const b = new Browser(s.base);
  for (let i = 0; i < 5; i++) await b.post('/login', { identifier: username, password: `Wrong-guess-${i}!` });
  const r = await b.post('/login', { identifier: username, password: GOOD_PW });
  assert.equal(r.status, 401);
  // Simulate the 15 minutes passing:
  await db.run('UPDATE users SET locked_until = 0 WHERE username_lower = $1', [username.toLowerCase()]);
  assert.equal((await b.post('/login', { identifier: username, password: GOOD_PW })).status, 303);
  await s.close();
});

test('per-IP rate limiting kicks in on login', async () => {
  const s = await startServer();
  const b = new Browser(s.base);
  let last;
  for (let i = 0; i < 21; i++) last = await b.post('/login', { identifier: 'nobody', password: 'whatever!!1' });
  assert.equal(last.status, 429);
  await s.close();
});

test('CSRF: forms submitted without the secret token, or from another website, are blocked', async () => {
  const s = await startServer();
  const { username, browser } = await signupAndVerify(s.base);
  await browser.post('/login', { identifier: username, password: GOOD_PW });

  const noToken = await browser.request('POST', '/logout', {});
  assert.equal(noToken.status, 403);
  const wrongToken = await browser.request('POST', '/logout', { _csrf: 'A'.repeat(43) });
  assert.equal(wrongToken.status, 403);
  const evilSite = await browser.post('/logout', {}, { origin: 'https://evil.example' });
  assert.equal(evilSite.status, 403);
  const crossSite = await browser.post('/logout', {}, { 'sec-fetch-site': 'cross-site' });
  assert.equal(crossSite.status, 403);

  assert.equal((await browser.get('/dashboard')).status, 200, 'still logged in: the attacks did nothing');
  await s.close();
});

test('SQL injection and XSS attempts are harmless', async () => {
  const s = await startServer();
  const b = new Browser(s.base);
  const sqli = await b.post('/login', { identifier: "' OR '1'='1' --", password: "' OR '1'='1' --" });
  assert.equal(sqli.status, 401);
  const xss = await b.post('/login', { identifier: '<script>alert(1)</script>', password: 'x' });
  assert.ok(!xss.text.includes('<script>alert(1)</script>'));
  assert.ok(xss.text.includes('&lt;script&gt;alert(1)&lt;/script&gt;'));
  const { n } = await db.get('SELECT COUNT(*) AS n FROM users');
  assert.ok(Number(n) >= 0, 'users table still exists');
  await s.close();
});

test('weird form input (arrays, huge bodies) does not crash the server', async () => {
  const s = await startServer();
  const b = new Browser(s.base);
  await b.get('/signup');
  const body = `_csrf=${b.cookies.get('csrf')}&username=a&username=b&email=x@y.com&password=p&confirm=p`;
  const res = await fetch(`${s.base}/signup`, {
    method: 'POST', body,
    headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: `csrf=${b.cookies.get('csrf')}` },
  });
  assert.equal(res.status, 400);
  const huge = await b.post('/login', { identifier: 'x'.repeat(20000), password: 'y' });
  assert.equal(huge.status, 413);
  await s.close();
});

test('forged or tampered session cookies are ignored', async () => {
  const s = await startServer();
  const b = new Browser(s.base);
  b.cookies.set('sid', 'A'.repeat(43));
  assert.equal((await b.get('/dashboard')).status, 303);
  b.cookies.set('sid', "' OR 1=1 --");
  assert.equal((await b.get('/dashboard')).status, 303);
  await s.close();
});

test('forgot password: same answer for real and fake emails, link works once, old sessions die', async () => {
  const s = await startServer();
  const { username, email } = await signupAndVerify(s.base);
  const laptop = new Browser(s.base);
  await laptop.post('/login', { identifier: username, password: GOOD_PW });
  assert.equal((await laptop.get('/dashboard')).status, 200);

  const b = new Browser(s.base);
  const fakeEmail = `${unique()}@example.com`;
  const real = await b.post('/forgot-password', { email });
  const fake = await b.post('/forgot-password', { email: fakeEmail });
  assert.equal(real.status, fake.status);
  assert.equal(real.text.replace(email, 'E'), fake.text.replace(fakeEmail, 'E'));
  assert.equal(lastMailTo(fakeEmail), undefined, 'no email sent for unknown address');

  const link = linkIn(lastMailTo(email));
  assert.match(link, /^\/reset-password\?token=/);
  const token = new URLSearchParams(link.split('?')[1]).get('token');
  assert.equal((await b.get(link)).status, 200);

  const weak = await b.post('/reset-password', { token, password: 'short', confirm: 'short' });
  assert.equal(weak.status, 400);

  const NEW_PW = 'Brand-New-Pass-99#';
  const ok = await b.post('/reset-password', { token, password: NEW_PW, confirm: NEW_PW });
  assert.equal(ok.status, 200);
  assert.match(ok.text, /password has been changed/);
  assert.match(lastMailTo(email).subject, /password was changed/);

  assert.equal((await laptop.get('/dashboard')).status, 303, 'other devices were logged out');
  assert.equal((await b.post('/reset-password', { token, password: 'Another-Pass-77!', confirm: 'Another-Pass-77!' })).status, 400, 'link only works once');
  assert.equal((await b.post('/login', { identifier: username, password: GOOD_PW })).status, 401, 'old password no longer works');
  assert.equal((await b.post('/login', { identifier: username, password: NEW_PW })).status, 303, 'new password works');
  await s.close();
});

test('requesting a second reset link cancels the first one; expired links fail', async () => {
  const s = await startServer();
  const { email } = await signupAndVerify(s.base);
  const b = new Browser(s.base);
  await b.post('/forgot-password', { email });
  const first = linkIn(lastMailTo(email));
  await b.post('/forgot-password', { email });
  const second = linkIn(lastMailTo(email));
  assert.equal((await b.get(first)).status, 400);
  assert.equal((await b.get(second)).status, 200);
  await db.run('UPDATE tokens SET expires_at = 1');
  assert.equal((await b.get(second)).status, 400);
  await s.close();
});

test('forgot username emails the username, same answer for unknown emails', async () => {
  const s = await startServer();
  const { username, email } = await signupAndVerify(s.base);
  const b = new Browser(s.base);
  const r = await b.post('/forgot-username', { email: email.toUpperCase() });
  assert.equal(r.status, 200);
  const m = lastMailTo(email.toUpperCase());
  assert.match(m.text, new RegExp(`Your username is: ${username}`));
  const fake = await b.post('/forgot-username', { email: `${unique()}@example.com` });
  assert.equal(fake.status, 200);
  await s.close();
});

test('email forms are rate-limited per IP', async () => {
  const s = await startServer();
  const b = new Browser(s.base);
  let last;
  for (let i = 0; i < 6; i++) last = await b.post('/forgot-username', { email: `${unique()}@example.com` });
  assert.equal(last.status, 429);
  await s.close();
});

test('verification links work once; resend issues a fresh one', async () => {
  const s = await startServer();
  const b = new Browser(s.base);
  const username = unique();
  const email = `${username}@example.com`;
  await b.post('/signup', { username, email, password: GOOD_PW, confirm: GOOD_PW });
  const first = linkIn(lastMailTo(email));
  await b.post('/resend-verification', { email });
  const second = linkIn(lastMailTo(email));
  assert.notEqual(first, second);
  assert.equal((await b.get(first)).status, 400, 'old link was cancelled');
  assert.equal((await b.get(second)).status, 200);
  assert.equal((await b.get(second)).status, 400, 'link only works once');
  await s.close();
});

test('logout of all devices ends every session', async () => {
  const s = await startServer();
  const { username } = await signupAndVerify(s.base);
  const phone = new Browser(s.base);
  const laptop = new Browser(s.base);
  await phone.post('/login', { identifier: username, password: GOOD_PW });
  await laptop.post('/login', { identifier: username, password: GOOD_PW });
  assert.match((await laptop.get('/dashboard')).text, /Active sessions<\/dt><dd>2/);
  await laptop.post('/logout-all');
  assert.equal((await phone.get('/dashboard')).status, 303);
  assert.equal((await laptop.get('/dashboard')).status, 303);
  await s.close();
});

test('idle sessions expire', async () => {
  const s = await startServer();
  const { username, browser } = await signupAndVerify(s.base);
  await browser.post('/login', { identifier: username, password: GOOD_PW });
  await db.run('UPDATE sessions SET last_seen = 1');
  assert.equal((await browser.get('/dashboard')).status, 303);
  await s.close();
});

test('unverified accounts expire so nobody can squat a username forever', async () => {
  const s = await startServer();
  const b = new Browser(s.base);
  const username = unique();
  await b.post('/signup', { username, email: `${username}@example.com`, password: GOOD_PW, confirm: GOOD_PW });
  await db.run('UPDATE users SET created_at = 1 WHERE username_lower = $1', [username.toLowerCase()]);
  const r = await new Browser(s.base).post('/signup', { username, email: `other-${username}@example.com`, password: GOOD_PW, confirm: GOOD_PW });
  assert.equal(r.status, 200);
  await s.close();
});

test('passwords are stored as scrypt hashes, never as plain text', async () => {
  const s = await startServer();
  const { username } = await signupAndVerify(s.base);
  const row = await db.get('SELECT password_hash FROM users WHERE username_lower = $1', [username.toLowerCase()]);
  assert.match(row.password_hash, /^scrypt\$32768\$8\$3\$/);
  assert.ok(!row.password_hash.includes(GOOD_PW));
  const tok = await db.get('SELECT token_hash FROM tokens LIMIT 1');
  if (tok) assert.match(tok.token_hash, /^[0-9a-f]{64}$/, 'tokens stored as SHA-256 hashes');
  await s.close();
});

test('security headers are present', async () => {
  const s = await startServer();
  const res = await fetch(`${s.base}/login`);
  assert.match(res.headers.get('content-security-policy'), /script-src 'self'/);
  assert.match(res.headers.get('content-security-policy'), /frame-ancestors 'none'/);
  assert.equal(res.headers.get('x-content-type-options'), 'nosniff');
  assert.equal(res.headers.get('cache-control'), 'no-store');
  assert.equal(res.headers.get('x-powered-by'), null);
  await s.close();
});

test.after(async () => { await db.close(); });
