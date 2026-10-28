'use strict';

const crypto = require('node:crypto');
const { promisify } = require('node:util');

const scrypt = promisify(crypto.scrypt);

// ---------- Password hashing ----------
// Passwords are never stored. We store a scrypt hash: a slow, memory-hungry
// one-way function with a random salt per user. Even if someone stole the
// database they could not reverse it, and guessing is very expensive.
// These settings match OWASP's recommended scrypt parameters (N=2^15, r=8, p=3).
const SCRYPT = { N: 32768, r: 8, p: 3 };
const KEYLEN = 64;
const MAXMEM = 64 * 1024 * 1024;

async function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const key = await scrypt(password.normalize('NFKC'), salt, KEYLEN, { ...SCRYPT, maxmem: MAXMEM });
  return ['scrypt', SCRYPT.N, SCRYPT.r, SCRYPT.p, salt.toString('base64'), key.toString('base64')].join('$');
}

async function verifyPassword(password, stored) {
  const parts = String(stored).split('$');
  if (parts.length !== 6 || parts[0] !== 'scrypt') return false;
  const [, N, r, p, saltB64, keyB64] = parts;
  const expected = Buffer.from(keyB64, 'base64');
  const actual = await scrypt(password.normalize('NFKC'), Buffer.from(saltB64, 'base64'), expected.length, {
    N: Number(N), r: Number(r), p: Number(p), maxmem: MAXMEM,
  });
  // timingSafeEqual takes the same time whether the first byte or the last
  // byte is wrong, so attackers can't learn anything from response timing.
  return crypto.timingSafeEqual(actual, expected);
}

// When a login uses a username that doesn't exist, we still run one full hash
// check against this dummy. Otherwise "user doesn't exist" would answer
// noticeably faster, and attackers could use that to discover real usernames.
let dummyHashPromise = null;
function dummyHash() {
  if (!dummyHashPromise) dummyHashPromise = hashPassword(crypto.randomBytes(16).toString('hex'));
  return dummyHashPromise;
}
async function burnTime(password) {
  await verifyPassword(password || 'x', await dummyHash());
}

// ---------- Random tokens ----------
// 32 random bytes = 256 bits. Impossible to guess. We email the raw token and
// store only its SHA-256 hash, so a database leak doesn't leak usable links.
function randomToken() {
  return crypto.randomBytes(32).toString('base64url');
}
function hashToken(token) {
  return crypto.createHash('sha256').update(String(token)).digest('hex');
}
function newToken() {
  const token = randomToken();
  return { token, hash: hashToken(token) };
}
const TOKEN_RE = /^[A-Za-z0-9_-]{43}$/;
const isTokenShape = (t) => typeof t === 'string' && TOKEN_RE.test(t);

function safeEqual(a, b) {
  const ha = crypto.createHash('sha256').update(String(a)).digest();
  const hb = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(ha, hb);
}

// ---------- Validation ----------
const USERNAME_RE = /^[A-Za-z0-9_]{3,20}$/;
const RESERVED = new Set(['admin', 'administrator', 'root', 'support', 'help', 'system', 'moderator', 'staff', 'security', 'null', 'undefined']);
const EMAIL_RE = /^[^\s@<>()[\]\\,;:"]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}$/;
const SPECIAL_RE = /[^A-Za-z0-9\s]/;

const PASSWORD_MIN = 10;
const PASSWORD_MAX = 128;

function validateUsername(u) {
  if (!u) return 'Pick a username.';
  if (!USERNAME_RE.test(u)) return 'Usernames are 3–20 characters: letters, numbers and underscores only.';
  if (RESERVED.has(u.toLowerCase())) return 'That username is reserved. Try another.';
  return null;
}

function validateEmail(e) {
  if (!e) return 'Enter your email address.';
  if (e.length > 254 || !EMAIL_RE.test(e)) return 'That doesn’t look like a valid email address.';
  return null;
}

// Returns a list of everything wrong with the password (empty list = good).
function passwordProblems(pw, { username = '', email = '' } = {}) {
  const problems = [];
  if (pw.length < PASSWORD_MIN) problems.push(`Use at least ${PASSWORD_MIN} characters.`);
  if (pw.length > PASSWORD_MAX) problems.push(`Use at most ${PASSWORD_MAX} characters.`);
  if (!SPECIAL_RE.test(pw)) problems.push('Include at least one special character (like ! @ # $ % & *).');
  const lower = pw.toLowerCase();
  if (username && username.length >= 3 && lower.includes(username.toLowerCase())) problems.push('Don’t put your username in your password.');
  const local = email.split('@')[0] || '';
  if (local.length >= 4 && lower.includes(local.toLowerCase())) problems.push('Don’t put your email in your password.');
  return problems;
}

module.exports = {
  hashPassword, verifyPassword, burnTime,
  randomToken, hashToken, newToken, isTokenShape, safeEqual,
  validateUsername, validateEmail, passwordProblems,
  PASSWORD_MIN, PASSWORD_MAX,
};
