'use strict';

// All settings live here. Anything secret or deploy-specific comes from
// environment variables so nothing sensitive is ever committed to GitHub.

const isProd = process.env.NODE_ENV === 'production';
const port = Number(process.env.PORT) || 3000;

// The public URL of the site. Used to build links inside emails.
// We never build email links from the request's Host header, because an
// attacker could fake that header and make reset links point to their site.
// Render sets RENDER_EXTERNAL_URL automatically, so on Render this just works.
const appUrl = (
  process.env.APP_URL ||
  process.env.RENDER_EXTERNAL_URL ||
  `http://localhost:${port}`
).replace(/\/+$/, '');

const MINUTE = 60 * 1000;
const HOUR = 60 * MINUTE;

module.exports = {
  isProd,
  port,
  appUrl,
  appOrigin: new URL(appUrl).origin,
  appName: process.env.APP_NAME || 'Lockbox',

  // Behind Render's load balancer we must trust exactly one proxy hop so we
  // see the real visitor IP (for rate limiting) and know the request was HTTPS.
  trustProxy: process.env.TRUST_PROXY !== undefined
    ? Number(process.env.TRUST_PROXY)
    : (process.env.RENDER ? 1 : 0),

  // "__Host-" cookies can only be set over HTTPS, on path "/", with no domain.
  // Browsers enforce that, which blocks a whole class of cookie-injection tricks.
  // Plain localhost has no HTTPS, so we use normal names in development.
  cookieSecure: isProd,
  sessionCookie: isProd ? '__Host-sid' : 'sid',
  csrfCookie: isProd ? '__Host-csrf' : 'csrf',

  sessionIdleMs: 60 * MINUTE,        // logged out after 1 hour of no activity
  sessionAbsoluteMs: 12 * HOUR,      // logged out after 12 hours no matter what
  verifyTokenTtlMs: 24 * HOUR,       // email verification link lifetime
  resetTokenTtlMs: 30 * MINUTE,      // password reset link lifetime
  unverifiedAccountTtlMs: 24 * HOUR, // unverified accounts are deleted after this

  maxFailedLogins: 5,                // wrong passwords before the account locks
  lockoutMs: 15 * MINUTE,            // how long the lock lasts
};
