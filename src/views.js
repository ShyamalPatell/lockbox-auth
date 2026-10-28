'use strict';

// Server-rendered HTML pages.
// The html`` tag below escapes EVERY value it inserts unless it is wrapped in
// raw(). So if someone signs up with a username like <script>alert(1)</script>
// it shows up as harmless text, never as code. That blocks XSS attacks.

const config = require('./config');
const { PASSWORD_MIN } = require('./security');

class Raw { constructor(s) { this.s = s; } toString() { return this.s; } }
const raw = (s) => new Raw(s);
const ESC = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;', '`': '&#96;' };
const esc = (v) => String(v).replace(/[&<>"'`]/g, (c) => ESC[c]);
function render(v) {
  if (v === null || v === undefined || v === false) return '';
  if (Array.isArray(v)) return v.map(render).join('');
  if (v instanceof Raw) return v.s;
  return esc(v);
}
function html(strings, ...values) {
  let out = strings[0];
  values.forEach((v, i) => { out += render(v) + strings[i + 1]; });
  return raw(out);
}

// ---------- building blocks ----------
function layout({ title, user, csrf, body, wide = false }) {
  const nav = user
    ? html`<span class="nav-user">@${user.username}</span>
        <form method="post" action="/logout" class="inline">${csrfField(csrf)}<button class="link-btn" type="submit">Log out</button></form>`
    : html`<a href="/login">Log in</a><a href="/signup" class="nav-cta">Create account</a>`;
  return `<!doctype html>${html`<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="referrer" content="no-referrer">
  <title>${title} · ${config.appName}</title>
  <link rel="stylesheet" href="/style.css">
  <link rel="icon" href="/favicon.svg" type="image/svg+xml">
  <script src="/app.js" defer></script>
</head>
<body>
  <header class="topbar">
    <a class="brand" href="/">${raw(LOCK_SVG)}<span>${config.appName}</span></a>
    <nav>${nav}</nav>
  </header>
  <main class="${wide ? 'wrap wide' : 'wrap'}">${body}</main>
  <footer class="foot">${config.appName} · built with security in mind</footer>
</body>
</html>`}`;
}

const LOCK_SVG = '<svg viewBox="0 0 24 24" width="22" height="22" aria-hidden="true"><rect x="4" y="10" width="16" height="11" rx="2.5" fill="currentColor"/><path d="M8 10V7a4 4 0 0 1 8 0v3" fill="none" stroke="currentColor" stroke-width="2.2"/></svg>';

const csrfField = (csrf) => html`<input type="hidden" name="_csrf" value="${csrf}">`;

function notice(type, text) {
  if (!text) return '';
  return html`<div class="notice notice-${type}" role="${type === 'error' ? 'alert' : 'status'}">${text}</div>`;
}

function field({ name, label, type = 'text', value = '', error, autocomplete, hint, extra = '' }) {
  const id = `f-${name}`;
  const isPw = type === 'password';
  return html`<div class="field${error ? ' has-error' : ''}">
    <label for="${id}">${label}</label>
    <div class="${isPw ? 'pw-wrap' : ''}">
      <input id="${id}" name="${name}" type="${type}" value="${isPw ? '' : value}"
        ${autocomplete ? raw(`autocomplete="${esc(autocomplete)}"`) : ''}
        ${error ? raw(`aria-invalid="true" aria-describedby="${id}-err"`) : ''}
        ${raw(extra)} required>
      ${isPw ? raw(`<button type="button" class="pw-toggle" data-toggle="${id}" aria-label="Show password">Show</button>`) : ''}
    </div>
    ${hint ? html`<p class="hint">${hint}</p>` : ''}
    ${error ? html`<p class="field-error" id="${id}-err">${error}</p>` : ''}
  </div>`;
}

function card(title, sub, inner) {
  return html`<section class="card">
    <h1>${title}</h1>
    ${sub ? html`<p class="sub">${sub}</p>` : ''}
    ${inner}
  </section>`;
}

const pwChecklist = html`<ul class="pw-rules" data-rules-for="f-password" aria-live="polite">
  <li data-rule="len">At least ${PASSWORD_MIN} characters</li>
  <li data-rule="special">At least one special character (! @ # $ % …)</li>
</ul>`;

// ---------- pages ----------
module.exports = {
  html, raw,

  home({ csrf }) {
    const body = html`
      <section class="hero">
        <p class="eyebrow">Secure accounts, done right</p>
        <h1>Your account, locked down.</h1>
        <p class="lede">Create an account, confirm your email, and log in. Every step is protected against the attacks real websites face.</p>
        <div class="cta-row">
          <a class="btn" href="/signup">Create an account</a>
          <a class="btn btn-ghost" href="/login">Log in</a>
        </div>
      </section>
      <section class="features">
        <h2>What’s protecting you</h2>
        <div class="grid">
          ${[
            ['Hashed passwords', 'Passwords are run through scrypt with a unique salt. The real password is never stored anywhere.'],
            ['Verified emails', 'You can’t log in until you click the link sent to your inbox.'],
            ['Unique usernames', 'The database itself rejects duplicates, so no one can claim a name that’s taken, not even with different capital letters.'],
            ['Brute-force lockout', `After ${config.maxFailedLogins} wrong passwords the account locks for ${config.lockoutMs / 60000} minutes, and each IP address is rate-limited.`],
            ['Safe sessions', 'Sessions live in secure, HttpOnly cookies, expire automatically, and are destroyed on logout.'],
            ['One-time links', 'Reset and verification links are random, single use, short-lived and stored only as hashes.'],
            ['CSRF & XSS defense', 'Every form carries a secret token, and a strict Content Security Policy blocks injected scripts.'],
            ['No account fishing', 'Password-reset and username-recovery pages give the same answer whether or not an email is registered.'],
          ].map(([t, d]) => html`<div class="feature"><h3>${t}</h3><p>${d}</p></div>`)}
        </div>
      </section>`;
    return layout({ title: 'Welcome', csrf, body, wide: true });
  },

  signup({ csrf, values = {}, errors = {} }) {
    const body = card('Create your account', 'It takes less than a minute.', html`
      ${notice('error', errors.form)}
      <form method="post" action="/signup" novalidate>
        ${csrfField(csrf)}
        ${field({ name: 'username', label: 'Username', value: values.username, error: errors.username, autocomplete: 'username', hint: '3–20 characters: letters, numbers, underscores.', extra: 'maxlength="20" autocapitalize="none" spellcheck="false"' })}
        ${field({ name: 'email', label: 'Email', type: 'email', value: values.email, error: errors.email, autocomplete: 'email', extra: 'maxlength="254"' })}
        ${field({ name: 'password', label: 'Password', type: 'password', error: errors.password, autocomplete: 'new-password', extra: 'maxlength="128"' })}
        ${pwChecklist}
        ${field({ name: 'confirm', label: 'Confirm password', type: 'password', error: errors.confirm, autocomplete: 'new-password', extra: 'maxlength="128" data-match="f-password"' })}
        <button class="btn btn-block" type="submit">Create account</button>
      </form>
      <p class="alt">Already have an account? <a href="/login">Log in</a></p>`);
    return layout({ title: 'Create account', csrf, body });
  },

  login({ csrf, values = {}, error, info, showResend = false }) {
    const body = card('Welcome back', 'Log in with your username or email.', html`
      ${notice('success', info)}
      ${notice('error', error)}
      ${showResend ? html`<p class="small">Didn’t get the email? <a href="/resend-verification">Send it again</a></p>` : ''}
      <form method="post" action="/login" novalidate>
        ${csrfField(csrf)}
        ${field({ name: 'identifier', label: 'Username or email', value: values.identifier, autocomplete: 'username', extra: 'maxlength="254" autocapitalize="none" spellcheck="false"' })}
        ${field({ name: 'password', label: 'Password', type: 'password', autocomplete: 'current-password', extra: 'maxlength="128"' })}
        <button class="btn btn-block" type="submit">Log in</button>
      </form>
      <div class="links-row">
        <a href="/forgot-password">Forgot password?</a>
        <a href="/forgot-username">Forgot username?</a>
      </div>
      <p class="alt">New here? <a href="/signup">Create an account</a></p>`);
    return layout({ title: 'Log in', csrf, body });
  },

  emailForm({ csrf, kind, values = {}, error }) {
    const copy = {
      'forgot-password': ['Reset your password', 'Enter the email on your account and we’ll send you a reset link.', 'Send reset link'],
      'forgot-username': ['Find your username', 'Enter the email on your account and we’ll email you your username.', 'Email my username'],
      'resend-verification': ['Resend confirmation email', 'Enter the email you signed up with and we’ll send a fresh confirmation link.', 'Resend email'],
    }[kind];
    const body = card(copy[0], copy[1], html`
      ${notice('error', error)}
      <form method="post" action="/${kind}" novalidate>
        ${csrfField(csrf)}
        ${field({ name: 'email', label: 'Email', type: 'email', value: values.email, autocomplete: 'email', extra: 'maxlength="254"' })}
        <button class="btn btn-block" type="submit">${copy[2]}</button>
      </form>
      <p class="alt"><a href="/login">Back to log in</a></p>`);
    return layout({ title: copy[0], csrf, body });
  },

  resetPassword({ csrf, token, errors = {} }) {
    const body = card('Choose a new password', 'After this, every device signed into your account will be logged out.', html`
      ${notice('error', errors.form)}
      <form method="post" action="/reset-password" novalidate>
        ${csrfField(csrf)}
        <input type="hidden" name="token" value="${token}">
        ${field({ name: 'password', label: 'New password', type: 'password', error: errors.password, autocomplete: 'new-password', extra: 'maxlength="128"' })}
        ${pwChecklist}
        ${field({ name: 'confirm', label: 'Confirm new password', type: 'password', error: errors.confirm, autocomplete: 'new-password', extra: 'maxlength="128" data-match="f-password"' })}
        <button class="btn btn-block" type="submit">Save new password</button>
      </form>`);
    return layout({ title: 'New password', csrf, body });
  },

  dashboard({ csrf, user, sessionCount }) {
    const joined = new Date(user.created_at).toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric', timeZone: 'UTC' });
    const body = card(`Hi, ${user.username} 👋`, 'You’re logged in. This page is only visible to you.', html`
      <dl class="details">
        <div><dt>Username</dt><dd>${user.username}</dd></div>
        <div><dt>Email</dt><dd>${user.email} <span class="badge">Verified</span></dd></div>
        <div><dt>Member since</dt><dd>${joined}</dd></div>
        <div><dt>Active sessions</dt><dd>${sessionCount}</dd></div>
      </dl>
      <div class="stack">
        <form method="post" action="/logout">${csrfField(csrf)}<button class="btn btn-block" type="submit">Log out</button></form>
        <form method="post" action="/logout-all">${csrfField(csrf)}<button class="btn btn-ghost btn-block" type="submit">Log out of all devices</button></form>
      </div>
      <p class="small center">For safety you’re logged out automatically after 1 hour of inactivity.</p>`);
    return layout({ title: 'Your account', user, csrf, body });
  },

  message({ csrf, user, title, text, tone = 'info', links = [] }) {
    const body = card(title, null, html`
      ${notice(tone, text)}
      ${links.length ? html`<div class="stack">${links.map(([href, label], i) => html`<a class="btn ${i ? 'btn-ghost' : ''} btn-block" href="${href}">${label}</a>`)}</div>` : ''}`);
    return layout({ title, user, csrf, body });
  },
};
