'use strict';

// Sends email through whichever provider is configured:
//   BREVO_API_KEY  -> Brevo HTTP API   (recommended for Render's free tier)
//   RESEND_API_KEY -> Resend HTTP API  (needs your own domain)
//   SMTP_HOST      -> any SMTP server  (Gmail etc. Blocked on Render free!)
//   nothing set    -> printed to the console (local development)
// Render's free plan blocks SMTP ports, which is why the default is an HTTP API.

const config = require('./config');

const provider = process.env.MAIL_PROVIDER ||
  (process.env.BREVO_API_KEY ? 'brevo'
    : process.env.RESEND_API_KEY ? 'resend'
      : process.env.SMTP_HOST ? 'smtp'
        : 'console');

const fromEmail = process.env.MAIL_FROM_EMAIL || 'no-reply@example.com';
const fromName = process.env.MAIL_FROM_NAME || config.appName;

const outbox = []; // used by the automated tests (MAIL_PROVIDER=memory)
let smtpTransport = null;

async function deliver({ to, subject, text, html }) {
  switch (provider) {
    case 'memory':
      outbox.push({ to, subject, text, html });
      return;

    case 'console':
      console.log(`\n----- EMAIL (not sent, no provider set) -----\nTo: ${to}\nSubject: ${subject}\n\n${text}\n---------------------------------------------\n`);
      return;

    case 'brevo': {
      const res = await fetch('https://api.brevo.com/v3/smtp/email', {
        method: 'POST',
        headers: { 'api-key': process.env.BREVO_API_KEY, 'content-type': 'application/json', accept: 'application/json' },
        body: JSON.stringify({
          sender: { name: fromName, email: fromEmail },
          to: [{ email: to }],
          subject, htmlContent: html, textContent: text,
        }),
      });
      if (!res.ok) throw new Error(`Brevo ${res.status}: ${(await res.text()).slice(0, 300)}`);
      return;
    }

    case 'resend': {
      const res = await fetch('https://api.resend.com/emails', {
        method: 'POST',
        headers: { authorization: `Bearer ${process.env.RESEND_API_KEY}`, 'content-type': 'application/json' },
        body: JSON.stringify({ from: `${fromName} <${fromEmail}>`, to: [to], subject, html, text }),
      });
      if (!res.ok) throw new Error(`Resend ${res.status}: ${(await res.text()).slice(0, 300)}`);
      return;
    }

    case 'smtp': {
      if (!smtpTransport) {
        const nodemailer = require('nodemailer');
        const port = Number(process.env.SMTP_PORT) || 587;
        smtpTransport = nodemailer.createTransport({
          host: process.env.SMTP_HOST,
          port,
          secure: port === 465,
          requireTLS: port !== 465,
          auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
        });
      }
      await smtpTransport.sendMail({ from: { name: fromName, address: fromEmail }, to, subject, text, html });
      return;
    }

    default:
      throw new Error(`Unknown MAIL_PROVIDER "${provider}"`);
  }
}

// Emails are sent in the background ("fire and forget"). This matters for
// security: if "forgot password" waited for the email to send, it would be
// slower for real accounts than fake ones, and an attacker could time it to
// find out which emails are registered.
function queue(message) {
  deliver(message).catch((err) => console.error(`[mail] failed to send "${message.subject}":`, err.message));
}

// ---------- Email templates ----------
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

function layout(heading, paragraphs, button) {
  const p = paragraphs.map((t) => `<p style="margin:0 0 16px;line-height:1.55;color:#33373d">${esc(t)}</p>`).join('');
  const b = button
    ? `<p style="margin:24px 0"><a href="${esc(button.url)}" style="background:#1f6f5c;color:#fff;text-decoration:none;padding:12px 20px;border-radius:8px;font-weight:600;display:inline-block">${esc(button.label)}</a></p>
       <p style="margin:0 0 16px;font-size:13px;color:#6b7078;line-height:1.5">Button not working? Paste this link into your browser:<br><span style="word-break:break-all">${esc(button.url)}</span></p>`
    : '';
  return `<!doctype html><html><body style="margin:0;background:#f3f1ec;padding:32px 16px;font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif">
  <div style="max-width:520px;margin:0 auto;background:#fff;border-radius:12px;padding:32px">
    <div style="font-weight:700;color:#1f6f5c;margin-bottom:20px">${esc(config.appName)}</div>
    <h1 style="font-size:20px;margin:0 0 16px;color:#16181b">${esc(heading)}</h1>${p}${b}
    <p style="margin:24px 0 0;font-size:12px;color:#8a8f96">If you didn’t expect this email, you can safely ignore it.</p>
  </div></body></html>`;
}

const text = (lines) => lines.filter(Boolean).join('\n\n');

const templates = {
  verify(username, url) {
    const lines = [`Hi ${username},`, `Confirm your email to finish creating your ${config.appName} account. This link works once and expires in 24 hours.`];
    return {
      subject: `Confirm your ${config.appName} account`,
      text: text([...lines, url]),
      html: layout('Confirm your email', lines, { label: 'Confirm email', url }),
    };
  },
  alreadyRegistered(username) {
    const lines = [`Someone just tried to create a new ${config.appName} account using this email address, but it already belongs to the account "${username}".`,
      'If that was you, just log in. If you forgot your password, use "Forgot password" on the login page.',
      'If it wasn’t you, no action is needed. Your account is safe.'];
    return {
      subject: `Sign-up attempt for your ${config.appName} email`,
      text: text([...lines, `${config.appUrl}/login`]),
      html: layout('You already have an account', lines, { label: 'Go to login', url: `${config.appUrl}/login` }),
    };
  },
  reset(username, url) {
    const lines = [`Hi ${username},`, 'We got a request to reset your password. This link works once and expires in 30 minutes.', 'If you didn’t ask for this, ignore this email. Your password will not change.'];
    return {
      subject: `Reset your ${config.appName} password`,
      text: text([...lines, url]),
      html: layout('Reset your password', lines, { label: 'Choose a new password', url }),
    };
  },
  passwordChanged(username) {
    const lines = [`Hi ${username},`, 'Your password was just changed and every device was logged out.', 'If you didn’t do this, reset your password right away using "Forgot password" on the login page.'];
    return {
      subject: `Your ${config.appName} password was changed`,
      text: text(lines),
      html: layout('Your password was changed', lines, { label: 'Go to login', url: `${config.appUrl}/login` }),
    };
  },
  username(username) {
    const lines = [`You asked for the username linked to this email address.`, `Your username is: ${username}`];
    return {
      subject: `Your ${config.appName} username`,
      text: text([...lines, `${config.appUrl}/login`]),
      html: layout('Here’s your username', lines, { label: 'Log in', url: `${config.appUrl}/login` }),
    };
  },
};

function send(to, templateName, ...args) {
  queue({ to, ...templates[templateName](...args) });
}

module.exports = { send, outbox, provider };
