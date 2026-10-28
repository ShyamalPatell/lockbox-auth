'use strict';

const config = require('./config');
const db = require('./db');
const mail = require('./mailer');
const { createApp } = require('./app');

async function main() {
  await db.init();
  const app = createApp();

  // Clean out expired sessions, used links and stale unverified accounts every hour.
  setInterval(() => app.locals.cleanup().catch((e) => console.error('[cleanup]', e)), 60 * 60 * 1000).unref();

  if (config.isProd && mail.provider === 'console') {
    console.warn('[warning] No email provider configured. Emails will only be printed to the logs.');
  }
  if (config.isProd && db.kind === 'sqlite') {
    console.warn('[warning] No DATABASE_URL set. Using SQLite, which is wiped whenever a free Render server restarts.');
  }

  const server = app.listen(config.port, () => {
    console.log(`${config.appName} running at ${config.appUrl} (db: ${db.kind}, mail: ${mail.provider})`);
  });

  const shutdown = () => server.close(() => db.close().finally(() => process.exit(0)));
  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);
}

main().catch((err) => {
  console.error('Failed to start:', err);
  process.exit(1);
});
