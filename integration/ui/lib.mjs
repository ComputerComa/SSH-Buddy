import { chromium } from 'playwright';
import assert from 'node:assert/strict';

export const BASE = 'https://keys.test';
export const results = [];

export async function start() {
  // ignoreHTTPSErrors only for this *test browser* (Chromium has no access to the container's CA store);
  // the agent/bootstrap under test verify TLS normally.
  const browser = await chromium.launch();
  const ctx = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1280, height: 900 } });
  const page = await ctx.newPage();
  page.state = { ws: false };
  page.on('websocket', () => (page.state.ws = true));
  page.on('pageerror', e => console.log('PAGE ERROR', e.message));
  return { browser, ctx, page };
}

/** Navigate and wait until the Blazor circuit is up, so button clicks hit interactive handlers. */
export async function open(page, path, { interactive = true } = {}) {
  page.state.ws = false;
  await page.goto(BASE + path, { waitUntil: 'networkidle' });
  if (interactive) {
    for (let i = 0; i < 100 && !page.state.ws; i++) await page.waitForTimeout(100);
    assert.ok(page.state.ws, 'Blazor circuit (websocket) did not start for ' + path);
    await page.waitForTimeout(600);
  }
}

export async function step(name, fn) {
  try {
    await fn();
    results.push([true, name]);
    console.log('PASS', name);
  } catch (e) {
    results.push([false, name]);
    console.log('FAIL', name, '\n    ', String(e.message).split('\n').slice(0, 4).join('\n     '));
  }
}

export function finish() {
  const failed = results.filter(r => !r[0]).length;
  console.log(`\n${results.length - failed}/${results.length} UI checks passed`);
  process.exit(failed ? 1 : 0);
}

export async function login(page) {
  await open(page, '/login', { interactive: false });
  await page.fill('#email', 'admin@test.example');
  await page.fill('#password', 'integration test passphrase');
  await Promise.all([page.waitForURL(u => !u.pathname.startsWith('/login')), page.click('button[type=submit]')]);
}

export async function until(fn, ms = 10000, label = 'condition') {
  const end = Date.now() + ms;
  let last;
  while (Date.now() < end) {
    try { const v = await fn(); if (v) return v; } catch (e) { last = e; }
    await new Promise(r => setTimeout(r, 200));
  }
  throw new Error('timed out waiting for ' + label + (last ? ': ' + last.message : ''));
}
