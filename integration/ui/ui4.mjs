import assert from 'node:assert/strict';
import { start, open, step, finish, login, until } from './lib.mjs';
const { page } = await start();
await login(page);
const row = () => page.locator('tr', { hasText: 'web1.lab.test' });
const MODE = process.env.MODE;
await step(`machine shows ${MODE}`, async () => {
  await until(async () => { await open(page, '/machines'); return (await row().innerText()).includes(MODE); }, MODE === 'Healthy' ? 120000 : 8000, MODE + ' badge');
  console.log('    ' + (await row().innerText()).replace(/\s+/g, ' ').slice(0, 140));
  console.log('    counters: healthy=' + (await page.locator('#count-healthy').innerText()) + ' stale=' + (await page.locator('#count-stale').innerText()));
});
finish();
