import fs from 'node:fs';
import { start, open, step, finish, login, until } from './lib.mjs';

const { page } = await start();
await login(page);
const label = process.env.LABEL;
const action = process.env.ACTION;
await open(page, '/keys');

if (action === 'add') {
  await step(`add ${label} through the UI`, async () => {
    await page.fill('#label', label);
    await page.fill('#pubkey', fs.readFileSync('/shared/test.pub', 'utf8'));
    await page.click('button:has-text("Add key")');
    await page.locator('tr', { hasText: label }).waitFor({ timeout: 8000 });
  });
} else {
  await step(`revoke ${label} through the UI`, async () => {
    await page.locator('tr', { hasText: label }).locator('button:has-text("Revoke")').click();
    await until(async () => (await page.locator('tr', { hasText: label }).innerText()).includes('Revoked'), 8000, 'revoked badge');
  });
}
finish();
