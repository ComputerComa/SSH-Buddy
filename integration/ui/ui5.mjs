import assert from 'node:assert/strict';
import { start, open, step, finish, login, until } from './lib.mjs';

// A machine that is still running, with its credential file in place, is removed in the UI and later permitted.
// Nothing is done on the machine itself.
const PHASE = process.env.PHASE;                 // remove | requested | healthy
const { page } = await start();
await login(page);
const row = () => page.locator('tr', { hasText: 'web1.lab.test' });

if (PHASE === 'remove') {
  await step('remove the running machine in the UI', async () => {
    await open(page, '/machines');
    await row().locator('button:has-text("Remove")').click();
    await page.click('#remove-confirm-yes');
    await until(async () => (await page.locator('#count-revoked').innerText()).trim() === '1', 8000, 'removed counter');
  });
}
if (PHASE === 'requested') {
  await step('the still-running machine\'s own next run shows up as "re-enrollment requested"; permit it', async () => {
    await until(async () => {
      await open(page, '/machines');
      await page.check('#show-removed');
      return (await row().innerText()).includes('Re-enrollment requested');
    }, 150000, 're-enrollment requested');
    await row().locator('button:has-text("Permit re-enrollment")').click();
    await page.locator('.alert-success', { hasText: 'may re-enroll once' }).waitFor({ timeout: 5000 });
  });
}
if (PHASE === 'healthy') {
  await step('after the permit the machine is healthy again on its next run, with no action on the machine', async () => {
    await until(async () => {
      await open(page, '/machines');
      return (await row().count()) > 0 && (await row().innerText()).includes('Healthy');
    }, 150000, 'healthy again');
    const t = await row().innerText();
    assert.doesNotMatch(t, /Re-enrollment/);
    assert.equal((await page.locator('#count-revoked').innerText()).trim(), '0');
  });
}
finish();
