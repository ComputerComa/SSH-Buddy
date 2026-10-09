import assert from 'node:assert/strict';
import { start, open, step, finish, login, until } from './lib.mjs';

const PHASE = process.env.PHASE;                 // a: healthy + remove, b: re-enrollment requested + permit, c: healthy again
const FQDN = process.env.FQDN || 'web1.lab.test';
const CLIENT_IP = process.env.CLIENT_IP || '172.30.0.20';
const { page } = await start();
await login(page);
const rowOf = () => page.locator('tr', { hasText: FQDN });
const counter = id => page.locator('#' + id).innerText().then(s => s.trim());

if (PHASE === 'a') {
  await step('Machines page lists the enrolled container as healthy with the client address, agent version and revision', async () => {
    await open(page, '/machines');
    await rowOf().waitFor({ timeout: 8000 });
    const text = await rowOf().innerText();
    assert.match(text, /Healthy/);
    assert.ok(text.includes(CLIENT_IP), `IP column should show the client container ${CLIENT_IP}, not the proxy:\n${text}`);
    assert.match(text, /\b1\.0\.\d\b/);
    assert.match(text, /[0-9a-f]{12}/, 'key-list revision');
    assert.equal(await counter('count-healthy'), '1');
    assert.equal(await counter('count-error'), '0');
  });

  await step('Remove asks for confirmation and explains what it does and does not do; Cancel changes nothing', async () => {
    await rowOf().locator('button:has-text("Remove")').click();
    const box = page.locator('#remove-confirm');
    await box.waitFor({ timeout: 5000 });
    const t = await box.innerText();
    assert.match(t, /disables this machine's reporting credential/);
    assert.match(t, /does\s+not\s+revoke any SSH keys/i);
    assert.match(t, /already\s+present/);
    await page.click('button:has-text("Cancel")');
    await box.waitFor({ state: 'detached', timeout: 5000 });
    assert.match(await rowOf().innerText(), /Healthy/);
  });

  await step('confirming removal disables reporting: the machine moves to Removed and is hidden by default', async () => {
    await rowOf().locator('button:has-text("Remove")').click();
    await page.click('#remove-confirm-yes');
    await until(async () => (await counter('count-revoked')) === '1', 8000, 'removed counter');
    await page.locator('.alert-success', { hasText: 'reporting credential is disabled' }).waitFor({ timeout: 5000 });
    assert.equal(await rowOf().count(), 0);
    await page.check('#show-removed');
    await rowOf().waitFor({ timeout: 5000 });
    assert.match(await rowOf().innerText(), /Revoked/);
  });
}

if (PHASE === 'b') {
  await step('the rebuilt container\'s refused enrollment shows up as "re-enrollment requested" with its address', async () => {
    await until(async () => {
      await open(page, '/machines');
      await page.check('#show-removed');
      return (await rowOf().innerText()).includes('Re-enrollment requested');
    }, 90000, 're-enrollment requested flag');
    assert.ok((await rowOf().innerText()).includes(CLIENT_IP));
  });
  await step('Permit re-enrollment shows a time-limited permit', async () => {
    await rowOf().locator('button:has-text("Permit re-enrollment")').click();
    await page.locator('.alert-success', { hasText: 'may re-enroll once' }).waitFor({ timeout: 5000 });
    assert.match(await rowOf().innerText(), /Re-enrollment permitted until/);
  });
}

if (PHASE === 'c') {
  await step('after the permit the rebuilt machine is back: healthy, un-removed, permit consumed', async () => {
    await until(async () => {
      await open(page, '/machines');
      return (await rowOf().count()) > 0 && (await rowOf().innerText()).includes('Healthy');
    }, 120000, 'rebuilt machine healthy');
    const text = await rowOf().innerText();
    assert.doesNotMatch(text, /Re-enrollment/);
    assert.equal(await counter('count-healthy'), '1');
    assert.equal(await counter('count-revoked'), '0');
  });
  await step('the audit trail shows the whole story without secrets', async () => {
    await open(page, '/audit');
    const t = await page.locator('table').innerText();
    for (const a of ['MachineRegistered', 'MachineRevoked', 'MachineReenrollPermitted', 'MachineReenrolled'])
      assert.ok(t.includes(a), 'missing ' + a);
    assert.ok(!/sb[tm]_[A-Za-z0-9_-]{20,}/.test(await page.content()), 'a credential-looking string is present in the page');
  });
}

finish();
