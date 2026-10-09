import fs from 'node:fs';
import assert from 'node:assert/strict';
import { start, open, step, finish, login, until, BASE } from './lib.mjs';

const { page, ctx } = await start();
const KEY = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMgXTvJTR9gazAPocNC4rL8cutrwxP4HUcSYPQAmkdoc ui-test';
const KEY_OTHER_COMMENT = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMgXTvJTR9gazAPocNC4rL8cutrwxP4HUcSYPQAmkdoc a-different-comment';
const list = async () => (await page.request.get(BASE + '/api/authorized-keys')).text();

await step('anonymous visitor is sent to the login page for every management page', async () => {
  for (const p of ['/keys', '/machines', '/templates', '/audit', '/enroll']) {
    await page.goto(BASE + p, { waitUntil: 'networkidle' });
    assert.match(page.url(), /\/login/, p);
  }
});

await step('wrong password is refused', async () => {
  await open(page, '/login', { interactive: false });
  await page.fill('#email', 'admin@test.example');
  await page.fill('#password', 'definitely wrong password');
  await page.click('button[type=submit]');
  await page.waitForURL(/error=invalid/);
  assert.ok(await page.locator('.alert-danger').isVisible());
});

await step('login with the CLI-created administrator', async () => {
  await login(page);
  await open(page, '/keys');
  assert.ok(await page.locator('h1', { hasText: 'Approved SSH keys' }).isVisible());
  const cookies = await ctx.cookies();
  const auth = cookies.find(c => c.name === 'SshBuddy.Auth');
  assert.ok(auth && auth.secure && auth.httpOnly, 'auth cookie must be Secure and HttpOnly');
});

await step('adding a valid key shows it with algorithm and SHA256 fingerprint', async () => {
  await page.fill('#label', 'ui-laptop');
  await page.fill('#pubkey', KEY);
  await page.click('button:has-text("Add key")');
  const row = page.locator('tr', { hasText: 'ui-laptop' });
  await row.waitFor({ timeout: 8000 });
  assert.match(await row.innerText(), /ssh-ed25519/);
  assert.match(await row.innerText(), /SHA256:gZDwIlFyJUsv3SZrSLW/);
  assert.match(await row.innerText(), /Active/);
  assert.match(await list(), /AAAAC3NzaC1lZDI1NTE5AAAAIMgXTvJTR9gazAPocNC4rL8cutrwxP4HUcSYPQAmkdoc ui-laptop/);
});

await step('the same key under a different comment is rejected as a duplicate', async () => {
  await page.fill('#label', 'dupe');
  await page.fill('#pubkey', KEY_OTHER_COMMENT);
  await page.click('button:has-text("Add key")');
  await page.locator('.alert-danger', { hasText: 'already registered' }).waitFor({ timeout: 8000 });
  assert.equal(await page.locator('tr', { hasText: 'dupe' }).count(), 0);
});

await step('a private key is rejected', async () => {
  await page.fill('#label', 'oops');
  await page.fill('#pubkey', '-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmU=\n-----END OPENSSH PRIVATE KEY-----');
  await page.click('button:has-text("Add key")');
  await page.locator('.alert-danger', { hasText: 'private key' }).waitFor({ timeout: 8000 });
});

await step('an authorized_keys option line is rejected', async () => {
  await page.fill('#label', 'opts');
  await page.fill('#pubkey', 'command="/bin/evil" ' + KEY);
  await page.click('button:has-text("Add key")');
  await page.locator('.alert-danger').waitFor({ timeout: 8000 });
  assert.equal(await page.locator('tr', { hasText: 'opts' }).count(), 0);
});

await step('revoking removes the key from the distributed list, reactivating restores it', async () => {
  await page.locator('tr', { hasText: 'ui-laptop' }).locator('button:has-text("Revoke")').click();
  await until(async () => (await page.locator('tr', { hasText: 'ui-laptop' }).innerText()).includes('Revoked'), 8000, 'revoked badge');
  assert.doesNotMatch(await list(), /ui-laptop/);
  await page.locator('tr', { hasText: 'ui-laptop' }).locator('button:has-text("Reactivate")').click();
  await until(async () => (await page.locator('tr', { hasText: 'ui-laptop' }).innerText()).includes('Active'), 8000, 'active badge');
  assert.match(await list(), /ui-laptop/);
});

await step('single-use key enrollment page produces a ready-to-copy curl command', async () => {
  await open(page, '/enroll');
  await page.click('button:has-text("Generate enrollment token")');
  const cmd = await page.locator('textarea').first().inputValue();
  assert.match(cmd, /^curl .*--header "Authorization: Bearer sbe_/);
  assert.match(cmd, /https:\/\/keys\.test\/api\/keys\/enroll/);
  assert.doesNotMatch(cmd, /\?token=/);
});

let rawToken;
await step('creating a template credential shows the raw value exactly once', async () => {
  await open(page, '/templates');
  await page.fill('#tpl-name', 'integration-template');
  await page.click('button:has-text("Create credential")');
  const box = page.locator('#created-credential textarea');
  await box.waitFor({ timeout: 8000 });
  rawToken = (await box.inputValue()).trim();
  assert.match(rawToken, /^sbt_[A-Za-z0-9_-]{40,}$/);
  fs.writeFileSync('/shared/template-token', rawToken);

  await open(page, '/templates');      // reload: the secret must be gone
  assert.equal(await page.locator('#created-credential').count(), 0);
  assert.ok(!(await page.content()).includes(rawToken), 'raw credential is still in the page after reload');
  const row = page.locator('tr', { hasText: 'integration-template' });
  assert.match(await row.innerText(), /Active/);
});

await step('the audit trail records key and credential events without any secret', async () => {
  await open(page, '/audit');
  const text = await page.locator('table').innerText();
  for (const a of ['KeyAdded', 'KeyRevoked', 'KeyReactivated', 'TemplateCredentialCreated', 'EnrollmentTokenCreated'])
    assert.ok(text.includes(a), 'missing ' + a);
  assert.ok(!(await page.content()).includes(rawToken));
});

await step('Machines page starts empty and links to template credentials', async () => {
  await open(page, '/machines');
  assert.match(await page.locator('table').innerText(), /No machines have registered yet/);
  assert.equal((await page.locator('#count-healthy').innerText()).trim(), '0');
});

await step('sign out ends the session', async () => {
  await page.click('button:has-text("Sign out")');
  await page.waitForURL(/\/login/);
  await page.goto(BASE + '/keys', { waitUntil: 'networkidle' });
  assert.match(page.url(), /\/login/);
});

finish();
