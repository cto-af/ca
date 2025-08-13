import {createCA, createCert} from '../lib/index.js';
import assert from 'node:assert';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

const certDir = await fs.mkdtemp(path.join(os.tmpdir(), 'cto-af-test-cert-'));
const ISSUER = '/CN=github.cto-af.ca';
test.after(async () => {
  await fs.rm(certDir, {recursive: true, force: true});
});

test('createCert', async () => {
  assert(certDir);

  const opts = {
    certDir,
    caDir: certDir,
    notAfterDays: 3,
    logLevel: -10,
    logFile: path.join(certDir, 'cert.log'),
    caSubject: ISSUER,
  };

  const kc = await createCert(opts);
  const {key, cert, notAfter, ca, issuer, subject} = kc;
  assert(key);
  assert(cert);
  assert(notAfter);
  assert(ca);

  assert.equal(ca.subject, ISSUER);
  assert.equal(subject, '/CN=localhost');
  assert.equal(issuer, ISSUER);

  const cached = await createCert(opts);
  assert.equal(key, cached.key);
  assert.equal(cert, cached.cert);
  assert.deepEqual(notAfter, cached.notAfter);
  assert.deepEqual(ca.cert, cached.ca.cert);
  assert.deepEqual(cached.san, [{dns: 'localhost'}]);

  const ip = await createCert({...opts, host: '::1'});
  assert.deepEqual(ip.san, [{ip: '::1'}]);

  // Check what happens when the CA subject is wrong.
  const ISSUER2 = `${ISSUER}2`;
  // eslint-disable-next-line require-atomic-updates
  opts.caSubject = ISSUER2;
  const cert2 = await createCert(opts);
  assert.equal(cert2.ca.subject, ISSUER2);
  assert.equal(cert2.issuer, ISSUER2);

  await fs.writeFile(path.join(certDir, 'localhost.cert.pem'), 'MANGLED CERT', 'utf8');
  await assert.rejects(() => createCert(opts));

  // Doesn't exist, create new
  await fs.rm(path.join(certDir, 'localhost.cert.pem'));
  await assert.doesNotReject(() => createCert(opts));

  // Not long enough
  // eslint-disable-next-line require-atomic-updates
  opts.minRunDays = 7;
  await assert.doesNotReject(() => createCert(opts));

  const caNoKey = await createCA({
    ...opts,
    noKey: true,
  });

  assert.equal(caNoKey.key, undefined);
  await assert.rejects(() => createCert({
    ...opts,
    noKey: true,
    forceCert: true,
  }));

  await kc.delete(opts);
  // eslint-disable-next-line require-atomic-updates
  opts.log = {
    warn() {
      // No-op
    },
  };
  await kc.ca.delete(opts);
});
