import {
  CertificateAuthority,
  KEYCHAIN_SERVICE,
  KeyCert,
  createCA,
  createCert,
} from '../lib/index.mjs';
import {resetCreateSecureContext, whileCAtrusted} from '../lib/client.mjs';
import {AsyncEntry} from '@napi-rs/keyring';
import assert from 'node:assert';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import tls from 'node:tls';

const rootDir = await fs.mkdtemp(path.join(os.tmpdir(), 'cto-af-test-cert-'));
const certDir = path.join(rootDir, 'certs');
const caDir = path.join(rootDir, 'ca');
const logFile = path.join(rootDir, 'cert.log');
const ISSUER = '/CN=github.cto-af.ca';
test.after(async () => {
  assert.deepEqual(await fs.readdir(certDir), [], `${certDir} not empty`);
  assert.deepEqual(await fs.readdir(caDir), [], `${caDir} not empty`);
  for await (const {account} of KeyCert.listKeys()) {
    assert.doesNotMatch(account, new RegExp(`^${rootDir}`));
  }
  await fs.rm(rootDir, {recursive: true, force: true});
});

async function fromAsync(it) {
  const ret = [];
  for await (const i of it) {
    ret.push(i);
  }
  return ret;
}

test('createCert', async () => {
  assert(certDir);

  const opts = {
    certDir,
    caDir,
    notAfterDays: 3,
    logLevel: -10,
    logFile,
    caSubject: ISSUER,
  };

  await assert.rejects(() => createCert({...opts, host: []}));

  const kc = await createCert(opts);
  const {key, cert, chain, notAfter, ca, issuer, subject, san} = kc;
  assert(key);
  assert(cert);
  assert(notAfter);
  assert(ca);
  assert(san);
  assert.equal(chain, cert + ca.cert);

  assert.equal(ca.subject, ISSUER);
  assert.equal(subject, '/CN=localhost');
  assert.equal(issuer, ISSUER);

  const cached = await createCert(opts);
  assert.equal(key, cached.key);
  assert.equal(cert, cached.cert);
  assert.deepEqual(notAfter, cached.notAfter);
  assert.deepEqual(ca.cert, cached.ca.cert);
  assert.deepEqual(cached.san, [{dns: 'localhost'}, {ip: '127.0.0.1'}, {ip: '::1'}]);

  await cached.delete(opts);

  const ip = await createCert({...opts, host: '::1'});
  assert.deepEqual(ip.san, [{ip: '::1'}]);
  await ip.delete({...opts, host: '::1'});

  const multi = await createCert({...opts, host: ['127.0.0.1', 'localhost']});
  assert.deepEqual(multi.san, [{ip: '127.0.0.1'}, {dns: 'localhost'}]);
  await multi.delete({...opts, host: ['127.0.0.1', 'localhost']});

  // Check what happens when the CA subject is wrong.
  const ISSUER2 = `${ISSUER}2`;
  // eslint-disable-next-line require-atomic-updates
  opts.caSubject = ISSUER2;
  const cert2 = await createCert(opts);
  assert.equal(cert2.ca.subject, ISSUER2);
  assert.equal(cert2.issuer, ISSUER2);
  await cert2.delete();

  await fs.writeFile(path.join(certDir, 'localhost.cert.pem'), 'MANGLED CERT', 'utf8');
  await assert.rejects(() => createCert(opts));
  await fs.rm(path.join(certDir, 'localhost.cert.pem'));

  // Doesn't exist, create new
  await assert.doesNotReject(
    () => createCert(opts).then(kp => kp.delete(opts))
  );

  // Not long enough
  // eslint-disable-next-line require-atomic-updates
  opts.minRunDays = 7;
  await assert.doesNotReject(
    () => createCert(opts).then(kp => kp.delete(opts))
  );

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

  delete opts.log;
  opts.temp = true;
  const kct = await createCert(opts);
  assert(kct);

  const log = CertificateAuthority.logger(opts);
  await kct.delete(opts, log);
  await ca.delete(undefined, log);
  await cert2.ca.delete(null, log);
});

test('whileCAtrusted', async () => {
  const opts = {
    certDir,
    caDir,
    notAfterDays: 3,
    logLevel: -10,
    logFile,
    caSubject: ISSUER,
  };

  const kc = await createCert(opts);

  const whileRet = await whileCAtrusted(opts, () => tls.createSecureContext());
  assert(whileRet.context);

  const certRet = await whileCAtrusted(kc.ca.cert, () => 4);
  assert.equal(certRet, 4);

  await assert.rejects(async () => {
    await whileCAtrusted(opts, () => whileCAtrusted(opts, () => 5));
  }, /createSecureContext already hooked/);

  await kc.delete();
  await kc.ca.delete();

  await assert.rejects(
    () => whileCAtrusted({...opts, host: []}, () => Promise.resolve(4)),
    /Only single host allowed for CA subject, got 0/
  );

  assert.throws(() => resetCreateSecureContext(undefined));
  assert.throws(() => resetCreateSecureContext(Symbol('overrideCreateSecureContext')));
});

test('new API', async () => {
  assert.throws(() => new CertificateAuthority({host: []}));
  const ca = new CertificateAuthority({dir: caDir});
  const kp = await ca.init();
  const kp2 = await ca.init();
  assert.equal(kp, kp2);
  assert(kp.verify());

  const opts = {dir: certDir};
  const cert = await ca.issue(opts);
  assert(cert.verify());

  let certs = await fromAsync(ca.list({dir: certDir}));
  assert.equal(certs.length, 1);

  // Put old-style key file in place, so conversion happens.
  const kf = cert.keyFile;
  const cf = cert.certFile;

  assert(kf);
  assert(cf);

  await fs.writeFile(kf, cert.key);
  const e = new AsyncEntry(KEYCHAIN_SERVICE, kf);
  await e.deletePassword();

  const cert2 = await ca.issue(opts);
  assert.equal(cert2.serial, cert.serial);

  await fs.writeFile(kf, cert.key);
  const cert3 = await ca.issue({...opts, force: true});
  assert.notEqual(cert3.serial, cert.serial);

  // Delete the good key, and drop a directory where the old key would have
  // been, causing the file removal to fail.
  const ae = new AsyncEntry(KEYCHAIN_SERVICE, kf);
  await ae.deletePassword();
  await fs.mkdir(kf);
  await assert.rejects(() => ca.issue(opts));

  await assert.rejects(() => ca.issue({...opts, force: true}));

  certs = await fromAsync(CertificateAuthority.list(opts));
  assert.equal(certs.length, 1);

  certs = await fromAsync(CertificateAuthority.list({...opts, noKey: true}));
  assert.equal(certs.length, 1);

  const log = CertificateAuthority.logger(opts);
  await assert.rejects(() => cert3.delete(opts, log));
  await fs.rmdir(kf);

  const cert4 = await ca.issue({...opts, force: true});
  await fs.writeFile(kf, cert.key);
  await cert4.delete(opts, log);

  await ca.delete();

  // Temp certs
  const tempCA = new CertificateAuthority({
    dir: caDir,
    temp: true,
    notAfterDays: 0.5,
    host: ['/CN=temp-test'],
  });
  await tempCA.delete();
});

test('timing', async () => {
  const ca = new CertificateAuthority({dir: caDir, notAfterDays: 1});
  const kp = await ca.init();
  const ca2 = new CertificateAuthority({dir: caDir, notAfterDays: 1});
  const kp2 = await ca2.init();
  assert.notEqual(kp.serial, kp2.serial);

  const opts = {dir: certDir};
  const cert = await ca2.issue(opts);
  await ca2.delete(cert);
  await ca2.issue(opts);

  const keys = await fromAsync(KeyCert.listKeys(opts));
  assert(Array.isArray(keys));

  const ca3 = new CertificateAuthority({dir: caDir, notAfterDays: 1});
  const cert2 = await ca3.issue(opts);
  assert.notEqual(cert2.serial, cert.serial);
  await ca3.delete(opts); // Delete cert
  await ca3.delete();
});

test('issueNew', () => {
  const opts = {
    certDir,
    caDir,
    notAfterDays: 3,
    logLevel: -10,
    logFile,
    caSubject: ISSUER,
    temp: true,
  };
  const ca = new CertificateAuthority(opts);
  assert.doesNotThrow(() => ca.issueNew());

  const ca2 = new CertificateAuthority({...opts, temp: false});
  assert.throws(() => ca2.issueNew());
});
