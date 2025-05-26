import type {AnyKey, CertOptions, RequiredCertOptions} from './types.js';
import {type Logger, createLog} from '@cto.af/log';
import {KeyCert} from './cert.js';
import {daysFromNow} from './utils.js';
import envPaths from 'env-paths';
import filenamify from 'filenamify';
import path from 'node:path';
import rs from 'jsrsasign';

const CA_SUBJECT = '/C=US/ST=Colorado/L=Denver/O=@cto.af/CN=cto-af-Root-CA';
const APP_NAME = '@cto.af/ca';
const {config} = envPaths(APP_NAME);

export type {
  AnyKey,
  CertOptions,
  RequiredCertOptions,
};
export {
  KeyCert,
};

export const DEFAULT_CERT_OPTIONS: RequiredCertOptions = {
  caSubject: CA_SUBJECT,
  minRunDays: 1,
  notAfterDays: 7,
  caDir: config,
  certDir: '.cert',
  forceCA: false,
  forceCert: false,
  host: 'localhost',
  logLevel: 0,
  logFile: null,
  log: null,
  noKey: false,
};

function setLog(opts: CertOptions): Logger {
  opts.log ??= createLog({
    logLevel: opts.logLevel,
    logFile: opts.logFile,
  });
  return opts.log;
}

/**
 * Read a valid CA cert, or create a new one, writing it.
 *
 * @param options Cert options.
 * @returns Private Key / Certificate for CA.
 */
export async function createCA(options: CertOptions): Promise<KeyCert> {
  const opts: RequiredCertOptions = {
    ...DEFAULT_CERT_OPTIONS,
    ...options,
  };
  const log = setLog(opts);
  opts.certDir = opts.caDir;

  const ca_file = filenamify(opts.caSubject);
  if (!opts.forceCA) {
    const pair = await KeyCert.read(opts, ca_file);
    if (pair) {
      return pair; // Still valid.
    }
  }

  log.info('Creating new CA certificate');
  // Create a self-signed CA cert
  const kp = rs.KEYUTIL.generateKeypair('EC', 'secp256r1');
  const prv = kp.prvKeyObj;
  const pub = kp.pubKeyObj;

  const now = new Date();
  const recently = new Date(now.getTime() - 10000); // 10s ago.
  const oneYear = daysFromNow(365, now);

  const ca_cert = new rs.KJUR.asn1.x509.Certificate({
    version: 3,
    serial: {int: now.getTime()},
    issuer: {str: opts.caSubject},
    notbefore: rs.datetozulu(recently, false, false),
    notafter: rs.datetozulu(oneYear, false, false),
    subject: {str: opts.caSubject},
    sbjpubkey: pub,
    ext: [
      {extname: 'basicConstraints', cA: true},
    ],
    sigalg: 'SHA256withECDSA',
    cakey: prv,
  });
  const kc = new KeyCert(opts.caSubject, prv, ca_cert);
  await kc.write(opts);

  if (process.platform === 'darwin') {
    log.info(`
To trust the new CA for OSX apps like Safari, try:
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain %s.cert.pem
`, path.resolve(opts.caDir, ca_file));
  }
  return kc;
}

/**
 * Create a CA-signed localhost certificate.
 *
 * @param options Certificate options.
 * @returns Cert and private key.
 */
export async function createCert(
  options: CertOptions
): Promise<KeyCert> {
  const opts: RequiredCertOptions = {
    ...DEFAULT_CERT_OPTIONS,
    ...options,
  };
  const log = setLog(opts);

  const ca = await createCA(opts);
  if (!opts.forceCert) {
    const pair = await KeyCert.read(opts, opts.host, ca);
    if (pair) {
      if (pair.issuer !== ca.subject) {
        log.warn('Invalid CA subject "%s" != "%s".', pair.issuer, ca.subject);
      } else if (pair.notBefore.getTime() >= ca.notBefore.getTime()) {
        return pair; // Still valid.
      }
      log.warn('CA no longer valid: %s < %s', pair.notBefore.toISOString(), ca.notBefore.toISOString());
    }
  }

  log.info('Creating cert for "%s".', opts.host);

  const now = new Date();
  const recently = new Date(now.getTime() - 10000); // 10s ago.
  const nextWeek = daysFromNow(opts.notAfterDays, now);

  const kp = rs.KEYUTIL.generateKeypair('EC', 'secp256r1');
  const prv = kp.prvKeyObj;
  const pub = kp.pubKeyObj;

  if (!ca.key) {
    throw new Error('Key required');
  }

  const x = new rs.KJUR.asn1.x509.Certificate({
    version: 3,
    serial: {int: now.getTime()},
    issuer: {str: ca.subject},
    notbefore: rs.datetozulu(recently, true, false),
    notafter: rs.datetozulu(nextWeek, true, false),
    subject: {str: `/CN=${opts.host}`},
    sbjpubkey: pub,
    ext: [
      {extname: 'basicConstraints', cA: false},
      {extname: 'keyUsage', critical: true, names: ['digitalSignature']},
      {extname: 'subjectAltName', array: [{dns: opts.host}]},
    ],
    sigalg: 'SHA256withECDSA',
    cakey: ca.key,
  });

  const kc = new KeyCert(opts.host, prv, x.getPEM(), ca);
  await kc.write(opts);
  return kc;
}
