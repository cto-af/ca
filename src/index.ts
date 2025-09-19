import type {
  AnyKey,
  CertOptions,
  CommonCertLogOptions,
  CommonCertOptions,
  CtoCertOptions,
  RequiredCertOptions,
  RequiredCommonCertOptions,
} from './types.js';
import {KEYCHAIN_SERVICE, KeyCert, SELF_SIGNED, SecretEntry} from './cert.js';
import {LOG_OPTIONS_NAMES, type LogOptions, type Logger, childLogger} from '@cto.af/log';
import {nameSet, select} from '@cto.af/utils';
import {daysFromNow} from './utils.js';
import envPaths from 'env-paths';
import filenamify from 'filenamify';
import net from 'node:net';
import path from 'node:path';
import rs from 'jsrsasign';

const CA_SUBJECT = '/C=US/ST=Colorado/L=Denver/O=@cto.af/CN=cto-af-Root-CA';
const APP_NAME = '@cto.af/ca';
const {config} = envPaths(APP_NAME);

export type {
  AnyKey,
  CertOptions,
  CommonCertLogOptions,
  CommonCertOptions,
  CtoCertOptions,
  RequiredCertOptions as RequiredCtoCertOptions,
  RequiredCommonCertOptions,
  SecretEntry,
};
export {
  KEYCHAIN_SERVICE,
  KeyCert,
  SELF_SIGNED,
};

export const DEFAULT_CA_OPTIONS: RequiredCommonCertOptions = {
  dir: config,
  force: false,
  host: CA_SUBJECT,
  minRunDays: 1,
  noKey: false,
  notAfterDays: 365,
  temp: false,
};

export const DEFAULT_COMMON_CERT_OPTIONS: RequiredCommonCertOptions = {
  dir: '.cert',
  force: false,
  host: ['localhost', '127.0.0.1', '::1'],
  minRunDays: 1,
  noKey: false,
  notAfterDays: 7,
  temp: false,
};
export const COMMON_CERT_OPTIONS_NAMES = nameSet(DEFAULT_COMMON_CERT_OPTIONS);

export const DEFAULT_CERT_OPTIONS: RequiredCertOptions = {
  caSubject: CA_SUBJECT,
  caNotAfterDays: DEFAULT_CA_OPTIONS.notAfterDays,
  caMinRunDays: DEFAULT_CA_OPTIONS.minRunDays,
  minRunDays: 1,
  notAfterDays: 7,
  caDir: config,
  certDir: DEFAULT_COMMON_CERT_OPTIONS.dir,
  forceCA: false,
  forceCert: false,
  host: DEFAULT_COMMON_CERT_OPTIONS.host,
  noKey: false,
  temp: false,
};

function altNames(hosts: string[]): jsrsasign.GeneralName[] {
  return hosts.map(h => (
    net.isIP(h) ? {ip: h} : {dns: h}
  ));
}

/**
 * Extract CA options from mixed options.
 *
 * @param options Original options.
 * @returns Extracted CA options.
 */
export function getCAoptions(options: CertOptions = {}): CommonCertLogOptions {
  const [opts, logOpts] = select(
    options,
    DEFAULT_CERT_OPTIONS,
    LOG_OPTIONS_NAMES
  );

  return {
    dir: opts.caDir,
    host: opts.caSubject,
    minRunDays: opts.caMinRunDays,
    notAfterDays: opts.caNotAfterDays,
    force: opts.forceCA,
    noKey: opts.noKey,
    temp: opts.temp,
    ...logOpts,
  };
}

/**
 * Extract leaf certificate options from mixed options.
 *
 * @param options Original options.
 * @returns Extracted options.
 */
export function getIssueOptions(
  options: CertOptions = {}
): CommonCertLogOptions {
  const [opts] = select(
    options,
    DEFAULT_CERT_OPTIONS
  );

  return {
    dir: opts.certDir,
    host: opts.host,
    minRunDays: opts.minRunDays,
    notAfterDays: opts.notAfterDays,
    force: opts.forceCert,
    noKey: opts.noKey,
    temp: opts.temp,
  };
}

/**
 * Certificate Authority that does local storage, intended for testing on the
 * local machine.
 *
 * WARNING: Not intended for scale or actual security.  DO NOT deploy on the
 * Internet in the current form.
 */
export class CertificateAuthority {
  #log: Logger;
  #opts: RequiredCommonCertOptions;
  #pair: KeyCert | null = null;
  #subject: string;

  public constructor(options: CommonCertLogOptions = {}) {
    const [opts, logOpts] = select(
      options,
      DEFAULT_CA_OPTIONS,
      LOG_OPTIONS_NAMES
    );

    if (Array.isArray(opts.host)) {
      if (opts.host.length !== 1) {
        throw new TypeError(`Only single host allowed for CA subject, got ${opts.host.length}`);
      }
      [this.#subject] = opts.host;
    } else {
      this.#subject = opts.host;
    }

    this.#log = CertificateAuthority.logger(logOpts);
    this.#opts = opts;
  }

  /**
   * Create a child logger for the CA's use.
   *
   * @param logOpts Options for logging.
   * @returns Child logger.
   */
  public static logger(logOpts?: LogOptions): Logger {
    return childLogger(logOpts, {ns: 'ca'});
  }

  /**
   * List all of the CA certs.
   *
   * @param options Options, of which dir is the most important.
   * @yields Instantiated instances of CA KeyCert's.
   */
  public static async *list(
    options: CommonCertLogOptions
  ): AsyncGenerator<KeyCert> {
    const [opts, logOpts] = select(
      options,
      DEFAULT_CA_OPTIONS,
      LOG_OPTIONS_NAMES
    );
    const log = CertificateAuthority.logger(logOpts);
    yield *KeyCert.list(opts, log);
  }

  /**
   * Mostly-internal, for initialization.  Must be called before any substantive
   * work is done.
   *
   * @returns CA KeyCert.
   */
  public async init(): Promise<KeyCert> {
    if (this.#pair) {
      return this.#pair;
    }
    const now = new Date();
    const ca_file = filenamify(this.#subject);
    if (!this.#opts.force && !this.#opts.temp) {
      this.#pair = await KeyCert.read(
        this.#opts, ca_file, this.#log, SELF_SIGNED
      );
      if (this.#pair) {
        const na = this.#pair.notAfter;
        if (na.getTime() < daysFromNow(this.#opts.minRunDays, now).getTime()) {
          this.#log.warn(`Not enough CA run time: ${na}`);
          this.#pair = null;
        } else {
          return this.#pair;
        }
      }
    }
    const kc = this.#create(now);
    await kc.write(this.#opts, this.#log);

    if ((process.platform === 'darwin') && !this.#opts.temp) {
      this.#log.info(`
  To trust the new CA for OSX apps like Safari, try:
  sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain %s.cert.pem
  `, path.resolve(this.#opts.dir, ca_file));
    }
    return kc;
  }

  /**
   * Issue a certificate for use in an HTTPS server.  May read from existing
   * on-disk cert and in-keychain key.  Will generate a new cert if the old
   * one is no longer valid.
   *
   * @param options Options.
   * @returns Initialized KeyCert.
   */
  public async issue(options: CommonCertOptions = {}): Promise<KeyCert> {
    const [opts] = select(options, DEFAULT_COMMON_CERT_OPTIONS);
    this.#log.debug('Issue options: %o', opts);
    const ca = await this.init();

    const [host, hosts] = (typeof opts.host === 'string') ?
      [opts.host, [opts.host]] :
      [opts.host[0], opts.host];

    if (hosts.length < 1) {
      throw new Error('One or more hosts required');
    }

    const now = new Date();
    if (!opts.force && !opts.temp) {
      const pair = await KeyCert.read(opts, host, this.#log, ca);
      if (pair) {
        const oneDay = daysFromNow(opts.minRunDays, now);
        if (pair.notAfter.getTime() < oneDay.getTime()) {
          this.#log.warn('Not enough run time left on existing cert: %o < %o', pair.notAfter, oneDay);
        } else if (pair.issuer !== ca.subject) {
          this.#log.warn('Invalid CA subject "%s" != "%s".', pair.issuer, ca.subject);
        } else if (pair.notBefore.getTime() >= ca.notBefore.getTime()) {
          return pair; // Still valid.
        }
        this.#log.warn('CA no longer valid: %s < %s', pair.notBefore.toISOString(), ca.notBefore.toISOString());
      }
    }

    const kc = this.issueNew(options, now);
    await kc.write(opts, this.#log);
    return kc;
  }

  public issueNew(
    options: CommonCertOptions = {},
    now = new Date()
  ): KeyCert {
    const [opts] = select(options, DEFAULT_COMMON_CERT_OPTIONS);
    const [host, hosts] = (typeof opts.host === 'string') ?
      [opts.host, [opts.host]] :
      [opts.host[0], opts.host];

    let ca = this.#pair;
    if (!ca) {
      if (!this.#opts.temp) {
        throw new TypeError('Only call issueNew directly for temp CAs');
      }
      ca = this.#create(now);
    }

    this.#log.info('Creating cert for %o.', hosts);

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
      subject: {str: `/CN=${host}`},
      sbjpubkey: pub,
      ext: [
        {extname: 'basicConstraints', cA: false},
        {extname: 'keyUsage', critical: true, names: ['digitalSignature']},
        {extname: 'subjectAltName', array: altNames(hosts)},
        {extname: 'authorityKeyIdentifier', kid: ca.cert},
        {extname: 'subjectKeyIdentifier', kid: pub},
        {extname: 'extKeyUsage', array: ['serverAuth', 'clientAuth']},
      ],
      sigalg: 'SHA384withECDSA',
      cakey: ca.key,
    });
    return new KeyCert(host, prv, x.getPEM(), ca);
  }

  /**
   * Delete the CA certificate and key.
   */
  public async delete(): Promise<void>;

  /**
   * Delete the given certificate and key.
   */
  public async delete(cert: KeyCert): Promise<void>;

  /**
   * Delete the certificate pointed to by the options dir and host.
   *
   * @param options Options.
   */
  public async delete(options: CommonCertOptions): Promise<void>;
  public async delete(options?: KeyCert | CommonCertOptions): Promise<void> {
    if (options == null) {
      const kp = await this.init();
      await kp.delete(this.#opts, this.#log);
      return;
    }
    let kc: KeyCert | null = null;
    let opts: Required<CommonCertOptions> = {
      ...DEFAULT_COMMON_CERT_OPTIONS,
      noKey: true,
    };
    if (options instanceof KeyCert) {
      kc = options;
    } else {
      [opts] = select(options, opts);
      let {host} = opts;
      if (Array.isArray(host)) {
        [host] = host;
      }
      kc = await KeyCert.read(opts, host, this.#log);
    }
    await kc?.delete(opts, this.#log);
  }

  /**
   * List the certs in the local directory.
   *
   * @param options Options, of which dir is the most important.
   * @yields Already-read KeyCert instances.
   */
  public async *list(options: CommonCertLogOptions): AsyncGenerator<KeyCert> {
    const [opts] = select(options, DEFAULT_COMMON_CERT_OPTIONS);
    const ca = await this.init();
    yield *KeyCert.list(opts, this.#log, ca);
  }

  /**
   * Just the sync parts of init().
   *
   * @param now Current time.
   * @returns New CA KeyCert.
   */
  #create(now = new Date()): KeyCert {
    this.#log.info(`Creating new${this.#opts.temp ? ' temp' : ''} CA certificate`);
    // Create a self-signed CA cert
    const kp = rs.KEYUTIL.generateKeypair('EC', 'secp256r1');
    const prv = kp.prvKeyObj;
    const pub = kp.pubKeyObj;

    const recently = new Date(now.getTime() - 10000); // 10s ago.
    const oneYear = daysFromNow(this.#opts.notAfterDays, now);

    const ca_cert = new rs.KJUR.asn1.x509.Certificate({
      version: 3,
      serial: {int: now.getTime()},
      issuer: {str: this.#subject},
      notbefore: rs.datetozulu(recently, false, false),
      notafter: rs.datetozulu(oneYear, false, false),
      subject: {str: this.#subject},
      sbjpubkey: pub,
      ext: [
        {extname: 'basicConstraints', critical: true, cA: true, pathLen: 0},
        {extname: 'keyUsage', critical: true, names: ['digitalSignature', 'keyCertSign', 'cRLSign']},
        {extname: 'authorityKeyIdentifier', kid: pub},
        {extname: 'subjectKeyIdentifier', kid: pub},
        {extname: 'extKeyUsage', array: ['serverAuth', 'clientAuth']},
      ],
      sigalg: 'SHA256withECDSA',
      cakey: prv,
    });
    const kc = new KeyCert(this.#subject, prv, ca_cert, SELF_SIGNED);
    this.#pair = kc;
    return kc;
  }
}

/**
 * Read a valid CA cert, or create a new one, writing it.
 *
 * @param options Cert options.
 * @returns Private Key / Certificate for CA.
 */
export async function createCA(
  options: CertOptions = {}
): Promise<KeyCert> {
  const ca = new CertificateAuthority(getCAoptions(options));
  return ca.init();
}

/**
 * Create a CA-signed localhost certificate.
 *
 * @param options Certificate options.
 * @returns Cert and private key.
 */
export async function createCert(
  options: CertOptions = {}
): Promise<KeyCert> {
  const ca = new CertificateAuthority(getCAoptions(options));
  return ca.issue(getIssueOptions(options));
}
