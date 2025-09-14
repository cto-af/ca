import {
  AnyKey,
  KeyCertNames,
  RequiredCommonCertOptions,
} from './types.js';
import {type SecretEntry, deleteSecret, getSecret, listSecrets, setSecret} from './keychain.js';
import type {Logger} from '@cto.af/log';
import assert from 'node:assert';
import {errCode} from '@cto.af/utils';
import filenamify from 'filenamify';
import fs from 'node:fs/promises';
import path from 'node:path';
import rs from 'jsrsasign';

export const KEYCHAIN_SERVICE = 'com.github.cto-af.ca';
export const SELF_SIGNED = Symbol('SELF_SIGNED');

export type {
  SecretEntry,
};

/**
 * A certificate and its private key.
 */
export class KeyCert {
  public readonly ca: KeyCert | undefined;
  public readonly cert: string;
  public readonly key: string | undefined = undefined;
  public readonly name: string;
  #keyFile: string | undefined = undefined;
  #certFile: string | undefined = undefined;
  #x509: rs.X509;

  public constructor(
    name: string,
    key: AnyKey | string | undefined,
    cert: rs.KJUR.asn1.x509.Certificate | string,
    ca?: KeyCert | typeof SELF_SIGNED
  ) {
    this.name = name;
    if (key) {
      this.key = (typeof key === 'string') ?
        key :
        rs.KEYUTIL.getPEM(key, 'PKCS8PRV');
    }
    this.cert = (typeof cert === 'string') ? cert : cert.getPEM();
    this.#x509 = new rs.X509();
    this.#x509.readCertPEM(this.cert);
    this.ca = (ca === SELF_SIGNED) ? this : ca;
  }

  /**
   * The account name of the key, stored under KEYCHAIN_SERVICE in the
   * OS-specific keychain.  This corresponds to the file name that the key
   * used to be stored in.  This file should no longer exist after the upgrade
   * procedure runs.
   *
   * @returns If known, the filename, otherwise undefined.
   */
  public get keyFile(): string | undefined {
    return this.#keyFile;
  }

  /**
   * The file name of the certificate.  The file is encoded as PEM.
   *
   * @returns The filename, or undefined if unknown.
   */
  public get certFile(): string | undefined {
    return this.#certFile;
  }

  /**
   * Issuer DN string.
   *
   * @returns A string of the form '/C=US'.
   */
  public get issuer(): string {
    return this.#x509.getIssuerString();
  }

  /**
   * Certificate not valid after this date.
   *
   * @returns Date constructed from X509.
   */
  public get notAfter(): Date {
    return rs.zulutodate(this.#x509.getNotAfter());
  }

  /**
   * Certificate not valid before this date.
   *
   * @returns Date constructed from X509.
   */
  public get notBefore(): Date {
    return rs.zulutodate(this.#x509.getNotBefore());
  }

  /**
   * List of subjectAlternativeNames for the cert.
   *
   * @returns Array of {dns: 'hostname'} or {ip: 'address'} objects.
   */
  public get san(): rs.GeneralName[] | undefined {
    return this.#x509.getExtSubjectAltName()?.array;
  }

  /**
   * Serial number of the cert.
   *
   * @returns Hex string.
   */
  public get serial(): string {
    return this.#x509.getSerialNumberHex();
  }

  /**
   * Subject name of the cert.
   *
   * @returns String of the form '/CN=localhost'.
   */
  public get subject(): string {
    return this.#x509.getSubjectString();
  }

  /**
   * Read the cert file and the key from the keychain.
   *
   * @param opts Options.  Most important is dir.
   * @param name Base name of the files, escaped for use as filenames.
   *   No suffix or directory.
   * @param log Logger.
   * @param ca If known, the CA.  Use SELF_SIGNED for the CA.
   * @returns KeyCert, or null if not found.
   */
  public static async read(
    opts: RequiredCommonCertOptions,
    name: string,
    log: Logger,
    ca?: KeyCert | typeof SELF_SIGNED
  ): Promise<KeyCert | null> {
    try {
      const names = this.#getNames(opts, name);
      const cert = await fs.readFile(names.certName, 'utf8');
      const key = opts.noKey ?
        undefined :
        await getSecret(log, KEYCHAIN_SERVICE, names.keyName);
      const kc = new KeyCert(name, key, cert, ca);
      kc.#keyFile = names.keyName;
      kc.#certFile = names.certName;
      return kc;
    } catch (e) {
      if (errCode(e, 'ENOENT')) {
        return null;
      }
      throw e;
    }
  }

  /**
   * Get all known certs in the given directory.
   *
   * @param opts Options, most important is dir.
   * @param log Logger.
   * @param ca If known, the CA, or SELF_SIGNED for CAs.
   * @yields Already-read KeyCert instances.
   */
  public static async *list(
    opts: RequiredCommonCertOptions,
    log: Logger,
    ca?: KeyCert | typeof SELF_SIGNED
  ): AsyncGenerator<KeyCert> {
    const certDir = path.resolve(process.cwd(), opts.dir);
    for (const f of await fs.readdir(certDir)) {
      if (f.endsWith('.cert.pem')) {
        const name = f.slice(0, -9);
        const certFile = path.join(certDir, f);
        const keyFile = path.join(certDir, `${name}.key.pem`);

        const cert = await fs.readFile(certFile, 'utf8');
        const key = opts.noKey ?
          undefined :
          await getSecret(log, KEYCHAIN_SERVICE, keyFile);
        const kc = new KeyCert(name, key, cert, ca);
        kc.#keyFile = keyFile;
        kc.#certFile = certFile;
        yield kc;
      }
    }
  }

  /**
   * List all known keys.
   *
   * @yields Object with account name and pre-populated AsyncEntry for
   *   modifications.
   */
  public static async *listKeys(): AsyncGenerator<SecretEntry> {
    yield *listSecrets(KEYCHAIN_SERVICE);
  }

  static #getNames(
    opts: RequiredCommonCertOptions,
    name: string
  ): KeyCertNames {
    const fn = filenamify(name);
    const certDir = path.resolve(process.cwd(), opts.dir);
    const keyName = path.join(certDir, `${fn}.key.pem`);
    const certName = path.join(certDir, `${fn}.cert.pem`);
    return {
      certDir,
      keyName,
      certName,
    };
  }

  /**
   * Delete this key, if it isn't temporary.
   *
   * @param opts Options, of which temp is the most important.
   * @param log Logger.
   * @returns Promise that completes when done deleting.
   */
  public async delete(
    opts?: RequiredCommonCertOptions,
    log?: Logger
  ): Promise<void> {
    if (opts?.temp) {
      return;
    }
    const keyName = this.#keyFile;
    const certName = this.#certFile;
    assert(keyName, '#keyName should have been set on creation');
    assert(certName, '#certName should have been set on creation');
    await deleteSecret(KEYCHAIN_SERVICE, keyName, log);
    log?.debug?.('Deleting cert: "%s"', certName);
    await fs.rm(certName);
  }

  /**
   * Save the cert file and key, unless this is temporary.
   *
   * @param opts Options, of which temp is the most important.
   * @param log Logger.
   * @returns Promise that completes when writing is done.
   */
  public async write(
    opts: RequiredCommonCertOptions,
    log: Logger
  ): Promise<void> {
    const names = KeyCert.#getNames(opts, this.name);
    this.#keyFile = names.keyName;
    this.#certFile = names.certName;
    if (opts.temp) {
      return;
    }
    await fs.mkdir(names.certDir, {recursive: true});
    if (this.key) {
      await setSecret(log, KEYCHAIN_SERVICE, names.keyName, this.key);
    }
    await fs.writeFile(names.certName, this.cert, 'utf8');
  }

  /**
   * Verify the certificate with its issuer.  If no CA, returns false.
   *
   * @returns True if valid.
   */
  public verify(): boolean {
    if (!this.ca) {
      return false;
    }
    return this.#x509.verifySignature(this.ca.#x509.getPublicKey());
  }
}
