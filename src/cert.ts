import {AnyKey, KeyCertNames, RequiredCertOptions} from './types.js';
import {deleteSecret, getSecret, setSecret} from './keychain.js';
import {daysFromNow} from './utils.js';
import filenamify from 'filenamify';
import fs from 'node:fs/promises';
import path from 'node:path';
import rs from 'jsrsasign';

const KEYCHAIN_SERVICE = 'com.github.cto-af.ca';

export class KeyCert {
  public readonly name: string;
  public readonly key: string | undefined = undefined;
  public readonly cert: string;
  public readonly notAfter: Date;
  public readonly notBefore: Date;
  public readonly subject: string;
  public readonly issuer: string;
  public readonly serial: string;
  public readonly ca: KeyCert | undefined;

  public constructor(
    name: string,
    key: AnyKey | string | undefined,
    cert: rs.KJUR.asn1.x509.Certificate | string,
    ca?: KeyCert
  ) {
    this.name = name;
    if (key) {
      this.key = (typeof key === 'string') ?
        key :
        rs.KEYUTIL.getPEM(key, 'PKCS8PRV');
    }
    this.cert = (typeof cert === 'string') ? cert : cert.getPEM();
    const x = new rs.X509();
    x.readCertPEM(this.cert);
    this.notAfter = rs.zulutodate(x.getNotAfter());
    this.notBefore = rs.zulutodate(x.getNotBefore());
    this.subject = x.getSubjectString();
    this.issuer = x.getIssuerString();
    this.ca = ca;
    this.serial = x.getSerialNumberHex();
  }

  public static async read(
    opts: RequiredCertOptions,
    name: string
  ): Promise<KeyCert | null> {
    try {
      const names = this.#getNames(opts, name);
      const key = opts.noKey ?
        undefined :
        await getSecret(opts, KEYCHAIN_SERVICE, names.keyName);
      const cert = await fs.readFile(names.certName, 'utf8');
      const kc = new KeyCert(name, key, cert);
      // If the server can't run for at least a day, create new certs.
      if (kc.notAfter < daysFromNow(opts.minRunDays)) {
        return null;
      }
      return kc;
    } catch (e) {
      const er = e as NodeJS.ErrnoException;
      if (er.code === 'ENOENT') {
        return null;
      }
      throw e;
    }
  }

  static #getNames(opts: RequiredCertOptions, name: string): KeyCertNames {
    const fn = filenamify(name);
    const certDir = path.resolve(process.cwd(), opts.certDir);
    const keyName = path.join(certDir, `${fn}.key.pem`);
    const certName = path.join(certDir, `${fn}.cert.pem`);
    return {
      certDir,
      keyName,
      certName,
    };
  }

  public async delete(opts: RequiredCertOptions): Promise<void> {
    const names = KeyCert.#getNames(opts, this.name);
    await deleteSecret(opts, KEYCHAIN_SERVICE, names.keyName);
    await fs.rm(names.certName);
  }

  public async write(opts: RequiredCertOptions): Promise<void> {
    const names = KeyCert.#getNames(opts, this.name);
    await fs.mkdir(names.certDir, {recursive: true});
    if (this.key) {
      await setSecret(opts, KEYCHAIN_SERVICE, names.keyName, this.key);
    }
    await fs.writeFile(names.certName, this.cert, 'utf8');
  }
}
