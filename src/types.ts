import type {LogOptions} from '@cto.af/log';
import type rs from 'jsrsasign';

export interface CommonCertOptions {
  /**
   * Hostname(s) for cert.  Used for subject CN, DNS subjectAltName, or IP
   * subjectAltName if IP address.  If array, the first name will be the CN,
   * and all names will be added as SANs.
   */
  host?: string | string[];

  /** Relative to cwd. */
  dir?: string;

  /**
   * Minimum number of days the server can run.  Ensure the cert will be good
   * at least this long.
   */
  minRunDays?: number;

  /** Certificate invalid after this many days, server restart required. */
  notAfterDays?: number;

  /** Always create a new cert, even if one exists and is valid. */
  force?: boolean;

  /**
   * If true, do not read the key.
   */
  noKey?: boolean;

  /**
   * If true, do not write any files.
   */
  temp?: boolean;
}

export type RequiredCommonCertOptions = Required<CommonCertOptions>;

export interface CtoCertOptions {

  /**
   * Subject Distinguished Name for CA.
   */
  caSubject?: string;

  /**
   * Minimum number of days the serve can run.  Ensure the cert will good
   * at least this long.
   */
  minRunDays?: number;

  /** Certificate invalid after this many days, server restart required. */
  notAfterDays?: number;

  /** Relative to cwd. */
  certDir?: string;

  /** Relative to cwd. */
  caDir?: string;

  /** Hostname for cert.  Used for subject CN, DNS subjectAltName. */
  host?: string | string[];

  /** Always create a new CA cert, even if one exists and is valid. */
  forceCA?: boolean;

  /** Always create a new certificate, even if one exists and is valid. */
  forceCert?: boolean;

  /**
   * If true, do not read the key.
   */
  noKey?: boolean;

  /**
   * If true, do not write any files.
   */
  temp?: boolean;
}

export type RequiredCertOptions = Required<CtoCertOptions>;

export type CertOptions = CtoCertOptions & LogOptions;
export type CommonCertLogOptions = CommonCertOptions & LogOptions;

export type AnyKey = rs.RSAKey | rs.KJUR.crypto.DSA | rs.KJUR.crypto.ECDSA;

export interface KeyCertNames {
  certDir: string;
  keyName: string;
  certName: string;
}
