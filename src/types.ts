import type {Logger} from '@cto.af/log';
import type rs from 'jsrsasign';

export interface CertOptions {

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
  host?: string;

  /** Always create a new CA cert, even if one exists and is valid. */
  forceCA?: boolean;

  /** Always create a new certificate, even if one exists and is valid. */
  forceCert?: boolean;

  /**
   * 0 for info. +verbose, -quiet.
   */
  logLevel?: number;

  /**
   * Log to a file instead.
   */
  logFile?: string | null;

  /**
   * Already have a log file?
   */
  log?: Logger | null;
}

export type RequiredCertOptions = Required<CertOptions>;

export type AnyKey = rs.RSAKey | rs.KJUR.crypto.DSA | rs.KJUR.crypto.ECDSA;

export interface KeyCertNames {
  certDir: string;
  keyName: string;
  certName: string;
}
