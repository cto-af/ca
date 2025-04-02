import type {RequiredCertOptions} from './types.js';
import fs from 'node:fs/promises';

// TODO: add support for "good" storage mechanisms on each platform

/**
 * Retrieve secret information from the keychain.
 *
 * @param opts Certificate options.
 * @param _service Currently ignored.  Will be used for native-keychain on OSX.
 * @param account Full path to a filename that *could* store the secret.
 * @returns Secret.
 */
export function getSecret(
  opts: RequiredCertOptions,
  _service: string,
  account: string
): Promise<string> {
  opts.log?.warn('Reading key from untrusted store: "%s"', account);
  return fs.readFile(account, 'utf8');
}

/**
 * Store a secret in the keychain.
 *
 * @param opts Certificate options.
 * @param _service Currently ignored.  Will be used for native-keychain on OSX.
 * @param account Full path to a filename that *could* store the secret.
 * @param secret Secret to store.
 */
export async function setSecret(
  opts: RequiredCertOptions,
  _service: string,
  account: string,
  secret: string
): Promise<void> {
  opts.log?.warn('Writing key to untrusted store: "%s"', account);
  await fs.writeFile(account, secret, 'utf8');
}

/**
 * Delete a secret from the keychain.
 *
 * @param opts Certificate options.
 * @param _service Currently ignored.  Will be used for native-keychain on OSX.
 * @param account Full path to a filename that *could* store the secret.
 */
export async function deleteSecret(
  opts: RequiredCertOptions,
  _service: string,
  account: string
): Promise<void> {
  opts.log?.warn('Deleting key in untrusted store: "%s"', account);
  await fs.rm(account);
}
