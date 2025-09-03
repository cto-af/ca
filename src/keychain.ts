import {AsyncEntry, findCredentialsAsync} from '@napi-rs/keyring';
import type {Logger} from '@cto.af/log';
import {errCode} from '@cto.af/utils';
import fs from 'node:fs/promises';

/**
 * Retrieve secret information from the keychain.
 *
 * @param log Logging service.
 * @param service Keychain service name.
 * @param account Full path to a filename that *could* store the secret.
 * @returns Secret.
 */
export async function getSecret(
  log: Logger,
  service: string,
  account: string
): Promise<string | undefined> {
  const e = new AsyncEntry(service, account);
  let secret = await e.getPassword();
  if (secret) {
    return secret;
  }
  try {
    log.warn('Reading key from untrusted store: "%s"', account);
    secret = await fs.readFile(account, 'utf8');
    log.info('Converting key to trusted store: "%s"', account);
    await e.setPassword(secret);
    log.info('Deleting old untrusted store: "%s"', account);
    await fs.rm(account);
    return secret;
  } catch (err) {
    if (errCode(err, 'ENOENT')) {
      return undefined;
    }
    throw err;
  }
}

/**
 * Store a secret in the keychain.
 *
 * @param log Logging service.
 * @param service Keychain service name.
 * @param account Full path to a filename that *could* store the secret.
 * @param secret Secret to store.
 */
export async function setSecret(
  log: Logger,
  service: string,
  account: string,
  secret: string
): Promise<void> {
  const e = new AsyncEntry(service, account);
  await e.setPassword(secret);
  try {
    await fs.stat(account);
    log.warn('Removing old untrusted store: "%s"', account);
    await fs.rm(account);
  } catch (err) {
    if (!errCode(err, 'ENOENT')) {
      throw err;
    }
  }
}

/**
 * Delete a secret from the keychain.
 *
 * @param service Keychain service name.
 * @param account Full path to a filename that *could* store the secret.
 * @param log Logging service.
 */
export async function deleteSecret(
  service: string,
  account: string,
  log?: Logger
): Promise<void> {
  const e = new AsyncEntry(service, account);
  log?.debug?.('Deleting secret: "%s"', account);
  await e.deletePassword();
  try {
    await fs.stat(account);
    log?.warn('Removing old untrusted store: "%s"', account);
    await fs.rm(account);
  } catch (err) {
    if (!errCode(err, 'ENOENT')) {
      throw err;
    }
  }
}

export interface SecretEntry {
  entry: AsyncEntry;
  account: string;
}

/**
 * List all of the keys in this service.
 *
 * @param service Keychain service name.
 * @yields An entry for each key found.
 */
export async function *listSecrets(
  service: string
): AsyncGenerator<SecretEntry> {
  for (const {account} of await findCredentialsAsync(service)) {
    yield {
      entry: new AsyncEntry(service, account),
      account,
    };
  }
}
