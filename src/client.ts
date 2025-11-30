import {type CertOptions, CertificateAuthority} from './index.js';
import assert from 'node:assert';
import tls from 'node:tls';

const origCsC = tls.createSecureContext;
const EXPECTED_NAME = 'createSecureContext';
let currentSym: symbol | undefined = undefined;

/**
 * Override tls.createSecureContext to trust a CA cert specified by the
 * options. WARNING: Do not call this function more than once without calling
 * resetCreateSecureContext.
 *
 * @param options CA options.
 * @returns Unique symbol, to be used in resetCreateSecureContext.
 * @throws On invalid state.
 */
export async function overrideCreateSecureContext(
  options: CertOptions | string
): Promise<symbol> {
  let cert: string | undefined = undefined;
  if (typeof options === 'string') {
    cert = options;
  } else {
    const CA = new CertificateAuthority(options);
    const {ca} = await CA.init();
    assert(ca, 'Will always be filled in if no exception thrown');
    ({cert} = ca);
  }

  assert.equal(
    origCsC.name,
    EXPECTED_NAME,
    'Original createSecureContext already hooked'
  );

  if (currentSym !== undefined) {
    throw new Error('Current createSecureContext already hooked');
  }

  // New symbol every time.
  currentSym = Symbol('overrideCreateSecureContext');
  tls.createSecureContext =
    (opts: tls.SecureContextOptions | undefined): tls.SecureContext => {
      const res = origCsC(opts);
      res.context.addCACert(cert);
      return res;
    };
  return currentSym;
}

/**
 * Reset tls.createSecureContext back to its default.  This must match
 * a corresponding call to overrideCreateSecureContext.
 *
 * @param sym Unique symbol returned from overrideCreateSecureContext.
 * @throws On invalid state.
 */
export function resetCreateSecureContext(sym: symbol): void {
  assert.equal(
    origCsC.name,
    EXPECTED_NAME,
    'Original createSecureContext already hooked'
  );

  if (!sym || sym !== currentSym) {
    throw new Error('Current override does not match');
  }

  currentSym = undefined;
  tls.createSecureContext = origCsC;
}

/**
 * Trust the CA cert that CertificateAuthority generates for all node.js TLS
 * operations, including fetch, but only for the duration of this function
 * call.
 *
 * @param options Certificate options.
 * @param during Callback during which the cert will be valid.
 * @returns The result of during.
 */
export async function whileCAtrusted<T>(
  options: CertOptions | string,
  during: () => T
): Promise<Awaited<T>> {
  const sym = await overrideCreateSecureContext(options);
  const val = await during();
  resetCreateSecureContext(sym);
  return val;
}
