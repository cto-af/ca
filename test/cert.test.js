import {KeyCert} from '../lib/cert.js';
import assert from 'node:assert/strict';
import test from 'node:test';

// eslint-disable-next-line sort-imports
import * as x509 from '@peculiar/x509';

test('No CA', async () => {
  const keys = await crypto.subtle.generateKey(
    {name: 'ECDSA', namedCurve: 'P-256'},
    true,
    ['sign', 'verify']
  );

  const cert = await x509.X509CertificateGenerator.createSelfSigned({
    name: 'CN=Test',
    notBefore: new Date('2020/01/01'),
    notAfter: new Date('2020/01/02'),
    signingAlgorithm: {name: 'ECDSA'},
    keys,
    extensions: [
      new x509.SubjectAlternativeNameExtension([{type: 'email', value: 'none@example.com'}]),
    ],
  });

  const kp = new KeyCert('CN=Test', keys.privateKey, cert);
  assert.equal(await kp.verify(), false);
  assert.throws(() => kp.san());

  const kp2 = new KeyCert('CN=Test', undefined, cert);
  assert.equal(kp2.keyPEM, '');
});
