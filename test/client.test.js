import {CertificateAuthority} from '../lib/index.js';
import assert from 'node:assert/strict';
import test from 'node:test';
import tls from 'node:tls';
import {whileCAtrusted} from '../lib/client.js';

test('tls e2e', async () => {
  const ca = new CertificateAuthority({temp: true});
  const cert = await ca.issue({temp: true, noKey: true});

  await new Promise((resolve, reject) => {
    const s = tls.createServer({
      key: cert.key,
      cert: cert.chain,
    }, socket => {
      socket.end();
      s.close();
    })
      .listen(0, '127.0.0.1', () => {
        const {port, address} = s.address();
        whileCAtrusted(cert.ca.cert, () => {
          const cli = tls.connect(port, address, () => {
            assert.deepEqual(
              cli.getPeerCertificate().serialNumber.toUpperCase(),
              cert.serial.toUpperCase()
            );
            resolve();
          }).on('error', reject);
        });
      })
      .on('error', reject);
  });
});
