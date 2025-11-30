# @cto.af/ca

Testing-only Certificate Authority (CA) for your local development environment
ONLY.  This is in no way suitable for production of any kind.

This package will automatically create new keypairs as needed, with the CA
cert lasting a year by default and the leaf certs 3 days by default.

Currently, there is NO SECURITY for the private keys.  These should be stored
in an OS-specific keychain one day.

## Installation

```sh
npm install @cto.af/ca
```

## API

Full [API documentation](http://cto-af.github.io/ca/) is available.

Example:

```js
import {createCert} from '@cto.af/ca';
import {createServer} from 'node:tls';

// This reads and writes files from a user-scoped config directory for
// the CA cert and cwd()/.cert for the certificate.
const {key, cert} = await createCert({
  host: 'foo.local', // Default: 'localhost'
});
const server = createServer({key, cert}, () => {
  // Handle connection
});
```

On the client side, a mechanism is provided to override some of the TLS
internals of node so that fetch will work correctly.

Example:

```js
import {whileCAtrusted} from '@cto.af/ca/client';

const fetchResult = await whileCAtrusted(
  {}, // CA options, or a PEM-encoded string with the CA cert.
  () => fetch('https://localhost:8001')
);
```

### CLI

A rudimentary CLI is provided.

```
Usage: cto-af-ca [options] [command]

Options:
  -d,--dir <DIRECTORY>  Directory for CA certs (default:
                        "[User config directory]/@cto.af/ca-nodejs")
  -h, --help            display help for command
  -q,--quiet            Less verbose
  -v,--verbose          More verbose

Commands:
  cert [options]        Create a cert signed by the CA
  create [options]      Create a CA certificate
  dir                   Show directory for certs
  list                  List exising certs by subject
  rm <SUBJECT>          Remove a CA cert by subject
  help [command]        display help for command
```

---
[![Build Status](https://github.com/cto-af/ca/workflows/Tests/badge.svg)](https://github.com/cto-af/ca/actions?query=workflow%3ATests)
[![codecov](https://codecov.io/gh/cto-af/ca/graph/badge.svg?token=qFVzvS6t2V)](https://codecov.io/gh/cto-af/ca)
