#!/usr/bin/env node

// If debug needed:
// #!/usr/bin/env node -S node --enable-source-maps
import {
  CertificateAuthority,
  DEFAULT_CA_OPTIONS,
  DEFAULT_COMMON_CERT_OPTIONS,
  KeyCert,
} from '../lib/index.js';
import {Command} from 'commander';
import filenamify from 'filenamify';
import fs from 'node:fs/promises';
import path from 'node:path';

let logLevel = 0;
const prettyIgnore = 'pid,hostname,ns';

function collect(value, previous) {
  if (typeof previous === 'string') {
    return [value];
  }
  return previous.concat([value]);
}

const program = new Command();
program
  .option('-d, --dir <DIRECTORY>', 'Directory for CA certs', DEFAULT_CA_OPTIONS.dir)
  .option('-q, --quiet', 'Less verbose', () => --logLevel)
  .option('-v, --verbose', 'More verbose', () => ++logLevel)
  .configureHelp({
    showGlobalOptions: true,
    sortOptions: true,
  });

program
  .command('cert')
  .description('Create a cert signed by the CA')
  .option('-f, --force', 'Always create a new certificate')
  .option('-H, --host <HOSTNAME>', 'Hostname for the certificate', collect, DEFAULT_COMMON_CERT_OPTIONS.host)
  .option('-s, --subject <SUBJECT>', 'Subject for the CA cert', collect, DEFAULT_CA_OPTIONS.host)
  .option('-t, --temp', 'Do not output files')
  .action(async (_, cmd) => {
    const args = cmd.optsWithGlobals();
    args.forceCert = Boolean(args.force);
    const ca = new CertificateAuthority({
      host: args.subject,
      temp: args.temp,
      dir: args.dir,
      logLevel,
      prettyIgnore,
    });

    const kc = await ca.issue({
      force: args.force,
      host: args.host,
      temp: args.temp,
      noKey: true,
    });
    if (args.temp) {
      console.log(kc.cert);
      console.log(kc.key);
    } else {
      console.log(kc.notAfter, kc.subject);
    }
  });

program
  .command('create')
  .description('Create a CA certificate')
  .option('-f, --force', 'Always create a new CA certificate')
  .option('-s, --subject <SUBJECT>', 'Subject for the CA cert', collect, DEFAULT_CA_OPTIONS.host)
  .option('-t, --temp', 'Do not output files')
  .action(async (_, cmd) => {
    const args = cmd.optsWithGlobals();
    const ca = new CertificateAuthority({
      dir: args.dir,
      force: args.force,
      host: args.subject,
      temp: args.temp,
      logLevel,
      prettyIgnore,
    });
    const kc = await ca.init();
    if (args.temp) {
      console.log(kc.cert);
      console.log(kc.key);
    } else {
      console.log(kc.notAfter, kc.subject);
    }
  });

program
  .command('dir')
  .description('Show directory for CA certs')
  .action((_, cmd) => {
    const args = cmd.optsWithGlobals();
    console.log(args.dir);
  });

program
  .command('list')
  .description('List exising CA certs by subject')
  .action(async (_, cmd) => {
    const {dir} = cmd.optsWithGlobals();
    for await (const kc of CertificateAuthority.list({dir, noKey: true})) {
      console.log(kc.notAfter, kc.subject);
    }
  });

program
  .command('certs')
  .description('List exising certs by subject')
  .action(async (_, cmd) => {
    const {dir} = cmd.optsWithGlobals();
    const ca = new CertificateAuthority({
      dir,
      temp: true, // Don't save a CA for this if it doesn't exist.
      noKey: true,
      logLevel,
      prettyIgnore,
    });
    for await (const kc of ca.list()) {
      console.log(kc.notAfter, kc.subject);
    }
  });

program
  .command('rm <SUBJECT>')
  .description('Remove a CA cert by subject')
  .action(async (subject, _, cmd) => {
    const {dir} = cmd.optsWithGlobals();
    const fn = path.join(dir, filenamify(subject));
    await fs.rm(`${fn}.cert.pem`).catch(_ignored => undefined);
    await fs.rm(`${fn}.key.pem`).catch(_ignored => undefined);
  });

program
  .command('clear')
  .description('Remove all CA certs and keys')
  .action(async (_, cmd) => {
    const {dir} = cmd.optsWithGlobals();
    const opts = {dir, noKey: true};
    const log = CertificateAuthority.logger({
      logLevel,
      prettyIgnore,
    });
    for await (const kc of CertificateAuthority.list(opts)) {
      await kc.delete(opts, log);
    }
  });

program
  .command('clearkeys [pattern]')
  .description('Remove all keys from CAs and certs')
  .action(async pattern => {
    const log = CertificateAuthority.logger({
      logLevel,
      prettyIgnore,
    });
    const re = pattern ? new RegExp(pattern) : null;
    for await (const e of KeyCert.listKeys()) {
      if (!re || re.test(e.account)) {
        log.info('Deleting key: "%s"', e.account);
        await e.entry.deletePassword();
      }
    }
  });

await program.parseAsync();
