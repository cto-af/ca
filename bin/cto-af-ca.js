#!/usr/bin/env node
import {DEFAULT_CERT_OPTIONS, KeyCert, createCA, createCert} from '../lib/index.js';
import {Command} from 'commander';
import filenamify from 'filenamify';
import fs from 'node:fs/promises';
import path from 'node:path';

let logLevel = 0;
function getOpts(cmd) {
  const args = cmd.optsWithGlobals();
  return {
    caDir: args.dir,
    caSubject: args.subject,
    force: Boolean(args.force),
    forceCA: false,
    forceCert: false,
    host: args.host,
    logLevel,
  };
}

const program = new Command();
program
  .option('-d,--dir <DIRECTORY>', 'Directory for CA certs', DEFAULT_CERT_OPTIONS.caDir)
  .option('-q,--quiet', 'Less verbose', () => --logLevel)
  .option('-v,--verbose', 'More verbose', () => ++logLevel)
  .configureHelp({
    showGlobalOptions: true,
    sortOptions: true,
  });

program
  .command('cert')
  .description('Create a cert signed by the CA')
  .option('-f,--force', 'Always create a new certificate')
  .option('-H,--host <HOSTNAME>', 'Hostname for the certificate', DEFAULT_CERT_OPTIONS.host)
  .option('-s,--subject <SUBJECT>', 'Subject for the CA cert', DEFAULT_CERT_OPTIONS.caSubject)
  .action(async(_, cmd) => {
    const args = getOpts(cmd);
    args.forceCert = Boolean(args.force);
    const kc = await createCert(args);
    console.log(kc.notAfter, kc.subject);
  });

program
  .command('create')
  .description('Create a CA certificate')
  .option('-f,--force', 'Always create a new CA certificate')
  .option('-s,--subject <SUBJECT>', 'Subject for the CA cert', DEFAULT_CERT_OPTIONS.caSubject)
  .action(async(_, cmd) => {
    const args = getOpts(cmd);
    args.forceCA = Boolean(args.force);
    const kc = await createCA(args);
    console.log(kc.notAfter, kc.subject);
  });

program
  .command('dir')
  .description('Show directory for certs')
  .action((_, cmd) => {
    const args = getOpts(cmd);
    console.log(args.caDir);
  });

program
  .command('list')
  .description('List exising CA certs by subject')
  .action(async(_, cmd) => {
    const args = getOpts(cmd);
    args.certDir = args.caDir;
    for (const f of await fs.readdir(args.caDir)) {
      if (f.endsWith('.cert.pem')) {
        const file = f.slice(0, -9);
        const kc = await KeyCert.read(args, file);
        if (!kc) {
          throw new Error(`Error reading ${file}`);
        }
        console.log(kc.notAfter, kc.subject);
      }
    }
  });

program
  .command('rm <SUBJECT>')
  .description('Remove a CA cert by subject')
  .action(async(subject, _, cmd) => {
    const args = getOpts(cmd);
    const fn = path.join(args.caDir, filenamify(subject));
    await fs.rm(`${fn}.cert.pem`);
    await fs.rm(`${fn}.key.pem`);
  });

await program.parseAsync();
