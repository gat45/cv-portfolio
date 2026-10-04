#!/usr/bin/env node
/* Chiffre les documents de private-source/ : seuls vault/*.enc sont publiés. */
import { createCipheriv, pbkdf2Sync, randomBytes } from 'node:crypto';
import { createInterface } from 'node:readline/promises';
import { stdin as input, stdout as output } from 'node:process';
import { mkdir, readdir, readFile, rm, writeFile } from 'node:fs/promises';
import { basename, extname, join } from 'node:path';

const root = new URL('..', import.meta.url).pathname.replace(/^\/(.:)/, '$1');
const sourceDir = join(root, 'private-source');
const vaultDir = join(root, 'vault');
const iterations = 310000;
const mimeTypes = { '.pdf': 'application/pdf', '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.png': 'image/png' };

async function passwordFromUser() {
  if (process.env.VAULT_PASSWORD) return process.env.VAULT_PASSWORD;
  const rl = createInterface({ input, output });
  const password = await rl.question('Mot de passe du coffre : ');
  await rl.close();
  return password;
}
function encrypt(data, password) {
  const salt = randomBytes(16), iv = randomBytes(12);
  const key = pbkdf2Sync(password, salt, iterations, 32, 'sha256');
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(data), cipher.final()]);
  return Buffer.concat([salt, iv, cipher.getAuthTag(), ciphertext]);
}
const password = await passwordFromUser();
if (password.length < 10) throw new Error('Choisissez un mot de passe d’au moins 10 caractères.');
const files = (await readdir(sourceDir, { withFileTypes: true })).filter((entry) => entry.isFile());
if (!files.length) throw new Error('Aucun document trouvé dans private-source/.');
await rm(vaultDir, { recursive: true, force: true }); await mkdir(vaultDir, { recursive: true });
const manifest = { version: 1, documents: [] };
for (const [index, entry] of files.entries()) {
  const extension = extname(entry.name).toLowerCase();
  const encryptedName = `document-${String(index + 1).padStart(3, '0')}.enc`;
  await writeFile(join(vaultDir, encryptedName), encrypt(await readFile(join(sourceDir, entry.name)), password));
  manifest.documents.push({ label: basename(entry.name, extension), file: encryptedName, type: mimeTypes[extension] ?? 'application/octet-stream', extension });
}
await writeFile(join(vaultDir, 'manifest.enc'), encrypt(Buffer.from(JSON.stringify(manifest)), password));
console.log(`${manifest.documents.length} document(s) chiffré(s) dans vault/. Les originaux restent dans private-source/.`);
