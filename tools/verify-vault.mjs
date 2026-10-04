#!/usr/bin/env node
import { createDecipheriv, pbkdf2Sync } from 'node:crypto';
import { createInterface } from 'node:readline/promises';
import { stdin as input, stdout as output } from 'node:process';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
const root = new URL('..', import.meta.url).pathname.replace(/^\/(.:)/, '$1');
const rl = createInterface({ input, output }); const password = await rl.question('Mot de passe du coffre : '); await rl.close();
function decrypt(envelope) { const salt=envelope.subarray(0,16),iv=envelope.subarray(16,28),tag=envelope.subarray(envelope.length-16),ciphertext=envelope.subarray(28,envelope.length-16),key=pbkdf2Sync(password,salt,310000,32,'sha256'),decipher=createDecipheriv('aes-256-gcm',key,iv); decipher.setAuthTag(tag); return Buffer.concat([decipher.update(ciphertext),decipher.final()]); }
const manifest = JSON.parse(decrypt(await readFile(join(root,'vault','manifest.enc'))));
for (const document of manifest.documents) decrypt(await readFile(join(root,'vault',document.file)));
console.log(`Vérification réussie : ${manifest.documents.length} document(s) peuvent être ouverts.`);
