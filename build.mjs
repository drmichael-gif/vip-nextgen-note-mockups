// Encrypts each mockup under the gate password and emits notes/<slug>.enc plus notes/index.enc.
// The repo therefore contains NO plaintext of any note and no plaintext manifest — index.enc is
// both the note list and the password check. AES-256-GCM, PBKDF2-SHA256 (310k), parameters the
// browser's WebCrypto can verify in the splash page.
import { readFileSync, writeFileSync, readdirSync, mkdirSync } from 'node:fs';
import { webcrypto as crypto } from 'node:crypto';
import { join, basename, extname } from 'node:path';

const SRC = process.argv[2];
const PASSWORD = process.env.GATE_PASSWORD;
if (!SRC || !PASSWORD) {
  console.error('usage: GATE_PASSWORD=... node build.mjs <source-dir>');
  process.exit(1);
}

const ITER = 310000;
const enc = new TextEncoder();
const OUT = 'notes';
mkdirSync(OUT, { recursive: true });

async function encryptString(plaintext) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const base = await crypto.subtle.importKey('raw', enc.encode(PASSWORD), 'PBKDF2', false, ['deriveKey']);
  const key = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: ITER, hash: 'SHA-256' },
    base, { name: 'AES-GCM', length: 256 }, false, ['encrypt'],
  );
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(plaintext));
  return {
    v: 1, alg: 'AES-GCM', kdf: 'PBKDF2-SHA256', iter: ITER,
    salt: Buffer.from(salt).toString('base64'),
    iv: Buffer.from(iv).toString('base64'),
    ct: Buffer.from(ct).toString('base64'),
  };
}

const MIME = { '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.svg': 'image/svg+xml', '.gif': 'image/gif' };

// Every relative asset becomes a data: URI, so the encrypted note is fully self-contained and
// the repo never has to serve the asset in the clear. Returns [html, inlinedCount].
function inlineAssets(html, dir) {
  let n = 0;
  const out = html.replace(/(src|href)\s*=\s*"([^"]+)"/gi, (m, attr, url) => {
    if (/^(https?:|data:|mailto:|tel:|#|\/\/)/i.test(url)) return m;
    const ext = extname(url).toLowerCase();
    if (!MIME[ext]) return m;                       // .html handled separately, by inlining the doc
    const bytes = readFileSync(join(dir, url));
    n++;
    return `${attr}="data:${MIME[ext]};base64,${bytes.toString('base64')}"`;
  });
  return [out, n];
}

// An iframe pointing at a sibling HTML file cannot resolve once the note is served from an
// encrypted blob, so the referenced document is inlined into srcdoc instead. Escaping is for a
// double-quoted attribute value.
function inlineIframes(html, dir) {
  let n = 0;
  const out = html.replace(/<iframe\b([^>]*?)\ssrc\s*=\s*"([^"]+\.html)"([^>]*)>/gi, (m, pre, url, post) => {
    let inner = readFileSync(join(dir, url), 'utf8');
    [inner] = inlineAssets(inner, dir);
    const attrVal = inner
      .replaceAll('&', '&amp;').replaceAll('"', '&quot;')
      .replaceAll('<', '&lt;').replaceAll('>', '&gt;');
    n++;
    return `<iframe${pre}${post} srcdoc="${attrVal}">`;
  });
  return [out, n];
}

const WANTED = [
  ['1_INITIAL_VISIT_Note_Mockup.html',           'Initial Visit Note'],
  ['2_ULTRASOUND_REVIEW_Visit_Note_Mockup.html', 'Ultrasound Review Visit Note'],
  ['3_PROCEDURE_Note_Mockup_with_FollowUp.html', 'Procedure Note (with Follow-Up)'],
  ['4_FOLLOWUP_Visit_Note_Mockup.html',          'Follow-Up Visit Note'],
  ['lomn-template-ablation-v330.html',           'LOMN Template - Ablation v3.30'],
];

const present = new Set(readdirSync(SRC));
const notes = [];

for (const [file, title] of WANTED) {
  if (!present.has(file)) { console.error('MISSING, skipped:', file); continue; }
  const raw = readFileSync(join(SRC, file), 'utf8');

  let [html, frames] = inlineIframes(raw, SRC);
  let assets;
  [html, assets] = inlineAssets(html, SRC);

  // Refuse rather than ship a note that will fetch or 404 at view time.
  const leftover = [...html.matchAll(/(?:src|href)\s*=\s*"([^"]+)"/gi)]
    .map(m => m[1])
    .filter(u => !/^(https?:|data:|mailto:|tel:|#|\/\/)/i.test(u));
  if (leftover.length) {
    console.error('UNRESOLVED relative refs in', file, leftover);
    process.exit(1);
  }

  const slug = basename(file, '.html');
  const payload = await encryptString(html);
  writeFileSync(join(OUT, slug + '.enc'), JSON.stringify(payload));
  notes.push({ slug, title });
  console.log(
    'encrypted', slug.padEnd(44),
    String(raw.length).padStart(7), '->', String(html.length).padStart(7), 'chars',
    ' iframes:' + frames, ' assets:' + assets,
  );
}

// The manifest is encrypted too: decrypting it IS the password check, and an unauthenticated
// visitor cannot even read the note list.
writeFileSync(join(OUT, 'index.enc'), JSON.stringify(await encryptString(JSON.stringify({ notes }))));
console.log('\nindex.enc:', notes.length, 'notes');
