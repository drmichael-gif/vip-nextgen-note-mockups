// Measures the artifact that gets pushed, not the build's report about it.
// 1. right password decrypts every note and the manifest
// 2. wrong password fails on every one of them (the control)
// 3. decrypted bytes match the source file, allowing for the inlining rewrites
// 4. no plaintext of any note is recoverable from the files in this repo
// 5. every note is self-contained: no relative src/href survives
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { webcrypto as crypto } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { join } from 'node:path';

const SRC = process.argv[2];
const PASSWORD = process.env.GATE_PASSWORD;
if (!SRC || !PASSWORD) { console.error('usage: GATE_PASSWORD=... node verify.mjs <source-dir>'); process.exit(1); }

// Control passwords are DERIVED at run time, never written here. Spelling them out literally put
// the real password into this file as a substring — a control formed by appending one character
// contains the whole secret — and check 4 correctly flagged verify.mjs as leaking it. Then the
// comment explaining that failure quoted the password too, and check 4 flagged it again. A leak
// detector must not be the leak, and neither must its documentation: never write the value.
const WRONG = [
  PASSWORD.toLowerCase() === PASSWORD ? PASSWORD.toUpperCase() : PASSWORD.toLowerCase(),
  PASSWORD.slice(0, -1),                    // one char short
  PASSWORD.slice(1),                        // one char off the front
  PASSWORD.split('').reverse().join(''),
  '', 'password', 'letmein',
].filter(p => p !== PASSWORD);

const dec = new TextDecoder(), enc = new TextEncoder();
let fail = 0;
const ok = (cond, msg) => { console.log((cond ? '  PASS  ' : '  FAIL  ') + msg); if (!cond) fail++; };

async function decrypt(file, password) {
  const p = JSON.parse(readFileSync(join('notes', file), 'utf8'));
  const base = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
  const key = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: Buffer.from(p.salt, 'base64'), iterations: p.iter, hash: 'SHA-256' },
    base, { name: 'AES-GCM', length: 256 }, false, ['decrypt'],
  );
  const pt = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: Buffer.from(p.iv, 'base64') }, key, Buffer.from(p.ct, 'base64'));
  return dec.decode(pt);
}

console.log('\n[1] manifest + notes decrypt with the real password');
const manifest = JSON.parse(await decrypt('index.enc', PASSWORD));
ok(Array.isArray(manifest.notes) && manifest.notes.length === 5,
   `index.enc lists ${manifest.notes.length} notes (expected 5)`);

const plain = new Map();
for (const n of manifest.notes) {
  let html = null, err = null;
  try { html = await decrypt(n.slug + '.enc', PASSWORD); } catch (e) { err = e; }
  ok(html !== null, `${n.slug} decrypts` + (err ? ' — ' + err.message : ` (${html.length} chars)`));
  if (html) plain.set(n.slug, html);
}

console.log('\n[2] CONTROL: wrong passwords must fail on every file');
const targets = ['index.enc', ...manifest.notes.map(n => n.slug + '.enc')];
let attempts = 0, refused = 0;
for (const pw of WRONG) {
  for (const t of targets) {
    attempts++;
    try { await decrypt(t, pw); console.log(`  FAIL  ${t} DECRYPTED with wrong password ${JSON.stringify(pw)}`); fail++; }
    catch { refused++; }
  }
}
ok(refused === attempts, `${refused}/${attempts} wrong-password attempts refused (${WRONG.length} passwords x ${targets.length} files)`);

console.log('\n[3] decrypted content matches the source on disk');
// The build inlines an iframe src and data-URI's images, so a fixed-offset probe can land on a
// ref the build legitimately rewrote — that is what made the first version of this check fail on
// the LOMN template. Probe the longest run of source text that contains no src/href at all, and
// probe three of them so one unlucky region cannot decide the result.
function probeRegions(text, count) {
  const collapsed = text.replace(/\s+/g, ' ');
  const gaps = [];
  let cursor = 0;
  for (const m of collapsed.matchAll(/(?:src|href)\s*=\s*"[^"]*"/gi)) {
    if (m.index - cursor > 0) gaps.push([cursor, m.index]);
    cursor = m.index + m[0].length;
  }
  gaps.push([cursor, collapsed.length]);
  return gaps
    .filter(([a, b]) => b - a >= 400)
    .sort((x, y) => (y[1] - y[0]) - (x[1] - x[0]))
    .slice(0, count)
    .map(([a, b]) => collapsed.slice(a + Math.floor((b - a - 400) / 2), a + Math.floor((b - a - 400) / 2) + 400));
}
for (const [slug, html] of plain) {
  const src = readFileSync(join(SRC, slug + '.html'), 'utf8');
  const probes = probeRegions(src, 3);
  const hay = html.replace(/\s+/g, ' ');
  const hit = probes.filter(p => hay.includes(p)).length;
  ok(probes.length > 0 && hit === probes.length,
     `${slug}: ${hit}/${probes.length} ref-free 400-char source probes present (src ${src.length} -> ${html.length})`);
}

console.log('\n[4] no plaintext of any note is recoverable from the pushed files');
// Take a distinctive phrase out of each source and require it appears nowhere in any file that
// gets committed. This is the check that would catch a stray copy of a mockup in the repo.
// Enumerate what GIT would publish, not what the folder contains: .snapshot/ holds the
// plaintext and is gitignored, so a directory walk would report a leak that never ships, and
// — worse — a walk would MISS a plaintext file that is committed but sits outside this tree.
// Falls back to a walk before `git init`, and says which mode it used.
let committed = [];
let mode = 'git ls-files';
try {
  committed = execFileSync('git', ['ls-files', '-co', '--exclude-standard'], { encoding: 'utf8' })
    .split('\n').filter(Boolean);
  if (!committed.length) throw new Error('empty');
} catch {
  mode = 'directory walk (no git yet)';
  committed = [];
  (function walk(d) {
    for (const e of readdirSync(d)) {
      if (e === '.git' || e === 'node_modules' || e === '.snapshot') continue;
      const p = join(d, e);
      if (statSync(p).isDirectory()) walk(p); else committed.push(p);
    }
  })('.');
}
ok(committed.some(p => p.endsWith('index.html')) && committed.some(p => p.includes('index.enc')),
   `enumeration via ${mode} found the page and the manifest (${committed.length} files)`);
ok(!committed.some(p => p.startsWith('.snapshot')),
   'plaintext .snapshot/ is excluded from what git would publish');
const blobs = committed.map(p => ({ p, t: readFileSync(p, 'latin1') }));
console.log(`        scanning ${committed.length} files: ${committed.map(p => p.replace('./', '')).join(', ')}`);
for (const [slug, html] of plain) {
  const needle = html.replace(/\s+/g, ' ').slice(3000, 3120);
  const hits = blobs.filter(b => b.t.replace(/\s+/g, ' ').includes(needle)).map(b => b.p);
  ok(hits.length === 0, `${slug}: 120-char plaintext probe found in ${hits.length} committed file(s) ${JSON.stringify(hits)}`);
}
// And the password itself must not be in any committed file.
const pwHits = blobs.filter(b => b.t.includes(PASSWORD)).map(b => b.p);
ok(pwHits.length === 0, `password string absent from every committed file ${JSON.stringify(pwHits)}`);

console.log('\n[5] every note is self-contained (no relative refs, nothing to fetch)');
for (const [slug, html] of plain) {
  const rel = [...html.matchAll(/(?:src|href)\s*=\s*"([^"]+)"/gi)].map(m => m[1])
    .filter(u => !/^(https?:|data:|mailto:|tel:|#|\/\/)/i.test(u));
  const remote = [...new Set([...html.matchAll(/(?:src|href)\s*=\s*"(https?:[^"]+)"/gi)].map(m => m[1]))];
  ok(rel.length === 0, `${slug}: ${rel.length} relative refs ${JSON.stringify(rel.slice(0, 5))}`);
  if (remote.length) console.log(`        ${slug} outbound links (user-clicked only): ${JSON.stringify(remote)}`);
}

console.log('\n[6] PHI sweep of the decrypted plaintext (what a viewer actually sees)');
const PATS = [['SSN', /\b\d{3}-\d{2}-\d{4}\b/g], ['MRN', /\bMRN\b\s*[:#]?\s*[A-Z0-9-]{4,}/gi],
              ['email', /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g], ['NPI10', /\b\d{10}\b/g]];
for (const [slug, html] of plain) {
  const found = PATS.map(([n, re]) => [n, [...new Set(html.match(re) || [])]]).filter(([, h]) => h.length);
  ok(found.length === 0, `${slug}: ${found.length} PHI pattern class(es) ${JSON.stringify(found)}`);
}

console.log(fail === 0 ? '\nALL CHECKS PASSED\n' : `\n${fail} CHECK(S) FAILED\n`);
process.exit(fail === 0 ? 0 : 1);
