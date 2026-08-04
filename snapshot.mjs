// Freezes the source files into .snapshot/ so build and verify measure the SAME bytes.
// Michael edits these mockups live; a build that reads the file at 14:26 and a verify that
// reads it at 14:31 are checking two different documents, and the mismatch is invisible.
import { readFileSync, writeFileSync, mkdirSync, readdirSync, rmSync, statSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join } from 'node:path';

const SRC = process.argv[2];
if (!SRC) { console.error('usage: node snapshot.mjs <source-dir>'); process.exit(1); }

const FILES = [
  '1_INITIAL_VISIT_Note_Mockup.html',
  '2_ULTRASOUND_REVIEW_Visit_Note_Mockup.html',
  '3_PROCEDURE_Note_Mockup_with_FollowUp.html',
  '4_FOLLOWUP_Visit_Note_Mockup.html',
  'lomn-template-ablation-v330.html',
  'lomn-template-ablation-v330_html_43bafd0c.png',
];

rmSync('.snapshot', { recursive: true, force: true });
mkdirSync('.snapshot', { recursive: true });

const rows = [];
for (const f of FILES) {
  const buf = readFileSync(join(SRC, f));
  writeFileSync(join('.snapshot', f), buf);
  const sha = createHash('sha256').update(buf).digest('hex');
  const mtime = statSync(join(SRC, f)).mtime.toISOString();
  rows.push({ file: f, bytes: buf.length, sha256: sha, source_mtime: mtime });
  console.log(sha.slice(0, 12), String(buf.length).padStart(7), mtime, f);
}

// Re-read every snapshot and confirm it still hashes to what we recorded: proves the copy
// itself is intact, independent of the source, which may have changed again by now.
let bad = 0;
for (const r of rows) {
  const again = createHash('sha256').update(readFileSync(join('.snapshot', r.file))).digest('hex');
  if (again !== r.sha256) { console.error('SNAPSHOT MISMATCH', r.file); bad++; }
}
if (bad) process.exit(1);

writeFileSync('.snapshot/MANIFEST.json', JSON.stringify({ source: SRC, files: rows }, null, 2));
console.log('\nsnapshot: ' + rows.length + ' files frozen in .snapshot/ (all hashes re-verified)');
