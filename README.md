# NextGen Note Mockups — password-gated preview

Static preview of the VIP / VTC NextGen note redesign mockups. **Sample data only. Not a
real chart.** Every mockup here carries synthetic values (`PATIENT, SAMPLE`, `DOB 01/01/1970`).

## Why the notes are encrypted rather than password-checked

GitHub Pages on a free plan requires a **public** repository. A JavaScript password prompt in
front of a plaintext file is theater: anyone can read the file directly, or read the check
itself in view-source. So the password is not compared against anything — it **is** the
decryption key.

- `notes/*.enc` — AES-256-GCM ciphertext, key derived by PBKDF2-SHA256 at 310,000 iterations
- `notes/index.enc` — the note list, encrypted too, so an unauthenticated visitor cannot even
  see which notes exist. Decrypting it is the password check.
- `index.html` — the gate. Derives the key in-browser via WebCrypto and decrypts locally. The
  password is never transmitted.

A wrong password fails GCM authentication and throws. There is no plaintext copy in this
repository to route around the gate with, which `verify.mjs` asserts by probing every
committed file for the notes' plaintext.

Each note is **self-contained**: the LOMN letterhead image is inlined as a `data:` URI and the
LOMN iframe is inlined as `srcdoc`, so a decrypted note fetches nothing. The only remote
references left are two `medwork.io` links a viewer would have to click.

## Rebuilding after editing a mockup

```sh
SRC="$HOME/Documents/Codex/2026-08-04/https-friday-vipmedicalgroup-ai-nextgen-note/public"
node snapshot.mjs "$SRC"                          # freeze the source bytes
read -rs 'GATE_PASSWORD?gate password: ' && export GATE_PASSWORD
node build.mjs .snapshot                          # encrypt from the frozen copy
node verify.mjs .snapshot                          # 25 checks, incl. the wrong-password control
unset GATE_PASSWORD
git add -A && git commit -m "Update mockups" && git push
```

**`snapshot.mjs` is not optional.** These mockups get edited while the build runs — the first
build read one file at 259,578 chars and the verify read 261,857, checking a document that no
longer existed. Freezing the bytes first makes build and verify measure the same artifact.

`.snapshot/` holds plaintext and is gitignored. `verify.mjs` enumerates via `git ls-files`
rather than walking the directory, so it reports what would actually publish.

**The password is never written into any file in this repository**, which is why the commands
above prompt for it. Check 4 of `verify.mjs` enforces that, and it has fired three times during
this build: once on a control password formed by appending a character to the real one, once on
the comment explaining that failure, and once on an earlier draft of this README that spelled
the password out in these very instructions. A public repo holding both the ciphertext and its
key is just a plaintext repo with extra steps.
