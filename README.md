# Pricing Hub

A single, self-contained `index.html` that renders a password-protected pricing
catalogue. The dataset never ships in plaintext: the page holds only an
encrypted blob and decrypts it in the browser after the correct access key is
entered.

**Live site:** https://mhmdghayad.github.io/pricing-hub/

## Security model

- The catalogue is encrypted client-side and stored in `index.html` as an
  `ENC = { salt, iv, ct, iter }` envelope (double-layered: an outer access key
  guards an inner encrypted payload).
- Key derivation: **PBKDF2 / SHA-256, 600,000 iterations**. Encryption:
  **AES-GCM-256** with a random 12-byte nonce and random salt.
- `salt` and `iv` are *not* secrets — they are safe to be public. The only
  secrets are the access keys, which are never committed anywhere.

> Because the repository is public, the ciphertext is downloadable by anyone.
> Security therefore rests entirely on the strength and secrecy of the access
> keys. Do not weaken the iteration count or reuse keys. If a key is ever
> exposed, re-encrypt with a fresh salt and a new key.

## Verify guard

`scripts/verify-envelope.mjs` is a zero-dependency check that runs in CI
(`.github/workflows/verify.yml`) on every change to `index.html`. It refuses a
build that:

- is missing or has a malformed `ENC` envelope,
- uses a non-12-byte nonce or non-base64 fields,
- drops below the 600,000-iteration PBKDF2 floor,
- silently downgrades away from PBKDF2 / AES-GCM,
- or shrinks suspiciously (payload replaced by a stub).

Run it locally:

```bash
node scripts/verify-envelope.mjs index.html
```

### Optional end-to-end decrypt

Set a repository secret named `MONTY_TEST_PW` to the outer access key. When
present, CI additionally performs a full decrypt and asserts the result is
HTML — the strongest guard that a published build is actually openable. Without
the secret, only the structural checks run.

## Deployment

Publishing is handled by GitHub Pages (Settings → Pages, source = `main` /
root). The verify workflow does **not** deploy; it only gates content quality.

> After renaming the repository, GitHub Pages must be reconnected once in
> Settings → Pages (re-select the source branch and save) before new deploys
> will publish.

## Rollback

Known-good published builds are tagged (e.g. `good-<shortsha>`). To roll back:

```bash
git checkout <tag> -- index.html
git commit -m "Roll back index.html to <tag>"
```
