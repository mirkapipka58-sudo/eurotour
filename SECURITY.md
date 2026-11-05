# Security notes

This repository is public and the site is deployed through GitHub Pages. Do not commit tokens, private customer messages, phone lists, exports, or local `.env` files.

## What is protected now

- GitHub Pages artifact is built into `_site` and excludes `bot/`, `.github/`, `_archive/`, and repository documentation.
- Site <-> bot traffic is end-to-end encrypted (`js/et-crypto.js`, `bot/bot.py`). ntfy.sh topics are public and the topic name is in this repository, so the name is not a secret: only ciphertext is published.
  - Visitor -> bot: ECDH P-256 + HKDF-SHA256 + AES-256-GCM. The public key is in `data/site.json`; the private key exists only in the Actions secret `BRIDGE_PRIVATE_KEY`.
  - Bot -> visitor: AES-256-GCM with a random per-visitor key, delivered to the bot inside encrypted messages.
  - Files are encrypted the same way. The bot rejects plaintext, and the browser never falls back to it.
- `bot/state.json` is encrypted with `STATE_SECRET`. Without that secret, leads/chats stay in memory only and the file holds offsets and public lists.
- `robots.txt` disallows bot/workflow/archive paths for crawlers. This is only an indexing hint, not access control.

## Known limits

- The public key is public by design, so anyone can send a forged lead or message. The bot rate-limits this traffic and warns admins, but cannot tell forged from real.
- ntfy.sh sees sender IP addresses and message timing, not the content.
- Decrypted leads and chats are delivered to admins through Telegram.

## Required operator actions

1. Rotate any GitHub PAT that was ever pasted into chat or logs.
2. Add a strong GitHub Actions secret named `STATE_SECRET` if encrypted chat/lead persistence is needed across bot restarts.
3. After changing `STATE_SECRET`, `BRIDGE_PRIVATE_KEY` or the bridge inbox, manually restart the `Telegram admin bot` workflow.
4. Check GitHub Pages custom domain HTTPS: the certificate must be issued for `eurotour.kyiv.ua`, not only for `*.github.io`.

## Generate STATE_SECRET locally

Use a password manager or run locally:

```bash
python3 - <<'PY'
import secrets
print(secrets.token_urlsafe(48))
PY
```

Add the generated value in GitHub: Settings → Secrets and variables → Actions → New repository secret → `STATE_SECRET`.
