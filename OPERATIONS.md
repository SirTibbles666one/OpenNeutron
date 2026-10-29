# Sloth Lee Mail — operations

Everything here was run on the live server (`mail.slothlee.xyz`, 46.62.155.175, Hetzner
CPX22, Ubuntu). Anything that stops being true should be corrected the moment it is
noticed: a runbook that describes a machine you do not have is worse than no runbook,
because it is trusted at 3am.

No secrets in this file. Passwords, tokens and keys live on the server, at 0600, in the
paths named below.

## What is running

| Piece | Where it runs | What it does | Check |
|---|---|---|---|
| `openneutron` container | Docker | Mailbox store, HTTP API **:8080**, SMTP **:2525** | `docker ps` |
| Postfix | host, **:25** (public MX) | Receives mail, TLS, rspamd milter, recipient map | `systemctl status postfix` |
| rspamd + redis | **host** (not containers) | Spam scoring, greylisting, ratelimits | `systemctl status rspamd redis-server` |
| nginx | host, **:443** | Web client, `mta-sts` and `wkd` vhosts | `systemctl status nginx` |
| fail2ban | host | `sshd` + `nginx-limit-req` jails | `fail2ban-client status` |
| certbot | host, timer | Let's Encrypt renewal | `systemctl list-timers \| grep certbot` |

**One health command:** `mail-health.sh` — silent and exit 0 when everything is fine,
prints only what is wrong and exits 1 otherwise. `mail-health.sh -v` shows every check.
It checks the container, the API, all five units, https, certificate expiry, SMTP
listeners, the postfix queue, the recipient map, the age of the last off-site backup and
disk space.

## Deploying

The two halves are separate repositories (`Webinterface` = client, `OpenNeutron` =
server). Both are worked on locally and pushed to the box; nothing is edited in place on
the server except configuration.

**Web client**
```bash
cd <web-repo> && npm run build
tar czf - -C dist . | ssh -i <key> root@46.62.155.175 \
  'rm -rf /opt/on/data/static/* && tar xzf - -C /opt/on/data/static && chmod 755 /opt/on/data'
```
Bump the service-worker version in `public/sw.js` before building, or browsers keep the
old shell and a fix looks like it did nothing.

**Server**
```bash
tar czf - src Cargo.toml Cargo.lock | ssh -i <key> root@46.62.155.175 \
  'tar xzf - -C /opt/on && docker exec openneutron \
   cargo build --release --target x86_64-unknown-linux-musl && docker restart openneutron'
```
The binary is `OpenNeutron`, not `neutron`. A restart reloads sessions; users stay
signed in.

**Prove it after deploying**
```bash
./scripts/run-all-proofs.sh              # everything
./scripts/run-all-proofs.sh --only scheduled
```
The suite is the Rust tests, the browser-crypto proofs (Node), and the Python proofs
that run against the box over SSH. Each line of output is one proof; the runner exits
non-zero if any fails, **judged by the proof's exit status**, never by matching its
output — that mistake once let a 29/30 run report `ok`. No count is written here on
purpose: it changed twice this week, and a number in prose is a claim that rots.

## Backups and restore

**Nightly, 04:10** (`/usr/local/bin/mail-offsite-backup.sh`): tar of the state, encrypted
with GPG AES-256 using a passphrase that exists only on this host, uploaded to the private
repository `SirTibbles666one/sloth-mail-backups`, ten kept, each logged with a sha256 in
`/var/log/mail-offsite.log`. The script refuses to upload an archive it cannot decrypt and
list itself.

**The state it carries:** `users.bin`, the sidecar JSONs (waitlist, pending accounts,
recovery, two-factor, sessions, ephemeral rules, notes, aliases, scheduled, arrival, push,
VAPID, imported, PQ keys, deletion log + its signing key), `data/blobs`, `dkim`,
`config.yml`.

**A new `data/*.json` sidecar must be added to the tar list in the same commit** that
creates it, or it is not backed up.

**Monthly, 1st at 06:00:** `mail-restore-drill.sh` — downloads the newest archive,
compares its sha256 with the upload log, decrypts it, and boots a second server from the
restored state on port 8099 while production keeps running, then asserts the API answers,
the user table loaded, the DKIM key returned and the account count is non-zero. Logs to
`/var/log/mail-restore-drill.log`.

**A real disaster restore also needs**, and the archive deliberately does not carry: the
binary (rebuild from git — a backup that pinned a build would restore last month's server
with this month's data), TLS certificates (re-issue once DNS points at the new host), and
the `/usr/src/app` layout the image expects.

## Monitoring

A watchdog runs **every 30 minutes from the Hermes host**, not from this server —
deliberately, because a machine cannot report its own absence. `mail-watchdog.sh`
(script-only, no model invoked) SSHes in, runs `mail-health.sh`, and **prints nothing
when the check passes**. Silence means healthy; the only messages are the failures:

- **not answering over SSH** — the host is down, unreachable, or refusing the key
- **health check failed** — with the lines `mail-health.sh` printed

Alerts arrive in Telegram. They cover the container, the API, nginx, postfix, rspamd,
redis, fail2ban, https, certificate expiry under 14 days, the SMTP listeners, the
postfix queue, the age of the last off-site backup (over 26 h) and disk over 85%.

This is a backstop, not a substitute for `mail-health.sh -v` when something feels wrong.

## Where the secrets are

| Secret | Path |
|---|---|
| Backup GPG passphrase | `/root/.mail-backup-pass` |
| Backup repository token | `/root/.gh-backup-token` |
| Administrator JWT (cached) | `/root/.admin.jwt` |
| JWT signing secret, DKIM key, config | `/opt/on/config.yml`, `/opt/on/dkim/` |
| Deletion-log signing key | `/opt/on/data/logkey.json` (also in every backup) |

All 0600. `/opt/on/data` itself stays **755** — dropping it to 700 broke static serving
(`signup` 404, `sw.js` 403) because the container reads the directory as its own user.

## Everyday operations

- **Approve someone who asked for access** — Panel → Admin → the approval queue. Self
  signup at `/signup` creates the account but holds it; login answers "waiting for
  approval", not "wrong password". CLI: `mail-pending` lists the queue,
  `mail-pending approve <username>` and `mail-pending deny <username>` act on it.
- **Invite codes** — still work, still single-use (`mail-waitlist`).
- **Create an account by hand** — Panel → Admin → New account, then hand over the one-time
  setup token it shows. The account has no keys until setup completes.
- **Recovery** — users create a recovery key in Settings; it is single-use and replaces the
  old one when used. A server-side password reset costs the mailbox's old mail, because the
  private key is wrapped with the password. Say so before doing it.
- **A message that will not send** — the compose window shows the SMTP error the server
  returned (`502 smtp_error`). A scheduled message that fails appears in the Sent panel as
  "couldn't send — <reason>" and stays listed.

## Things that will bite

- **Never add a field to the `User` or `Email` structs.** Both stores are bincode and
  positional; a new field makes every existing record unreadable (`get_user` → `None` →
  every request 401) and the next save overwrites the store. New state goes in a
  `data/*.json` sidecar.
- **The CSP must keep `'wasm-unsafe-eval'`.** Argon2 runs as WebAssembly; without it,
  sign-in fails inside the browser while the server logs no request at all — and the app
  used to report that as "Login failed". The `headers` proof asserts it. Violations are
  readable at `/var/log/nginx/csp-reports.jsonl`.
- **`limit_req_status 429` on every rate-limited location.** Without it, throttling reads
  as "server broken" (it answered 503).
- **The postfix milter fails open.** `milter_default_action = accept` means that if rspamd
  is down, mail is still delivered — unscored. Check `systemctl status rspamd`, not the
  docker list.
- **`docker logs X | grep -q` lies under `set -o pipefail`**: grep exits early, docker logs
  dies of SIGPIPE, the pipeline returns 141 and a passing check reads as failure.
- **Run the mail server from `/usr/src/app`** (the image's workdir): the DKIM path in
  `config.yml` is absolute.
- **Editing a held message is device-local.** The server holds the sealed request and
  cannot return the plaintext; the pencil only appears on the device that composed it.
  `replace_id` without `send_at` is refused with `400 replace_needs_time` — otherwise an
  edit would deliver a second copy while the first stayed queued.

## Posture

Security details, the reasoning behind the headers, the fail2ban jails and what is still
open: `/root/HARDENING.md`. Mail authentication state (SPF, DKIM alignment, DMARC
`p=reject`, MTA-STS, TLS-RPT) is verified end-to-end through an outside receiver, not by
reading the DNS zone.
