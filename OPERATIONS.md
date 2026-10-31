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
| `data/geoip.mmdb` | file, read by the container | Country for each signed-in session (DB-IP Lite, CC BY 4.0) | `ls -l /opt/on/data/geoip.mmdb` |

**Every scheduled job that matters now says when it fails.** Five run: the nightly
off-site backup, the monthly restore drill, the monthly GeoIP refresh, the half-hourly DNS
watchdog (which mails on its own) and the weekly outbound DANE check. Each failure path
ends in `| /usr/local/bin/mail-alert.sh "<subject>"`, which uses `/usr/sbin/sendmail` —
there is no `mail` binary on this host, and an alert that silently fails is not an alert.
Before this, only the DANE check could tell anyone anything: a backup that stopped in
August looked exactly like one that ran last night.

**The restore drill has been proved, not just scheduled.** It downloaded the newest
archive (sha256 matched the upload log), decrypted it, extracted 397 members, booted a
second server on port 8099 from the restored state and read its user table back — 8
accounts, DKIM key recovered. A bogus archive name makes it exit 1 and mail the failure,
so the drill can fail rather than always passing.

**Outbound DANE is on, and it depends on one service staying up.** `unbound` runs as a
validating resolver on `127.0.0.1:53`; `systemd-resolved` points at it
(`/etc/systemd/resolved.conf.d/dane.conf`), so Postfix sees the AD bit without
`/etc/resolv.conf` changing — Docker reads that file when it builds a container's
resolver, and `127.0.0.1` there would point at the container itself. Postfix runs
`smtp_dns_support_level = dnssec`, `smtp_tls_security_level = dane`, so a domain that
publishes TLSA must present a matching certificate or delivery is deferred. If unbound
stops, every lookup loses the AD bit and DANE silently degrades to ordinary opportunistic
TLS — mail still flows, so nothing looks wrong. `mail-dane-outbound-check.sh` (cron
Mondays 05:23) is what notices, and it is proven to fail: stopping unbound turns it red.

**The apex is proxied, the mail records are not.** `slothlee.xyz` and `www` are proxied so
Cloudflare can add HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy and
Permissions-Policy that the Northflank origin does not send; SSL mode is Full (strict) so
the origin certificate is still verified. No CSP is injected there on purpose — the origin
is a Next.js app and a wrong policy breaks it silently. SMTP, MTA-STS and the mail host
stay DNS-only: proxying them breaks mail.

**DANE pins the mail certificate, and renewal must keep the key.** `reuse_key = True` is set
in `/etc/letsencrypt/renewal/mail.slothlee.xyz.conf`, so the SPKI pin published in DNS stays
correct across renewals without the deploy hook needing a token. Two traps: `reuse_key` must
sit inside `[renewalparams]` — appending it to the end of the file puts it in `[[webroot_map]]`
and certbot reads the value as a webroot path (`True/.well-known`), which fails the renewal
silently until someone runs a dry run. And a dry run is the only way to know: it passed only
after the setting was moved, and a failed renewal in January would have taken TLS down with it.

**Security keys live in `data/webauthn.json`.** Public keys and signature counters only —
no shared secrets, unlike `twofactor.json`, so a copy of the file cannot sign anyone in.
It is in the off-site backup tar list; a restore without it makes every enrolled key
unusable (TOTP and recovery codes still work). Login challenges are held in memory for
five minutes and deleted when redeemed, so a restart mid-login means starting again —
that is intentional: an assertion over an old challenge is still a valid signature.
WebAuthn requires the site to be a secure context, so it works on
`https://mail.slothlee.xyz` and not through a frame or a preview URL.

**Outbound mail must be DKIM-signed at the MTA, not only by the app.** The app signs what
it sends itself, but anything submitted locally — cron output, scripts, the DNS watchdog —
goes through Postfix and rspamd. `rspamd` was logging
`cannot load dkim key /var/lib/rspamd/dkim/slothlee.xyz.dkim.key` and signing nothing, so
those messages left unsigned while DMARC said `p=reject`. Fixed by
`/etc/rspamd/local.d/dkim_signing.conf` pointing at `/opt/on/dkim/slothlee.xyz.pem`,
selector `mail`, group-readable by `_rspamd`.

**The recipient map follows the mailboxes, and is case-insensitive on purpose.**
Postfix refuses an unknown recipient at RCPT — before the DATA that would otherwise be
accepted and then bounced — but only from a map that is maintained. `mail-recipients-sync.sh`
(cron `*/2`) asks the app's `/api/admin/recipients` (the truth: accounts plus live aliases,
minus pending signups) and writes `/etc/postfix/recipients.pcre`; it refuses to install an
empty map, refuses a map that omits `postmaster@` or `abuse@`, and leaves the old file alone
when the API does not answer.

Three things it depends on:

  - **`postfix-pcre` is installed.** Without it every lookup fails with
    `unsupported dictionary type: pcre` and `reject_unlisted_recipient` would refuse everything.
    The map is pcre rather than hash because mailbox names are case-insensitive
    (`Admin@` must reach `admin@`), and a hash lookup is not.
  - **The sync mints its own staff token each run** from the `jwt.secret` in `config.yml`.
    Do not point it back at a saved token: `/root/.admin.jwt` expires, and an expired token
    leaves the map frozen rather than failing loudly. Minting per run is the same authority
    as root on this box, scoped to a five-minute token.
  - **Role addresses are added by the script, not by the API**, because they are not accounts
    and cannot be aliases — `postmaster`, `abuse`, `hostmaster` and the like are reserved so a
    customer cannot claim them. The app routes them to staff.

**`roles.owner` decides who reads postmaster@ and abuse@.** Without it the choice is
alphabetical, which put role mail in a test account. Set in `config.yml`:

    roles:
      owner: tibs

An owner that does not exist, or is not an administrator, logs a warning and falls back to the
first administrator — a configuration mistake must not swallow complaints.

**The front door is postscreen, and the client's own DKIM decides own-domain mail.**
Port 25 is answered by `postscreen`, which runs the tests that need no conversation
(pregreet, DNSBL) and only then hands the connection to `smtpd`; the real listener
carries anvil limits (20 connections, 30/min per client, 60 messages/min, 120
recipients/min). DNSBL scoring: `sbl`/`xbl` weighted 3 (spam source, exploited host),
`bl.spamcop.net` 2, `zen` 1, threshold 3 — so a listing has to mean something before a
sender is refused, and residential/dynamic listings alone only cost latency.

Two settings that must stay as they are:

  - `postscreen_greet_action = ignore`. `drop` refuses any client that answers the
    preliminary banner promptly, which is most legitimate MTAs — the first version of
    this config would have silently discarded ordinary mail.
  - `dnsblog` must exist in `master.cf`. Without it postscreen logs
    `psc_dnsbl_request: connect to private/dnsblog service` and silently performs **no**
    DNSBL lookup at all, so every client passes and the config looks correct.

**Proving the drop path without a listed IP.** The blocking half of postscreen cannot be
tested from a machine that is not on a blocklist. It can be proved honestly with a zone that
exists only on this host:

    # /etc/unbound/unbound.conf.d/zz-dnsbl-selftest.conf
    server:
        local-zone: "selftest.dnsbl.slothlee.xyz." static
        local-data: "175.155.62.46.selftest.dnsbl.slothlee.xyz. 60 IN A 127.0.0.2"

then `postconf -e "postscreen_dnsbl_sites = selftest.dnsbl.slothlee.xyz*3"`, reload, and connect
from the public address. The answer is immediate and unambiguous:
`521 5.7.1 Service unavailable; client [...] blocked using selftest.dnsbl.slothlee.xyz`, with
`DNSBL rank 3` in the log. Revert both files afterwards — the zone must not survive the test.
Use a name under the real domain, not `.invalid`: systemd-resolved refuses to forward `.invalid`
by design, so the query never reaches unbound and the test silently "passes" by not blocking.

`postscreen_access_list = permit_mynetworks` is the whole list: `cidr:127.0.0.0/8` is not
valid there (`table lookup error -- ignoring the remainder of this access list`), and
mynetworks already covers loopback.

The app refuses own-domain senders that fail DKIM, which is what makes
`p=reject` true of us as well as of everyone we tell. Two consequences worth knowing:

  - Mail the box generates for itself — cron's daemon output, `mail-alert.sh`, certbot —
    is injected by the local MTA and sometimes arrives unsigned. It is accepted when
    **Postfix's own first `Received:` header** contains `(Postfix, from userid`, because
    Postfix prepends that line and a remote sender cannot place anything above it. The
    log says `own-domain mail accepted from local injection (unsigned)` when this fires.
    Before this exception existed, the 00:00 certbot report bounced and nobody knew.
  - Everything else from our domain must verify. A forgery from outside is refused at
    DATA with `550 5.7.1` and the sender gets the bounce.

Cost: a first-contact client waits about four seconds in postscreen (cached for an hour
after that). Rollback is two files — `/root/main.cf.<stamp>` and `/root/master.cf.<stamp>`
— then `postfix check && systemctl reload postfix`.

**A `local.d` file must not repeat its section name.** Writing
`dkim_signing { ... }` inside `local.d/dkim_signing.conf` nests it as
`dkim_signing.dkim_signing`, which rspamd accepts with `syntax OK` and then ignores
entirely — the log keeps showing the old behaviour. Check with
`rspamadm configdump dkim_signing` before believing a config took effect.

**Country lookup is local.** The session list labels each signed-in device with the
country its address is registered in. The lookup reads `data/geoip.mmdb` in-process: no
address is sent to a third party to answer "where is this signed in from". Refresh the
file monthly with `mail-geoip-update.sh` (cron `17 4 3 * *`, source in `scripts/`); it
installs atomically and refuses a download under 1 MB. **A missing database is not an
error** — the rows simply carry no country, because that is the truth.

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
cd <web-repo> && ./scripts/deploy.sh
```
That script builds, refuses to upload if the entry point or the build stamp is missing,
uploads, and then checks the served asset is byte-identical to the build (sha256). Use it
rather than the three-line pipeline: `npm run build | tail -2 && tar czf - ... | ssh ...`
takes its exit status from `tail`, so a failed build uploads the *previous* dist and the
result is indistinguishable from a browser cache problem.

Bump the service-worker version in `public/sw.js` before building, or browsers keep the
old shell and a fix looks like it did nothing. The sidebar footer shows the running build
(`<sha>[+] · <innerWidth>x<innerHeight>`), which answers "is my phone on the new build?"
without a devtools session.

**Server**
```bash
tar czf - src Cargo.toml Cargo.lock | ssh -i <key> root@46.62.155.175 \
  'tar xzf - -C /opt/on && docker exec -w /usr/src/app openneutron \
   bash -lc "PATH=/usr/local/cargo/bin:\$PATH cargo build --release --locked \
     --target x86_64-unknown-linux-musl" && docker restart openneutron'
```
The binary is `OpenNeutron`, not `neutron`. A restart reloads sessions; users stay
signed in.

**`cargo` is not on the default PATH inside the container** — `bash -lc` alone answers
`cargo: command not found`. Worse, piping the build through `tail` reports `tail`'s exit
status, so a build that never ran printed "done" and the old binary kept serving. Always
build without a pipe after the command, or with `set -o pipefail`, and confirm the
binary's mtime changed before restarting.

**`--locked` matters.** A new dependency means the lockfile changes, and the container
cannot write `/usr/src/app/Cargo.lock` (the bind mount's ownership). Resolve the lock on
the workstation (`cargo metadata`) and ship it; `--locked` then refuses to build if the
two disagree, which is the failure you want instead of a silent half-build.

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

## Dashboard headers (app.slothlee.xyz)

The staff dashboard is served by nginx at `/etc/nginx/sites-available/app-dashboard`,
which is where its security headers live (the Node process sets none of them).
Backups of that file: `/root/app-dashboard.pre-csp.<epoch>`.

CSP, enforced:

```
default-src 'none'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';
img-src 'self' data: https://cdn.discordapp.com https://media.discordapp.net;
font-src 'self' data:; connect-src 'self' wss://app.slothlee.xyz ws://app.slothlee.xyz;
media-src 'self'; worker-src 'self' blob:; manifest-src 'self';
frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none';
upgrade-insecure-requests
```

How it was proven, and how to prove it again:

1. Serve it as `Content-Security-Policy-Report-Only` first. Load the dashboard
   with a staff session and a `securitypolicyviolation` listener installed via
   CDP `Page.addScriptToEvaluateOnNewDocument` (installing it in the page is too
   late — the bootstrap has already run). Tour the screens; expect zero.
2. **Prove the listener itself fires** by requesting an image from a host the
   policy does not allow. Without this step a zero is indistinguishable from a
   broken collector.
3. Flip to enforced, then confirm nothing was blocked (`disposition: 'enforce'`
   in the violation events) and that the live feed still says "connected" — a
   websocket is the one thing `'self'` does not cover in every browser, hence the
   explicit `wss://`.

What it buys even with `'unsafe-inline'` in `script-src`: an injected script
cannot phone home. `fetch()` to another origin throws, and `<img>` beacons never
load — verified live, not assumed.

The report-only policy served alongside it drops `'unsafe-inline'` from
`script-src`. Its violations on a page load are the cost of a nonce migration:
8 inline scripts, which is Next.js's own bootstrap. Until that migration the
enforced policy stays as measured.

## The money gate, and the two ways it was not doing its job

Entitlement ("may this guild write, judged on money alone") has to sit where the
writes actually happen. It lived in the tool dispatcher, which covers every
tool-backed write — but three dashboard and Discord writes never pass through
it: closing a ticket, releasing a hold, deciding an appeal. Each calls its
service directly, so a lapsed subscription could still do all three.

Two defects, both now fixed:

1. **The gate was missing on those paths.** The check now lives in
   `writeBlocked()` (`src/services/security/killswitch.js`) and
   `appealWriteBlocked()`, which are the last checkpoints those services call.
2. **The read-only exemption was a dead letter on those same paths.** Both
   services called their gate without a guild id, so `readOnlyForGuild(null)`
   refused *every* guild — including the ones named in
   `SLOTH_LEE_READONLY_EXCEPT`. On a box with `READONLY=1` a ticket close was
   refused for the wrong reason, and the exemption it advertises did nothing.

The lesson generalises: **a write gate that forgets the guild id silently
disables the exception the gate exists to provide.** When a gate takes an
optional guild id, check every call site passes it.

### Proving it (do this after any change to the gate)

`scripts/money-drill.mjs` in the bot repo drives the real endpoint with a staff
session and a signed Paddle webhook. On a test guild:

1. set `trial_ends_at` in the past, `paid_until` null → `read` returns 200 and
   `entitlement.state` is `expired`; a `ticket_close` returns **403 with the
   billing line**.
2. `webhook-pay` (signed with the configured secret) → `paidUntil` extends; the
   same close now gets past the gate (it fails later, on the drill ticket having
   no real Discord thread — that is the proof it passed).
3. `webhook-cancel` with a period that already ended → the close is refused with
   the billing line again, and reads stay 200 throughout.
4. Restore the row to `null/null` (legacy) and delete the drill tickets.

A single refusal is not proof of the right refusal: read the message. A CSRF
refusal and a read-only refusal both say 403, and the drill once "passed" on a
wrong `csrf` field name before the field was corrected to `csrfToken`.

## Public site headers (slothlee.xyz, www)

The marketing site is `sloth-site` on `:3100`, proxied by
`/etc/nginx/sites-available/app.slothlee.xyz` (the file name predates the split;
it serves the apex and www, not the dashboard). Backups:
`/root/site.pre-csp.<epoch>`.

Until now it answered with **no** CSP, nosniff, referrer policy or permissions
policy — while the dashboard next door had all four. The public site is the one
anyone can load, so that was the wrong way round.

Enforced CSP (measured, not guessed):

```
default-src 'none'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';
img-src 'self' data: https:; font-src 'self' data:;
connect-src 'self' https://app.slothlee.xyz; media-src 'self' https:;
frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none';
upgrade-insecure-requests
```

The one cross-origin call the site makes is the **status page's health poll** to
`https://app.slothlee.xyz/healthz`. That host is named explicitly; nothing else
is. Verified live: that fetch returns 200 while a fetch to any other origin
throws.

The report-only policy alongside it drops `'unsafe-inline'` from `script-src`.
It reports **4 inline scripts per page** — the site's share of the nonce work
(the dashboard's is 8).

A trap worth remembering: the very first report-only tour showed 27 violations
on `/mail` that never reproduced. They were stale documents/chunk references
from before the header existed. **Re-tour on a clean load before believing a
violation count**, otherwise you widen a policy to satisfy a cache.
