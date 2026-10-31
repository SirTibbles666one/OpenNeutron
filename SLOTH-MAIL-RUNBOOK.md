# Sloth Lee Mail — operator runbook

Server: `mail.slothlee.xyz` (46.62.155.175, Hetzner CPX22, Ubuntu). Everything below runs as root.

## What is running

| Piece | What it does | Check |
|---|---|---|
| Postfix :25 | Public MX, TLS, rspamd milter, recipient map | `systemctl status postfix` |
| OpenNeutron (docker `openneutron`) | Mailbox store, HTTP API :8080, SMTP :2525 | `docker ps`, `docker logs --tail 50 openneutron` |
| nginx :443 | Web client + WKD vhost | `systemctl status nginx` |
| rspamd + redis | Spam scoring, greylist, ratelimits | `docker ps` |
| cron `sync-recipients.py` | Keeps `/etc/postfix/recipients` in step with accounts | takes ~1 min after creating a user |

Health one-liner: `mail-health.sh` (silent when healthy).

## Everyday operations

**Approve a self-registered account** (no invite code needed any more)
A signup at `/signup` creates the account but holds it: login answers "waiting
for approval" until it is accepted.

Panel → Admin → **Pending accounts** → *Approve* (or ✕ to deny, which deletes
the account). Each row shows when it was requested and the address it came from.

CLI equivalent:
```
mail-pending                        # list what is waiting
mail-pending approve <username>     # activate
mail-pending deny <username>        # delete the account and the request
```
Deleting the entry from `/opt/on/data/pending_users.json` on the host is the same
activation, and is the way out if a server has no administrator yet: a pending
account is never created as an admin, so there is nobody to press the button.

An invite code still works and still admits an account immediately — the
Invites panel is unchanged, it is now just optional rather than required.

**Approve someone who asked for access**
Panel → Admin → Invites → *Approve* → *Copy code + link*. Send it to them.
CLI equivalent: `mail-waitlist list` / `mail-waitlist approve someone@example.com`.

**Send a password-reset email** (last resort — costs the archive)
Panel → Admin → key icon on the row → set a recovery address → *Send recovery email*.
If mail fails, the panel hands you the same link to send yourself. The link works once, 60 minutes.

**Recovery keys** (the good path — keeps old mail)
Users create them in the key panel, or are prompted by the banner. A key is single-use: after use they must create a new one. Nothing to do server-side.

**Create an account by hand**
`POST /api/admin/users {"username":"x"}` returns a `setup_token`; the user signs in with that token as their password and is walked through key creation.

**Disappearing messages** (send-side feature, nothing to do unless something sticks)
A sender can mark a message "Deletes after reading" (or 1 h / 1 d / 7 d) in compose.
The recipient's stored copy is deleted the moment its body is served, or when the
timer runs out (swept every 60 s). Limits: only mailboxes on this server — another
provider keeps its own copy — and the sender's own copy stays in Sent, with a
receipt ("Read by …"). Both are stated in the UI.

- Records: `data/ephemeral.json`; read-only inspection is safe:
  `python3 -c "import json;d=json.load(open('/opt/on/data/ephemeral.json'));print(len(d['entries']),'armed /',len(d['receipts']),'receipts')"`
- A stuck message (rule recorded, blob gone) is pruned automatically on the next
  sweep; no manual step.
- To stop enforcing a rule on a specific message, remove its uid from `entries` and
  restart — the message then behaves like ordinary mail. There is no UI for this.
- Log lines: `[Ephemeral] <user> opened and deleted uid=…`, `[Ephemeral] Expired …`,
  `[Ephemeral] Could not delete …` (that last one means the copy is **still there**
  and the reader was told so).

**Sealed notes** (disappearing mail for recipients on other providers)
A sender can turn on "Sealed link" in compose — it appears only when a recipient
is on another provider. The body is then not emailed at all: the client encrypts
it to that recipient's OpenPGP key and `POST /api/note/create` stores the armour
here. The recipient gets a short email with a link; opening the link serves the
armour once and deletes it. This is the only way a disappearing rule reaches a
provider we do not control, and the UI says so.

- Records: `data/notes.json` — `{"notes":{token:{…}}}`. Bodies are cleared on
  open or expiry; the row stays 30 days so the sender can see "opened"/"expired".
  Inspection: `python3 -c "import json;d=json.load(open('/opt/on/data/notes.json'));print(sum(1 for n in d['notes'].values() if n.get('armored')),'sealed /',len(d['notes']),'rows')"`
- The page is `/api/note?t=<token>`; the open call is `POST /api/note/open`. A
  plain GET never consumes a note, deliberately: mail providers and scanners
  fetch links, and a fetched link must not burn the message.
- Two locks: "their key" (armour to the recipient's OpenPGP key, burned on
  fetch) and "a passphrase" (symmetric; the page decrypts in the browser and
  calls `POST /api/note/burn`; survives a wrong phrase, dies after 5 fetches or
  the timer). The phrase is generated in compose and recorded in the sender's
  Sent copy — never in the email.
- Sender-side: a sent copy carries `link:`/`passphrase:` lines, and the message
  view turns them into a panel — state, copy link, copy phrase, and **withdraw**
  (`POST /api/note/revoke`, 409 once it has been read).
- The note page loads `openpgp.min.js` from `data/static/`; if it 404s the
  passphrase box stops working, so that file must ship with the frontend.
- Links are built from `server.public_url` in `config.yml`
  (`https://mail.slothlee.xyz`); without it the request's Host header is used.
- "Recipient cannot open it" usually means their client does not decrypt an
  `.asc` / armour they were handed. They can paste it into `gpg --decrypt` or
  their PGP client; nothing server-side is involved.
- Log lines: `[Notes] Open failed…`, `[Notes] sweep could not write…`.
- A note whose notification bounced is unreachable — nobody has the link — and
  its timer (default 7 days) clears it.

**Self-registered accounts finish key setup themselves**
After approval they sign in and land on "Create your encryption keys"; `POST
/user/setup` now accepts an account that has a password but no keys yet. It does not
change their password. If someone is stuck on "Administrator privileges required",
they are on a build older than 2026-10-28 — the old client tried to delete and
re-create the account, which only an admin can do.

## Backups

Local snapshots: `/opt/data/backups/mail/<timestamp>/state.tgz` (cron `mail-backup`, 03:30).
Off-site: encrypted archive pushed to the private repo `SirTibbles666one/sloth-mail-backups`.
The archive includes `data/pending_users.json` (the approval queue) and
`data/ephemeral.json` (disappearing-message records) — a new `data/*.json` sidecar
must be added to the tar list in `mail-offsite-backup.sh`, otherwise a restore
silently loses that feature's state. Both are pre-created by the script when missing,
because a missing tar member makes tar exit non-zero under `set -e` and skips the
whole backup.

Restore (any backup):
```
systemctl stop docker   # or: docker stop openneutron
cd /opt/on/data && tar xzf <state.tgz>     # users.bin, blobs/, waitlist.json, recovery.json
cd /opt/on && docker cp users.bin openneutron:/usr/src/app/data/ 2>/dev/null || true
docker start openneutron
md5sum /opt/on/data/users.bin              # compare with the snapshot's copy
```
A restored `users.bin` must load with the same number of accounts in the log line
`[Storage] Loaded N users`.

## Traps that have bitten before

- **Never add a field to `User`.** `users.bin` is bincode (positional); a new field makes
  every account unreadable (`get_user` returns None → all requests 401) and the next save
  writes a stub over the store. Put new state in `data/recovery.json` instead.
  If it happens: stop the container, restore `data/users.bin.bak`, rebuild with the old
  struct, then start.
- **Pending signups are not recipients.** `sync-recipients.py` skips accounts whose
  `/api/admin/users` row has `pending: true`, so mail to an unapproved address bounces
  `550` instead of being stored for a mailbox nobody can read. Approving changes the map
  on the next sync (5s), so mail to a freshly approved account can bounce for a moment.
- **A pending account is never an administrator**, even when it is the first account on a
  fresh store — otherwise a stranger could approve themselves into admin. On a new server
  with approval mode on, activate the first account by removing its entry from
  `data/pending_users.json` and promote it afterwards.
- **Bump `sloth-mail-shell-vN` in `public/sw.js` on every client deploy**, or phones keep
  serving the previous build and new UI looks "not deployed".
- **Password resets must rotate the salt before `seal_password`** (the pepper uses the salt).
  A recovery-key restore must **not** rotate it (the client re-wraps with the existing one).
- **The container has no local MTA.** Outbound system mail goes to the docker bridge
  gateway (`172.18.0.1:25`); Postfix `mynetworks` must include `172.17.0.0/16 172.18.0.0/16`.
- **Mail to a brand-new account bounces `550 User unknown` for about a minute** until
  `sync-recipients.py` runs. Self-heals; not a bug.
- **WKD must be verified with GnuPG**, never curl: `gpg --auto-key-locate clear,wkd
  --locate-external-key tibs@slothlee.xyz`.

## Certificates

`certbot renew --dry-run` should pass for `mail.slothlee.xyz` and `openpgpkey.slothlee.xyz`
(expiry Jan 24 2027, nginx authenticator). Renewal is automatic via the certbot timer.

## If the server is lost

1. Build a new host, point the A/AAAA for `mail` and the MX at it.
2. Install Postfix + Docker, restore `config.yml`, `dkim/slothlee.xyz.pem`, `data/` from the
   newest off-site archive.
3. Start OpenNeutron, confirm `Loaded N users`, then re-issue TLS certs.
4. Mail sent during the outage is queued by senders and will arrive; nothing is lost by us.

## Disposable addresses (aliases)

`data/aliases.json` holds `{"aliases": {"<local>": {username, label, created_at,
disabled_at, received}}}`. Ten per account; never a field on `User`.

Delivery: the SMTP loop in `main.rs` resolves a local part to an account through
`core::aliases::resolve` when no user answers to the name, then proceeds exactly
as for a real address. A switched-off alias resolves to nothing and is refused.

Postfix decides what it will accept **before** the message reaches us, from
`/etc/postfix/recipients`. `sync-recipients.py` rebuilds that map every 5 seconds
(systemd `sync-recipients.timer`) from `GET /api/admin/recipients`, which returns
accounts (pending excluded) plus switched-on aliases. If that endpoint fails the
script leaves the old map alone — an empty map would reject all real mail.

Adding a new `data/*.json` sidecar means adding it to the tar list in
`/usr/local/bin/mail-offsite-backup.sh`, or a restore silently drops it. That
list now covers `pending_users.json`, `ephemeral.json`, `notes.json` and
`aliases.json`; the guard line for each must test **one** file (`[ -f a ] ||`, not
`[ -f a b ]`, which silently always fails and blanks the file).

## Scheduled send

`data/scheduled.json` holds `{"items": {"<id>": {owner, to, kind, data, subject,
created_at, send_at, status, sent_at, error}}}`. `kind` is `raw` (base64 MIME,
delivered with `emailutils::deliver_raw`) or `encrypted` (the whole
`SendEncryptedRequest` as JSON, replayed through `/api/email/sendencrypted` by the
sweeper with a short-lived token minted for the owner — so encryption, the sent
copy and the disappearing rule stay the endpoint's job).

The sweeper runs in the 30-second thread in `main.rs`. Body bytes are cleared when
an item finishes, sent or failed. Fifty pending per account; `sweep_old` prunes
finished rows after a day. `data/scheduled.json` is in the backup tar list.

## Sealed-note attachments

`Note.files: Vec<NoteFile {name, armored, size}>` lives inside the note record in
`data/notes.json`, so deleting the note deletes its files: there is no separate
blob directory to leak or forget. Bodies and files are cleared together in
`open` (key mode), `burn`, `revoke` and `sweep`.

Attachments are allowed only for passphrase notes — the page that can decrypt the
body can decrypt them, and in key mode the recipient is using their own client.
The client seals each file as a binary PGP message to the same phrase and sends
them in the same `/note/create` request, so the recipient's single fetch carries
everything and nothing is fetched after the burn.

## Replies from an alias

`data/arrival.json` maps message uid → alias local part, written in the SMTP path
when the recipient resolved through an alias and served to the client as `alias`
on `/email/bulk` and `/email/get`. It is in the offsite tar and pruned at 180 days.

Sending from an alias is validated server-side (`from_alias`): the local part must
belong to the caller and be switched on. The envelope sender is set by the server;
the `From:` header is written by the client, because on the encrypted path the
server cannot read headers. If you ever change the send path, keep both in step or
the visible sender and SPF will disagree.

## New-mail notifications (Web Push)

`data/push.json` holds one row per registered browser; `data/vapid.json` holds the
server's ES256 signing key. **Losing vapid.json invalidates every existing
subscription** — keep it in the offsite tar (it is). Both are sidecars, since a
`User` field would break the positional bincode store.

A pushed payload carries a sender only: no subject, no body. The endpoint is
validated against the push services browsers really use — Chrome's real endpoints
are `<something>.google.com/fcm/send/...`, not `fcm.googleapis.com`. Pushes are
sent on their own thread so delivery never waits on a push service, and a 404/410
deletes the dead subscription.
