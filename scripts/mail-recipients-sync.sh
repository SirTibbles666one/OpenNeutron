#!/usr/bin/env bash
# Keep Postfix's recipient map equal to the mailbox list the app considers real.
#
# Why: Postfix can refuse an unknown recipient at RCPT, which stops a bounce
# message before any data is transferred. It can only do that from a map that is
# actually maintained — a stale map is worse than no map, because it rejects
# real people. The app is the source of truth; this script copies its answer.
#
# The map is pcre, not hash, so the lookup is case-insensitive: addresses here
# are lowercase and our mailboxes are case-insensitive, so a sender writing
# Admin@slothlee.xyz must not be refused for a mailbox called admin.
#
# The role addresses are added by this script rather than read from the API.
# They are not accounts and cannot be aliases (the app reserves the names), but
# RFC 5321 requires postmaster@ to be deliverable and abuse@ is where complaints
# are expected; the app routes both to staff.
set -uo pipefail

API="http://127.0.0.1:8080/api/admin/recipients"
JWT_FILE="/root/.admin.jwt"
MAP="/etc/postfix/recipients.pcre"
STAGE="$(mktemp)"
trap 'rm -f "$STAGE"' EXIT

if [ ! -r "$JWT_FILE" ]; then
    echo "recipients-sync: no admin token at $JWT_FILE" >&2
    exit 1
fi
TOKEN="$(tr -d '\n' < "$JWT_FILE")"

BODY="$(curl -fsS --max-time 10 -H "Authorization: Bearer $TOKEN" "$API")" || {
    # Never fall through to writing an empty map: that would refuse every
    # recipient on the server because one API call timed out.
    echo "recipients-sync: API unreachable, leaving $MAP alone" >&2
    exit 1
}

DOMAIN="$(postconf -h relay_domains | awk '{print $1}')"
[ -n "$DOMAIN" ] || { echo "recipients-sync: no relay_domains" >&2; exit 1; }

printf '%s' "$BODY" | python3 -c '
import json, sys, re
domain = sys.argv[1]
data = json.load(sys.stdin)
names = {n.strip().lower() for n in data.get("recipients", []) if n.strip()}
names.update({"postmaster", "abuse", "hostmaster"})
for name in sorted(names):
    # Escape regex metacharacters in the local part; match without case.
    print("/(?i)^" + re.escape(name) + "@" + re.escape(domain) + "$/ OK")
' "$DOMAIN" > "$STAGE" || { echo "recipients-sync: could not build map" >&2; exit 1; }

COUNT="$(wc -l < "$STAGE")"
if [ "$COUNT" -lt 1 ]; then
    echo "recipients-sync: refusing to install an empty map" >&2
    exit 1
fi
for required in postmaster abuse; do
    grep -qi "${required}@" "$STAGE" || {
        echo "recipients-sync: map would omit ${required}@ — refusing to install" >&2
        exit 1
    }
done

if [ -f "$MAP" ] && cmp -s "$STAGE" "$MAP"; then
    exit 0
fi

install -m 0644 -o root -g root "$STAGE" "$MAP.new" && mv "$MAP.new" "$MAP"
echo "recipients-sync: installed $COUNT recipients for $DOMAIN"
