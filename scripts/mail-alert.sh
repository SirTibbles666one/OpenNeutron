#!/usr/bin/env bash
# Send one alert mail. Body on stdin, subject as the argument.
#
# Written because scheduled jobs that fail quietly are worse than jobs that do not
# run: a backup that stopped in August looks identical to one that ran last night
# until the day it is needed. Every cron line that matters ends in
# `|| <job output> | mail-alert.sh "subject"`.
#
# Deliberately uses /usr/sbin/sendmail — there is no `mail` binary on this host, and
# an alert path that silently fails is not an alert path.
set -uo pipefail

SUBJECT="${1:-alert from $(hostname)}"
BODY="$(cat)"
{
    printf 'Subject: %s\n' "$SUBJECT"
    printf 'From: root@slothlee.xyz\n'
    printf 'To: tibs@slothlee.xyz\n'
    printf 'Date: %s\n' "$(date -R)"
    printf '\n'
    printf 'Host: %s\n\n' "$(hostname)"
    printf '%s\n' "${BODY:-(no output captured)}"
} | /usr/sbin/sendmail -t
rc=$?
[ "$rc" -eq 0 ] && echo "alert sent: $SUBJECT" || echo "ALERT COULD NOT BE SENT: $SUBJECT (sendmail rc=$rc)" >&2
exit "$rc"
