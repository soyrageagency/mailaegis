#!/bin/sh
#
# MailAegis — Postfix content filter.
#
#   /usr/local/bin/mailaegis-filter
#
# Postfix pipes the message on stdin and passes the envelope on the command
# line. This scans it, stamps the verdict into the headers, and hands it back
# to sendmail for delivery — or refuses it.
#
# The four rules this script exists to get right:
#
#   **Never lose mail.** Every failure that is not a verdict — the scanner
#   missing, a timeout, a full disk — exits 75 (EX_TEMPFAIL), so Postfix keeps
#   the message queued and retries. Delivering unscanned mail because the
#   scanner fell over is the worst outcome available, and exiting 0 on error is
#   how that happens.
#
#   **Never write to a predictable path.** The temporary file holds somebody's
#   entire message. mktemp in a private directory, mode 600, removed on every
#   exit path including a signal.
#
#   **Say what it decided.** The headers travel with the message, so the next
#   hop, the user's rules and any later investigation can all see the verdict
#   without re-running anything.
#
#   **Refuse rather than guess.** Malicious is rejected outright. Suspicious is
#   delivered *with the header*, because a filter that silently swallows
#   borderline mail trains people to stop trusting it.
#
# Crafted by SoyRage Agency — https://soyrage.es/
# Licensed under the SoyRage Attribution License (see LICENSE).

set -eu

# Where the sendmail binary lives, and how to reach MailAegis. Override in the
# environment or edit here.
SENDMAIL="${SENDMAIL:-/usr/sbin/sendmail}"
MAILAEGIS="${MAILAEGIS:-mailaegis}"

# EX_TEMPFAIL: Postfix requeues and retries rather than bouncing.
EX_TEMPFAIL=75
# EX_UNAVAILABLE: Postfix bounces the message back to the sender.
EX_UNAVAILABLE=69

# A private working directory. Falling back to /tmp is fine because mktemp -d
# creates it mode 700 with an unguessable name.
WORKDIR=$(mktemp -d "${TMPDIR:-/tmp}/mailaegis.XXXXXXXXXX") || exit "$EX_TEMPFAIL"
trap 'rm -rf "$WORKDIR"' EXIT HUP INT TERM

MESSAGE="$WORKDIR/message"
(umask 077 && cat > "$MESSAGE") || exit "$EX_TEMPFAIL"

# --- Scan --------------------------------------------------------------------
# `scan` exits 0 clean · 1 suspicious · 2 malicious · 3 its own error. `set -e`
# would abort on any non-zero, so the status is captured deliberately.
VERDICT_JSON="$WORKDIR/verdict.json"
set +e
"$MAILAEGIS" scan --json < "$MESSAGE" > "$VERDICT_JSON" 2> "$WORKDIR/stderr"
STATUS=$?
set -e

case "$STATUS" in
  0|1|2) ;;
  *)
    # The scanner failed, or was not found. Requeue: this message has not been
    # examined, and pretending otherwise is the one thing we must not do.
    logger -t mailaegis-filter "scan failed (exit $STATUS): $(head -c 200 "$WORKDIR/stderr" 2>/dev/null)" 2>/dev/null || true
    exit "$EX_TEMPFAIL"
    ;;
esac

# The **exit code is the contract**; the JSON is decoration. Deriving the
# verdict from the status means a change to the report's shape can never turn
# a malicious message into a delivered one — and it is why an earlier version
# of this script was wrong: it scraped `"verdict":"clean"` from the JSON, which
# is pretty-printed with a space after the colon, so the field came back empty
# and every message tempfailed.
case "$STATUS" in
  0) VERDICT=clean ;;
  1) VERDICT=suspicious ;;
  2) VERDICT=malicious ;;
esac

# Score and reference are a convenience for whoever reads the headers later, so
# they are extracted leniently and their absence is not fatal.
SCORE=$(sed -n 's/.*"score"[[:space:]]*:[[:space:]]*\([0-9]*\).*/\1/p' "$VERDICT_JSON" 2>/dev/null | head -1)
ID=$(sed -n 's/.*"id"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$VERDICT_JSON" 2>/dev/null | head -1)

logger -t mailaegis-filter "${ID:-unknown}: $VERDICT (${SCORE:-0}/100)" 2>/dev/null || true

# --- Malicious: refuse -------------------------------------------------------
if [ "$STATUS" -eq 2 ]; then
  echo "MailAegis rejected this message: $VERDICT (${SCORE:-0}/100), ref ${ID:-unknown}" >&2
  exit "$EX_UNAVAILABLE"
fi

# --- Stamp the verdict into the headers --------------------------------------
# Prepended, so they land in the header block ahead of everything the sender
# wrote — including any X-MailAegis-* header they tried to forge.
STAMPED="$WORKDIR/stamped"
{
  printf 'X-MailAegis-Verdict: %s\n' "$VERDICT"
  printf 'X-MailAegis-Score: %s\n' "${SCORE:-0}"
  printf 'X-MailAegis-Ref: %s\n' "${ID:-unknown}"
  # Strip any inbound copies: a header the sender supplied must not be
  # mistaken for ours by whatever reads this next.
  sed '/^[Xx]-[Mm]ail[Aa]egis-/d' "$MESSAGE"
} > "$STAMPED"

# --- Hand it back to Postfix -------------------------------------------------
# -i so a lone dot in the body does not end the message, -G because this is a
# gateway submission, and "$@" carries the envelope Postfix gave us.
"$SENDMAIL" -G -i "$@" < "$STAMPED" || exit "$EX_TEMPFAIL"
exit 0
