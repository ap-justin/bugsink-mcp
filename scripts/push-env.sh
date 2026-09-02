#!/bin/sh
# Pushes the values in .env to Fly as encrypted secrets.
#
#   ./scripts/push-env.sh            # push and restart the app
#   ./scripts/push-env.sh -n         # show what would be pushed, change nothing
#   ./scripts/push-env.sh --stage    # store them, apply on the next deploy
#   ./scripts/push-env.sh -f other.env
#
# Blank values and comments are skipped, so an unfilled .env pushes nothing.
# Names beginning LOCAL_ stay on this machine and are never sent.
# Values are piped in over stdin, keeping them out of your shell history.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

DRY=0; STAGE=""; DIR="$ROOT"; ENVFILE=""
while [ $# -gt 0 ]; do
  case $1 in
    -n|--dry-run) DRY=1; shift ;;
    --stage) STAGE="--stage"; shift ;;
    -f) ENVFILE=${2:?-f needs a path}; shift 2 ;;
    -h|--help) sed -n '2,10p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

[ -f "$DIR/fly.toml" ] || { echo "no $DIR/fly.toml" >&2; exit 1; }
APP=$(awk -F'"' '/^app *=/{print $2}' "$DIR/fly.toml")
[ -n "$ENVFILE" ] || ENVFILE="$DIR/.env"

[ -f "$ENVFILE" ] || { echo "no $ENVFILE — copy .env.example to .env first" >&2; exit 1; }

# Keep KEY=VALUE lines that have a non-empty value; strip surrounding quotes.
# LOCAL_* is dropped here: the server reads none of it.
PAIRS=$(sed -e 's/\r$//' "$ENVFILE" \
  | grep -E '^[A-Za-z_][A-Za-z0-9_]*=' \
  | grep -v '^LOCAL_' \
  | sed -e 's/=["'"'"']\(.*\)["'"'"']$/=\1/' \
  | awk -F= 'length($2) > 0')

if [ -z "$PAIRS" ]; then
  echo "nothing to push — every value in $ENVFILE is blank"
  exit 0
fi

echo "secrets to set on $APP:"
echo "$PAIRS" | cut -d= -f1 | sed 's/^/  /'

if [ "$DRY" = "1" ]; then
  echo "(dry run — nothing sent)"
  exit 0
fi

echo "$PAIRS" | fly secrets import -a "$APP" $STAGE
