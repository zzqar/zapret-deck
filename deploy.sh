#!/usr/bin/env bash
# Сборка и установка плагина на Steam Deck по SSH.
# Использование: ./deploy.sh [deck@steamdeck.local]
set -euo pipefail

HOST="${1:-deck@steamdeck.local}"
NAME="zapret-deck"
cd "$(dirname "$0")"

pnpm install --frozen-lockfile 2>/dev/null || pnpm install
pnpm build

STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
mkdir -p "$STAGE/$NAME"
cp -R dist main.py plugin.json package.json defaults py_modules "$STAGE/$NAME/"
tar -C "$STAGE" -czf "$STAGE/$NAME.tar.gz" "$NAME"

scp "$STAGE/$NAME.tar.gz" "$HOST:/tmp/$NAME.tar.gz"
ssh -t "$HOST" "sudo rm -rf ~/homebrew/plugins/$NAME \
  && sudo tar -C ~/homebrew/plugins -xzf /tmp/$NAME.tar.gz \
  && rm /tmp/$NAME.tar.gz \
  && sudo systemctl restart plugin_loader"

echo "Готово: плагин установлен на $HOST"
