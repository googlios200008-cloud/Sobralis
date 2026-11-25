#!/bin/sh
# Creates configuration only once; never resets a volume or overwrites passwords.
set -eu
cd "$(dirname "$0")/.."
if ! command -v docker >/dev/null 2>&1 || ! docker compose version >/dev/null 2>&1; then
  echo 'Docker и Docker Compose v2 необходимы для локального тестового стенда.' >&2
  exit 1
fi
if [ ! -f .env.demo ]; then
  umask 077
  python3 - <<'PY'
import os, secrets
fd=os.open('.env.demo',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
with os.fdopen(fd,'w') as f:
 for key in ('POSTGRES_PASSWORD','APP_DB_PASSWORD','MIGRATOR_DB_PASSWORD','CSRF_SECRET'):
  f.write(f'{key}={secrets.token_hex(32)}\n')
PY
fi
docker compose --env-file .env.demo -f compose.demo.yaml up --build -d
printf '%s\n' 'Стенд запускается на http://localhost:4175 — только на этом компьютере.' 'Это общая синтетическая демонстрация: не вводите реальные персональные данные.' 'Для остановки: docker compose --env-file .env.demo -f compose.demo.yaml down (данные сохраняются).'
