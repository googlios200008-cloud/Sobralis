#!/bin/sh
set -eu
# Refuse missing, example, short, or reused passwords before creating application roles.
for secret in "$POSTGRES_PASSWORD" "$APP_DB_PASSWORD" "$MIGRATOR_DB_PASSWORD"; do
  if [ "${#secret}" -lt 32 ]; then echo "Passwords must contain at least 32 characters" >&2; exit 1; fi
  case "$secret" in *REPLACE_WITH*) echo "Replace example passwords before starting" >&2; exit 1;; esac
done
if [ "$POSTGRES_PASSWORD" = "$APP_DB_PASSWORD" ] || [ "$POSTGRES_PASSWORD" = "$MIGRATOR_DB_PASSWORD" ] || [ "$APP_DB_PASSWORD" = "$MIGRATOR_DB_PASSWORD" ]; then
  echo "Database passwords must be distinct" >&2; exit 1
fi
# The official PostgreSQL image executes this only for a new, empty data volume.
# psql reads passwords from the environment; they are not passed as CLI arguments.
psql --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" -v ON_ERROR_STOP=1 --quiet <<'SQL'
\getenv app_pw APP_DB_PASSWORD
\getenv migrate_pw MIGRATOR_DB_PASSWORD
\getenv db_name POSTGRES_DB
SELECT format('CREATE ROLE sobralis_runtime LOGIN PASSWORD %L', :'app_pw') \gexec
SELECT format('CREATE ROLE sobralis_migrator LOGIN PASSWORD %L', :'migrate_pw') \gexec
SELECT format('REVOKE ALL ON DATABASE %I FROM PUBLIC', :'db_name') \gexec
SELECT format('GRANT CONNECT ON DATABASE %I TO sobralis_runtime, sobralis_migrator', :'db_name') \gexec
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE, CREATE ON SCHEMA public TO sobralis_migrator;
GRANT USAGE ON SCHEMA public TO sobralis_runtime;
SQL
