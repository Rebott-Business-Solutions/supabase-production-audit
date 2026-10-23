#!/usr/bin/env bash
# Loads test/fixtures.sql into a fresh database, runs audit.sql against it and
# compares severity | check | object with test/expected.txt.
#
# Needs a Postgres 15+ server you can create databases on, e.g.
#   docker run -d --name audit-pg -e POSTGRES_HOST_AUTH_METHOD=trust -p 54329:5432 postgres:15
#   PGHOST=127.0.0.1 PGPORT=54329 PGUSER=postgres test/run.sh
#
# The roles it creates (anon, authenticated, service_role) are cluster-wide, so
# use a throwaway server, never a real project.
set -euo pipefail
cd "$(dirname "$0")/.."

db="audit_test_$$"
psql -X -q -v ON_ERROR_STOP=1 -d postgres -c "create database $db"
trap 'psql -X -q -d postgres -c "drop database if exists $db"' EXIT

# Roles are cluster-wide; tolerate them existing from an earlier run.
psql -X -q -d "$db" -c "do \$\$ begin
  if not exists (select from pg_roles where rolname = 'anon') then create role anon nologin; end if;
  if not exists (select from pg_roles where rolname = 'authenticated') then create role authenticated nologin; end if;
  if not exists (select from pg_roles where rolname = 'service_role') then create role service_role nologin bypassrls; end if;
end \$\$;"
sed '/^create role /d' test/fixtures.sql | psql -X -q -v ON_ERROR_STOP=1 -d "$db" -f -

actual=$(psql -X -q -v ON_ERROR_STOP=1 -d "$db" -A -t -F ' | ' -f audit.sql | cut -d'|' -f1-3 | sed 's/ *$//')
if diff -u test/expected.txt <(printf '%s\n' "$actual"); then
  echo "audit.sql: all checks behave as expected"
else
  echo "audit.sql output differs from test/expected.txt" >&2
  exit 1
fi
