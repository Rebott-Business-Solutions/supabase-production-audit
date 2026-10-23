# Changelog

All notable changes are recorded here. This project uses [semantic versioning](https://semver.org/): adding a check is a minor release, and changing a check's ID or the output columns is a major release.

## Unreleased

## 0.1.0 (2026-10-23)

First public release.

- `audit.sql`: eleven read-only checks covering row-level security, `SECURITY DEFINER` functions, owner-run and materialized views, views over `auth.users`, and permissive or slow policies.
- `CHECKLIST.md`: the checks a query can't do, covering keys, Edge Functions, auth settings, storage, migrations, operations and front end.
- Fixture tests, run in CI against Postgres 15, 16 and 17.
