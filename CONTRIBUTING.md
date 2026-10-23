# Contributing

Thanks for helping. The most useful contributions are:

- **A false positive:** the audit flags something that's safe. Open an issue with a minimal, made-up example that reproduces it.
- **A missed problem:** a Supabase mistake you've seen in the wild that the query could detect. Open an issue describing the pattern before writing SQL, so we can agree it belongs here.
- **A checklist item** for something a query can't see, with how to check it.

## Ground rules

1. **`audit.sql` stays one read-only `SELECT`.** No DDL, DML, `SET`, temporary objects, or calls to functions in the audited schemas. It must be safe to paste into a production SQL editor. Use `has_function_privilege` and `has_table_privilege` to ask whether a role *can* do something. Never actually do it.
2. **Every check has a fix.** Each finding row includes a `fix` column a reader can act on.
3. **Every check is tested.** Add a bad example *and* a correct counterpart to `test/fixtures.sql`, and the expected line to `test/expected.txt`. The counterpart proves the check doesn't fire on correct code.
4. **No real data, ever.** Issues, PRs, fixtures and examples use invented names only. Don't paste output from a real project, and don't name a client or company.
5. **Plain language.** Write `detail` text for someone who built their app with an AI tool and has never heard of `pg_proc`.

## Running the tests

You need a disposable Postgres 15 or later. The tests create the cluster-wide roles `anon`, `authenticated` and `service_role`, so never point them at a real server.

```bash
docker run -d --name audit-pg -e POSTGRES_HOST_AUTH_METHOD=trust -p 54329:5432 postgres:17
PGHOST=127.0.0.1 PGPORT=54329 PGUSER=postgres test/run.sh
```

CI runs the same script against Postgres 15, 16 and 17.

## Pull requests

- Keep each PR to one change, and describe what it detects and why it matters.
- Add a line under **Unreleased** in `CHANGELOG.md`.
- By contributing, you agree your work is released under the [MIT licence](LICENSE).

Please follow the [code of conduct](CODE_OF_CONDUCT.md).
