# Supabase production audit

[![Tests](https://github.com/Rebott-Business-Solutions/supabase-production-audit/actions/workflows/test.yml/badge.svg)](https://github.com/Rebott-Business-Solutions/supabase-production-audit/actions/workflows/test.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

This is a read-only SQL check for the mistakes we keep finding in Supabase apps that are already live, including apps built with Lovable, Bolt, v0 and other AI tools. It comes with a short checklist for the things a query can't see.

It's what we run first when we audit a client's project, and it's free to use.

- **One `SELECT`.** It doesn't create, change or call anything, so it's safe to run against production.
- **Nothing leaves your database.** There's no install, no account and no telemetry. You paste a query and read the rows it returns.
- **Every finding comes with its fix,** written as SQL you can review before you run it.

## Quick start

**Supabase dashboard:** open the **SQL editor**, paste in [`audit.sql`](audit.sql) and click **Run**.

**psql:**

```bash
curl -fsSLO https://raw.githubusercontent.com/Rebott-Business-Solutions/supabase-production-audit/main/audit.sql
psql "$DATABASE_URL" -f audit.sql
```

If you'd like a guarantee rather than our word that it changes nothing, run it inside a read-only transaction:

```bash
psql "$DATABASE_URL" -c 'begin read only' -f audit.sql -c 'rollback'
```

Read the file before you run it. It's one commented query, and you should never paste SQL from the internet into production without reading it, ours included.

## What it checks

| Check | Severity | What it means |
|---|---|---|
| `rls_disabled` | high / medium | A table with row-level security off that the API roles can reach. |
| `definer_function_callable_by_anon` | high | A `SECURITY DEFINER` function anyone with your publishable key can call. |
| `definer_function_callable_by_authenticated` | medium | The same, but callable by any signed-in user. |
| `definer_function_mutable_search_path` | medium | A `SECURITY DEFINER` function with no pinned `search_path`. |
| `owner_run_view_exposed` | high / medium | A view without `security_invoker`, readable through the API. It ignores the RLS of the tables under it. |
| `materialized_view_exposed` | high / medium | A materialized view (these never have RLS) readable through the API. |
| `view_reads_auth_users` | high / medium | A view over `auth.users` readable through the API. |
| `policy_allows_anon_write` | high | A permissive policy whose condition is `true` that lets `anon` insert, update or delete. |
| `policy_calls_auth_per_row` | low | `auth.uid()` called bare in a policy, so it runs once per row instead of once per query. |
| `policy_allows_anon_read` | info | A policy that lets `anon` read every row. Often intended. |
| `rls_no_policies` | info | RLS on with no policies, so only `service_role` gets in. Often intended. |

**High** means the publishable key can reach it, and that key ships in your JavaScript bundle. **Medium** means any signed-in user can reach it, or it's a known way to get things wrong.

### The one most people miss

On Supabase, every new function in `public` is granted to `anon` and `authenticated` **by name**. The usual Postgres lockdown, `REVOKE ALL ON FUNCTION f() FROM PUBLIC`, removes the `PUBLIC` grant and leaves those two in place, so the function is still callable by anyone. Revoke each role by name:

```sql
REVOKE EXECUTE ON FUNCTION public.f() FROM PUBLIC, anon, authenticated;
GRANT  EXECUTE ON FUNCTION public.f() TO service_role;
```

[This teardown](https://rebott.co.za/blog/revoke-from-public-supabase) shows how it played out on a real multi-tenant app.

## Reading the results

A finding is a question, not a verdict. A `SECURITY DEFINER` function that `anon` can call is fine if its body checks who's calling before it does anything. Many Supabase apps have a helper like `is_admin()` that has to be callable for their policies to work. What matters is that you can give a one-sentence reason for every row.

An empty result doesn't mean the project is secure, only that none of these checks fired. Supabase's own **Security Advisor** and **Performance Advisor** (in the dashboard) cover different ground, so run those too.

The query checks the `public` schema, which is the one the Data API exposes by default. If you expose other schemas, add them to the `audited` list at the top of the file.

## What a query can't see

Some of the worst problems we find live outside the database: auth settings that differ between staging and production, a rate limiter that's switched off because a secret was never set, or Edge Functions that stopped deploying weeks ago. [`CHECKLIST.md`](CHECKLIST.md) covers those, and how to check each one.

## Compatibility

The tests run on every push against Postgres 15, 16 and 17, which covers the versions Supabase runs. The query only reads the system catalogs, so it also works on plain Postgres with roles named `anon` and `authenticated`.

## Tests

`test/run.sh` loads [`test/fixtures.sql`](test/fixtures.sql) into a throwaway database, then checks that the audit reports exactly what [`test/expected.txt`](test/expected.txt) lists. The fixtures are shaped like a Supabase project, with one example of each problem and a correct counterpart. The script needs a disposable Postgres server, never a real project. Its header explains how to start one with Docker.

## Contributing

Issues and pull requests are welcome, especially new checks and false positives. Start with [CONTRIBUTING.md](CONTRIBUTING.md). Never include anything from a real project (names, schemas, keys, data) in an issue.

Found a problem in the tool itself? See [SECURITY.md](SECURITY.md).

## Who made this

This is by [Rebott Business Solutions](https://rebott.co.za), a South African software firm. We build and run production apps on Supabase, and we audit and harden other people's. The [teardowns on our blog](https://rebott.co.za/blog) explain where several of these checks came from.

We're not affiliated with Supabase. "Supabase" is a trademark of Supabase, Inc.

[MIT licensed](LICENSE).
