-- =============================================================================
-- Supabase production audit: database checks, v0.1.0
-- https://github.com/Rebott-Business-Solutions/supabase-production-audit
-- SPDX-License-Identifier: MIT · Copyright (c) 2026 Rebott Business Solutions (Pty) Ltd
--
-- One read-only SELECT. It creates, changes and calls nothing. Paste it into
-- the Supabase SQL editor (or run it with psql) and read the rows it returns.
-- No rows means none of these checks found anything; it does not mean the
-- project is secure. See CHECKLIST.md for what a query cannot see.
--
-- Checks the `public` schema, which is what the Supabase Data API exposes by
-- default. If you expose more schemas, add them to `audited` below.
--
-- Severity:
--   high    reachable with the publishable key, the one in your JS bundle
--   medium  reachable by any signed-in user, or a known way to get it wrong
--   low     performance, or worth a second look
--   info    usually intended; confirm it is
-- =============================================================================

with audited(nspname) as (
  values ('public')
),

tables as (
  select c.oid, c.relname, n.nspname, c.relkind, c.relrowsecurity,
         format('%I.%I', n.nspname, c.relname) as name,
         has_table_privilege('anon', c.oid, 'SELECT,INSERT,UPDATE,DELETE') as anon_can,
         has_table_privilege('authenticated', c.oid, 'SELECT,INSERT,UPDATE,DELETE') as auth_can
  from pg_class c
  join pg_namespace n on n.oid = c.relnamespace
  join audited a on a.nspname = n.nspname
  where c.relkind in ('r', 'p', 'v', 'm')
),

definer_functions as (
  select p.oid,
         format('%I.%I(%s)', n.nspname, p.proname, pg_get_function_identity_arguments(p.oid)) as name,
         p.proconfig,
         has_function_privilege('anon', p.oid, 'EXECUTE') as anon_can,
         has_function_privilege('authenticated', p.oid, 'EXECUTE') as auth_can
  from pg_proc p
  join pg_namespace n on n.oid = p.pronamespace
  join audited a on a.nspname = n.nspname
  where p.prosecdef
    and p.prokind = 'f'
    -- Trigger functions cannot be called through the API.
    and p.prorettype <> 'trigger'::regtype
    and p.prorettype <> 'event_trigger'::regtype
    -- Functions that belong to an extension are the extension's business.
    and not exists (
      select 1 from pg_depend d
      where d.classid = 'pg_proc'::regclass and d.objid = p.oid and d.deptype = 'e'
    )
),

findings(severity, check_id, object, detail, fix) as (

  -- 1. A table with row-level security off is governed by grants alone.
  select case when anon_can then 'high' else 'medium' end,
         'rls_disabled',
         name,
         case when anon_can
           then 'Row-level security is off and anon holds privileges on it, so anyone with the publishable key can use this table through the API.'
           else 'Row-level security is off and authenticated holds privileges on it, so every signed-in user can read and write every row.'
         end,
         format('ALTER TABLE %s ENABLE ROW LEVEL SECURITY; then add a policy for each operation the app needs.', name)
  from tables
  where relkind in ('r', 'p') and not relrowsecurity and (anon_can or auth_can)

  union all

  -- 2. RLS on with no policies: only service_role (which bypasses RLS) gets in.
  select 'info', 'rls_no_policies', t.name,
         'Row-level security is on and no policy exists, so the API returns nothing for anon or authenticated. Correct for a server-only table; a bug if the app reads it from the browser.',
         'Leave it if only Edge Functions or service_role use it. Otherwise add policies.'
  from tables t
  where t.relkind in ('r', 'p') and t.relrowsecurity
    and not exists (select 1 from pg_policy pol where pol.polrelid = t.oid)

  union all

  -- 3. SECURITY DEFINER functions the publishable key can call.
  --    On Supabase, default privileges grant EXECUTE on every new function to
  --    anon and authenticated BY NAME, so REVOKE ... FROM PUBLIC leaves them.
  select 'high', 'definer_function_callable_by_anon', name,
         'Runs with its owner''s rights and anyone with the publishable key can call it at /rest/v1/rpc/. Unless its body checks the caller itself, it bypasses row-level security for the whole internet.',
         format('If only server code calls it: REVOKE EXECUTE ON FUNCTION %1$s FROM PUBLIC, anon, authenticated; GRANT EXECUTE ON FUNCTION %1$s TO service_role;', name)
  from definer_functions
  where anon_can

  union all

  select 'medium', 'definer_function_callable_by_authenticated', name,
         'Runs with its owner''s rights and any signed-in user can call it. Confirm the body checks who the caller is, which tenant they belong to and what role they hold.',
         format('If only server code calls it: REVOKE EXECUTE ON FUNCTION %1$s FROM PUBLIC, anon, authenticated; GRANT EXECUTE ON FUNCTION %1$s TO service_role;', name)
  from definer_functions
  where auth_can and not anon_can

  union all

  -- 4. SECURITY DEFINER without a pinned search_path can be steered into
  --    resolving names to objects the caller created.
  select 'medium', 'definer_function_mutable_search_path', name,
         'SECURITY DEFINER with no search_path set, so unqualified names resolve using the caller''s search_path.',
         format('ALTER FUNCTION %s SET search_path = '''';  (then schema-qualify every name in the body)', name)
  from definer_functions
  where not exists (
    select 1 from unnest(coalesce(proconfig, '{}'::text[])) cfg where cfg like 'search_path=%'
  )

  union all

  -- 5. Views run as their owner unless security_invoker is set, which skips the
  --    row-level security of every table underneath. Materialized views have no
  --    RLS at all.
  select case when anon_can then 'high' else 'medium' end,
         case when relkind = 'm' then 'materialized_view_exposed' else 'owner_run_view_exposed' end,
         name,
         case when relkind = 'm'
           then 'Materialized views have no row-level security, and this one is readable through the API.'
           else 'This view runs with its owner''s rights (security_invoker is not set), so it ignores the row-level security of the tables it reads, and it is readable through the API.'
         end
           || case when anon_can then ' anon holds privileges on it.' else ' authenticated holds privileges on it.' end,
         case when relkind = 'm'
           then format('REVOKE ALL ON %s FROM anon, authenticated; and serve it through a function that checks the caller.', name)
           else format('ALTER VIEW %s SET (security_invoker = true); or REVOKE ALL ON %1$s FROM anon, authenticated;', name)
         end
  from tables t
  where relkind in ('v', 'm') and (anon_can or auth_can)
    and (relkind = 'm' or not exists (
      select 1 from unnest(coalesce((select reloptions from pg_class where oid = t.oid), '{}'::text[])) opt
      where opt in ('security_invoker=true', 'security_invoker=on', 'security_invoker=1')
    ))

  union all

  -- 6. Any view, owner-run or not, that reads auth.users and is reachable
  --    through the API deserves a look: it is where emails and sign-in data leak.
  select case when t.anon_can then 'high' else 'medium' end,
         'view_reads_auth_users', t.name,
         'This view reads auth.users and is readable through the API. Check exactly which columns and rows each role can see.',
         format('REVOKE ALL ON %s FROM anon; and keep the view behind a check on the caller.', t.name)
  from tables t
  where t.relkind in ('v', 'm') and (t.anon_can or t.auth_can)
    and exists (
      select 1 from pg_depend d
      join pg_rewrite r on r.oid = d.objid
      where d.classid = 'pg_rewrite'::regclass and r.ev_class = t.oid
        and d.refobjid = to_regclass('auth.users')
    )

  union all

  -- 7. Policies that let anon (or everyone) write any row.
  select 'high', 'policy_allows_anon_write', format('%I.%I: %s', p.schemaname, p.tablename, p.policyname),
         format('Permissive %s policy for %s whose condition is "true": anyone with the publishable key can %s any row.',
                p.cmd, array_to_string(p.roles, ', '), lower(case when p.cmd = 'ALL' then 'insert, update or delete' else p.cmd end)),
         'Fine for an INSERT-only public form if the table holds nothing sensitive. Otherwise tie the condition to auth.uid() or move the write into an Edge Function.'
  from pg_policies p
  join audited a on a.nspname = p.schemaname
  where p.permissive = 'PERMISSIVE'
    and p.cmd in ('INSERT', 'UPDATE', 'DELETE', 'ALL')
    and p.roles && array['anon', 'public']::name[]
    and (btrim(coalesce(p.qual, '')) = 'true' or btrim(coalesce(p.with_check, '')) = 'true')

  union all

  select 'info', 'policy_allows_anon_read', format('%I.%I: %s', p.schemaname, p.tablename, p.policyname),
         'Anyone with the publishable key can read every row. Right for public marketing data, wrong for anything else.',
         'Confirm the table holds nothing private.'
  from pg_policies p
  join audited a on a.nspname = p.schemaname
  where p.permissive = 'PERMISSIVE'
    and p.cmd in ('SELECT', 'ALL')
    and p.roles && array['anon', 'public']::name[]
    and btrim(coalesce(p.qual, '')) = 'true'

  union all

  -- 8. auth.uid() / auth.jwt() called bare in a policy runs once per row.
  --    Wrapped as (select auth.uid()) it runs once per statement.
  select 'low', 'policy_calls_auth_per_row', format('%I.%I: %s', p.schemaname, p.tablename, p.policyname),
         'Calls auth.uid(), auth.jwt() or auth.role() without wrapping it in a SELECT, so Postgres evaluates it for every row it checks. Invisible on small tables, slow on large ones.',
         'Write (select auth.uid()) instead of auth.uid(), and the same for any stable helper the policy calls.'
  from pg_policies p
  join audited a on a.nspname = p.schemaname
  where (select count(*) from regexp_matches(coalesce(p.qual, '') || ' ' || coalesce(p.with_check, ''),
                                             'auth\.(uid|jwt|role)\(\)', 'g'))
      > (select count(*) from regexp_matches(coalesce(p.qual, '') || ' ' || coalesce(p.with_check, ''),
                                             'SELECT auth\.(uid|jwt|role)\(\)', 'gi'))
)

select severity, check_id, object, detail, fix
from findings
order by array_position(array['high', 'medium', 'low', 'info'], severity), check_id, object;
