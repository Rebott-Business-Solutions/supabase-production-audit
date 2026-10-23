-- A throwaway database shaped like a Supabase project, with one example of
-- each problem the audit looks for and one correct counterpart for each.
-- test/run.sh loads this into an empty database and compares the audit's
-- output with test/expected.txt.

create role anon nologin;
create role authenticated nologin;
create role service_role nologin bypassrls;

create schema auth;
create table auth.users (id uuid primary key, email text);
create function auth.uid() returns uuid language sql stable as $$ select null::uuid $$;
grant usage on schema auth to anon, authenticated;

-- What Supabase does on every project: grant new objects in public to the API
-- roles BY NAME.
grant usage on schema public to anon, authenticated, service_role;
alter default privileges in schema public grant all on tables to anon, authenticated, service_role;
alter default privileges in schema public grant all on functions to anon, authenticated, service_role;

-- 1. rls_disabled (high), and a table with RLS and a sound policy (no finding).
create table public.no_rls (id int);
create table public.notes (id int, owner uuid);
alter table public.notes enable row level security;
create policy "own notes" on public.notes for all to authenticated
  using (owner = (select auth.uid())) with check (owner = (select auth.uid()));

-- rls_disabled (medium): only authenticated holds privileges.
create table public.no_rls_signed_in (id int);
revoke all on public.no_rls_signed_in from anon;

-- 2. rls_no_policies (info).
create table public.server_only (id int);
alter table public.server_only enable row level security;

-- 3. The REVOKE FROM PUBLIC trap: still callable by anon (high).
create function public.delete_tenant(p uuid) returns void
  language sql security definer set search_path = '' as $$ select $$;
revoke all on function public.delete_tenant(uuid) from public;

-- Revoked by name (no finding).
create function public.server_job() returns void
  language sql security definer set search_path = '' as $$ select $$;
revoke execute on function public.server_job() from public, anon, authenticated;

-- authenticated only (medium).
create function public.signed_in_rpc() returns int
  language sql security definer set search_path = '' as $$ select 1 $$;
revoke execute on function public.signed_in_rpc() from public, anon;

-- 4. Mutable search_path, already locked to service_role (one medium finding).
create function public.no_path() returns int
  language sql security definer as $$ select 1 $$;
revoke execute on function public.no_path() from public, anon, authenticated;

-- A trigger function is not callable through the API (no finding).
create function public.touch() returns trigger
  language plpgsql security definer set search_path = '' as $$ begin return new; end $$;

-- 5. Owner-run view readable by anon (high), and an invoker view (no finding).
create view public.owner_view as select id from public.notes;
create view public.invoker_view with (security_invoker = true) as select id from public.notes;
create materialized view public.mat_view as select 1 as n;

-- 6. A view over auth.users that only authenticated can read: owner-run
--    (medium) and reads auth.users (medium).
create view public.user_emails as select id, email from auth.users;
revoke all on public.user_emails from anon;

-- 7. Policies: anon can delete anything (high); anon can read anything (info);
--    a per-row auth.uid() call (low).
create table public.guestbook (id int, owner uuid);
alter table public.guestbook enable row level security;
create policy "anyone deletes" on public.guestbook for delete to anon using (true);
create policy "anyone reads" on public.guestbook for select to anon using (true);
create policy "own rows" on public.guestbook for update to authenticated
  using (owner = auth.uid());
