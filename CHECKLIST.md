# What a query can't see

`audit.sql` reads your database. These checks need the dashboard, your repository or a terminal. Each one is something we've found broken in a live app.

## Keys and secrets

- [ ] **No secret key in the browser bundle.** Build the app and search the output for `service_role` and `sb_secret_`. Only the publishable (anon) key belongs in front-end code.
  ```bash
  npm run build && grep -rlE 'service_role|sb_secret_' dist/ || echo "clean"
  ```
- [ ] **No safety control switches itself off when a setting is missing.** Search your Edge Functions for features gated on an environment variable: rate limiting, CAPTCHA, signature checks, email sending. If a missing secret means "skip the check", assume it's skipped in production until you've proven otherwise. ([teardown](https://rebott.co.za/blog/rate-limiter-never-limited))

## Edge Functions

- [ ] **Rate limits actually limit.** Against staging, not production, send your password-reset, sign-up or contact function 40 requests in a minute. If none come back `429`, there's no rate limit, whatever the code says.
- [ ] **Every function's settings are in `supabase/config.toml`.** A `verify_jwt` set by CLI flag or in the dashboard is overwritten on the next deploy by the GitHub integration.
- [ ] **What's deployed is what's in the repo.** A failed deploy doesn't always say so. Compare each deployed function's version and update time in the dashboard with your last merge, or have each function report a content hash of its source that you can check after deploying.
- [ ] **CORS is an allowlist.** A function that answers `Access-Control-Allow-Origin: *` to authenticated requests lets any website call it with a visitor's session.

## Auth

- [ ] **Emailed links last as long as your emails say.** Check the email OTP expiry (in the Email provider settings under Authentication) on every project. If you manage a persistent branch through `[remotes.<branch>]` in `config.toml`, any auth setting that block doesn't declare is reset to the default on every merge, including the OTP expiry. Declare it.
- [ ] **Staging and production auth settings match on purpose.** Compare site URL, redirect allowlist, OTP expiry, email confirmation and the password policy across projects. They drift silently.
- [ ] **Sign-ups are what you intend.** If the app is invite-only, disable public sign-ups. Otherwise anyone can create an `authenticated` user and reach every **medium** finding from `audit.sql`.

## Storage

- [ ] **Public buckets are meant to be public.** In **Storage**, check every bucket marked public. Anything in it is readable by URL without a session.
- [ ] **`storage.objects` policies scope by path.** Upload and read policies should tie objects to the user or tenant, usually through the first folder in the path.

## Migrations and drift

- [ ] **Nobody applies SQL outside the migrations.** Compare `supabase_migrations.schema_migrations` on production with `supabase/migrations/`. A version that's in the database but not in the repo blocks the next deploy, and the Edge Functions deploy with it.
- [ ] **Applied migrations are never edited.** An edit to an applied migration never re-runs, so production keeps the old version while a freshly built staging gets the new one.

## Operations

- [ ] **Backups exist and someone has restored one.** Check the plan's backup schedule or Point-in-Time Recovery, and do a test restore into a scratch project.
- [ ] **Errors reach someone.** Throw a deliberate error in production and confirm it arrives in your error tracker.

## Front end

- [ ] **Menus close on navigation.** In a React app using shadcn or Radix, open each dropdown or sheet that contains links, choose one, and check that the new page isn't left `aria-hidden`. If it is, the page is invisible to screen readers. ([teardown](https://rebott.co.za/blog/flaky-test-accessibility-bug))

---

If you'd like us to work through this list on your project, we do it as a fixed-price audit: [rebott.co.za](https://rebott.co.za).
