# Security policy

## What this covers

This repository is a read-only SQL query and a checklist. A security problem **in the tool** might be:

- a statement in `audit.sql` that could change data, take a lock that blocks production traffic, or call a function in the audited database;
- a check that reports something as safe when it's exploitable (a false negative on a **high** finding);
- a suggested fix that would make a project less secure.

Please report those privately, as described below.

## How to report

Use GitHub's **[private vulnerability reporting](https://github.com/Rebott-Business-Solutions/supabase-production-audit/security/advisories/new)** for this repository. Only the maintainers can see the report.

We aim to acknowledge reports within three working days and to tell you within ten what we'll do about it. We'll credit you in the release notes unless you'd rather we didn't.

## What not to send us

**Never send vulnerabilities in your own or anyone else's Supabase project**, and never send keys, connection strings, schema dumps or audit output from a real project, publicly or privately. Describe the pattern with a made-up example instead, like the ones in `test/fixtures.sql`.

If you've found a vulnerability in Supabase itself, report it to Supabase through [their security policy](https://supabase.com/.well-known/security.txt), not here.

## Supported versions

Only the latest release on `main` gets fixes.
