# Changelog

Versions follow `MAJOR.MINOR.PATCH`:

- **PATCH** fixes a detector or the report without changing what you need to do.
- **MINOR** adds detectors, catalog classes or features. Your profile keeps working.
- **MAJOR** changes the profile format or the output files, and may need action on your side.

Not every commit is a release. A release is cut when a change is worth pulling.

---

## [1.0.0] - 2026-09-24

The first versioned release. It bundles two calibration rounds on real, open-source Supabase apps.

### Calibration method

- Ran on **four large apps** (hundreds of tables, over a thousand migrations) with independent reviewers judging a sample of findings by reading the code.
- Ran on **six apps with published security fixes**, before and after each fix and against the authors' later commits. What the authors went on to fix confirms the finding without a reviewer.
- The apps are not named here on purpose: real issues found along the way were reported privately to their maintainers.

### Added

- **36 mechanical detectors** (up from 19), each with a planted defect and a clean case in the example app, and every condition mutation-tested (108 mutations).
- `definer-confia-no-parametro`: a `SECURITY DEFINER` function reachable through the API that takes the id of an account, user or resource and never checks who is calling, directly or through a helper. Read per overload.
- `coluna-de-privilegio-editavel`: an UPDATE policy that only checks row ownership, on a table whose role or tenant column an access function reads.
- `acesso-por-id-sem-dono`: a tRPC procedure, Remix action or Next.js handler that reads or writes by an id from the request without referencing the session user. Only counts direct ORM access or a privileged client; a session-bound Supabase client is left to RLS.
- 12 tenancy and correctness detectors, among them role helpers that ignore a deactivation flag, sensitive column grants, invite oracles, "first user becomes owner", enum values added after a negative comparison, time ranges without a CHECK, cascades that delete history, and docs that cite policies that don't exist.
- Security catalog: a 5-minute threat model, plus SSRF, in-memory rate limits, destructive operations on caller-supplied paths, LLM output used as an argument, RAG without tenant partitioning, non-reproducible installs, and server-side IDOR.

### Fixed (how migrations are read)

- Final state instead of a sum of everything ever written: `DROP TABLE`, `DROP VIEW`, `DROP SCHEMA`, renames and `DROP FUNCTION` now remove objects.
- Tables outside `public`, the quoted `"public"."x"` form from `supabase db diff`, and comments no longer read as SQL.
- Columns added with `ALTER TABLE ... ADD COLUMN` were never recorded. They are now.
- `GRANT` and `REVOKE` built inside a loop (`execute format(...)` over an array of names) are understood, as is RLS enabled in a loop.
- In a database dump (`pg_dump`, `supabase db dump`, consolidated baselines) the grant list is complete: a role that isn't granted has no access.
- Overloaded functions are read per signature, normalized by type.
- `UPDATE` and `ALL` policies with only `USING` are no longer flagged as missing a write check.

### Known limits

- The scanner reads code. Whether a function is really reachable depends on the database's default privileges, which may have been changed outside migrations: confirm against the live database before treating a reachability finding as confirmed.
- Server-side IDOR through service classes (ownership checked in one place, write by id in another) is still out of mechanical reach. A tenant-key heuristic was measured and rejected for noise.

## [0.2.0] - 2026-09-23

Tenancy and correctness detectors, `supabase db diff` format, and the extended security catalog. Superseded by 1.0.0.

## [0.1.0] - 2026-09-20

First public version: two-dimension method, deterministic scanner with coverage proven by assertion, skeptic phase, HTML report, example app and self-test.
