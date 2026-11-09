# Every UPDATE on iam_user advances version (D8)

Status: proposed (fleet plan, yaadgaar 671). Nothing here is built.
Date: 2026-11-09. Base: `main` at 1332c1e.

## Problem

D8 (`proto/yadgar/common/v1/common.proto:282-284`): `Meta.version` is a
"Compare-and-set counter (D8). Incremented by the -db service on every
successful update."

`iam_user` has a `version` column (`src/schema.rs:213`, `DEFAULT 1`).
`CreateUser` answers `version: 1` (`src/service/identity.rs:76`,
`src/service/identity/bootstrap.rs:131`). No write after the insert moves it.
So a version compare-and-swap on `iam_user` cannot see a change. proto#99
(which superseded proto#98) uses a byte compare-and-swap for that reason, and
names SetUserAdmin as the cause.

## Premise check (HEAD 1332c1e)

The defect reproduces. `src/service/policy.rs:44` is still
`UPDATE iam_user SET is_admin = ? WHERE id = ? AND deleted_at IS NULL`.
Reference re-map: the task cites `src/service/policy.rs:44` at 933ddea. At
1332c1e the statement is still at line 44. No drift.

Measured on `mariadb:11.8.9` with a copy of the relevant columns:

- A re-asserted `is_admin` (same value) leaves `version` AND `updated_at`
  unchanged. `ON UPDATE CURRENT_TIMESTAMP` (`src/schema.rs:221-222`) fires
  only when a column value changes.
- A changed `is_admin` moves `updated_at` (by the column default) but not
  `version`.
- `UPDATE ... SET updated_at = FROM_UNIXTIME(1000000000)` under session zone
  `+05:00`, read back with `UNIX_TIMESTAMP(updated_at)` under `-07:00`, gives
  `1000000000`. The seed and compare form in the criteria below is
  zone-independent.

## Audit: every write that updates iam_user (HEAD 1332c1e)

Searched under `src/`: `UPDATE iam_user` (any line break), `INSERT INTO
iam_user` with `ON DUPLICATE KEY UPDATE`, and `REPLACE`. The two
`INSERT INTO iam_user` statements (`src/service/identity.rs:53`,
`src/service/identity/bootstrap.rs:95`) have no `ON DUPLICATE KEY UPDATE`.
There is no `REPLACE`. Three production statements update `iam_user`:

| Site                                                                 | Statement                                                                | version      | updated_at                     |
| -------------------------------------------------------------------- | ------------------------------------------------------------------------ | ------------ | ------------------------------ |
| `src/service/policy.rs:44` (`set_admin`, SetUserAdmin)               | `SET is_admin = ?`                                                       | not advanced | only when the value changes    |
| `src/service/epoch.rs:35` (`bump`: redemption, RevokeAllCredentials) | `SET credential_epoch = credential_epoch + 1`                            | not advanced | implicit (column always moves) |
| `src/service/epoch.rs:56` (`bump_live`: SetPassword)                 | `SET credential_epoch = credential_epoch + 1 ... AND deleted_at IS NULL` | not advanced | implicit (column always moves) |

All three have the version gap. The plan fixes all three. The other
`UPDATE iam_user` lines are test fixtures (soft deletes in `tests/`), not
production writes. No existing test reads `iam_user.version`.

## Design

1. `set_admin` (`src/service/policy.rs:44`): the UPDATE becomes
   `UPDATE iam_user SET is_admin = ?, version = version + 1, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND deleted_at IS NULL`.
   The `rows_affected() == 0` branch and the `live_user` re-read stay as they
   are. `sqlx-mysql` reports MATCHED rows, so the count for a live user is
   still 1 and the reported `rows` does not change.
2. `epoch::bump` and `epoch::bump_live` (`src/service/epoch.rs:35`, `:56`):
   the same two assignments are added to each statement. The statements lock
   the same row as before, so lock order and the ADR-0972 (4) argument do not
   change.
3. The coder may add one comment line per statement that names D8. No module
   doc change is required.

No schema change. No migration. No proto change. No new dependency.

## Acceptance criteria (summary; the literal examples are in the fleet json)

- AC1 `[e2e]` `tests/user_version_admin.rs`: each successful SetUserAdmin call
  advances `version` by exactly 1 (re-assert included) and sets `updated_at`.
  A NOT_FOUND (unknown id, soft-deleted person) writes nothing. Another
  person's row is untouched.
- AC2 `[e2e]` `tests/user_version_epoch.rs`: each epoch bump advances
  `version` by exactly 1 and sets `updated_at`: RevokeAllCredentials (live and
  soft-deleted person), SetPassword, an unflagged and a flagged redemption.
  An unknown-user RevokeAllCredentials, a refused SetPassword, an expired
  redemption and a replayed redemption leave `version` and `updated_at`
  unchanged.

How every example seeds and compares `updated_at` (zone-independent):

- Seed: `UPDATE iam_user SET updated_at = FROM_UNIXTIME(1000000000) WHERE id = ?`.
  Never a datetime string literal. Seed after any fixture write that changes
  the row (soft delete, earlier call), then read `version`. The seed itself
  does not move `version`.
- Success: `UNIX_TIMESTAMP(updated_at) > 1000000000`.
- Refusal: `UNIX_TIMESTAMP(updated_at) = 1000000000`.
- No example seeds or compares `updated_at` with a datetime string literal
  (plan-audit refusal of run wf_ce9bf3eb-e62). MariaDB reads a string literal
  in the session zone, while `UNIX_TIMESTAMP` of a `TIMESTAMP` column returns
  the stored UTC instant.

"Contract test against MariaDB 11.8" (the task's words): each new file is a
real-MariaDB test target on the shared `tests/db/mod.rs` fixture (`mod db;`),
as `tests/credential_epoch.rs` is. It panics without `YADGAR_TEST_DSN`, and
CI runs it on MariaDB 11.8. `version` and `updated_at` are not exposed by any
read RPC, so each test reads them with SQL on `svc.pool()`, as `stored_epoch`
does. Each file keeps its own SQL helpers; neither edits `tests/db/mod.rs`.
Each test uses its own database name, prefixed `iam_db_version_`.

TDD red: AC1's re-assert and every AC1/AC2 `version` assertion fail on
1332c1e.

## Repo obligations (coder steps)

- OB1 `cargo-fmt` (`.pre-commit-config.yaml:55`): run `cargo fmt` on the
  changed and new files.
- OB2 `cargo-clippy` and `cargo-clippy-complexity`
  (`.pre-commit-config.yaml:56`, `:88`): no new warnings.
- OB3 `complexity` (`.pre-commit-config.yaml:87`): no production file over 500
  lines and no function over 120. `policy.rs` is 221 lines and `epoch.rs` 80.
- OB4 `no-test-skips` (`.pre-commit-config.yaml:119`): the new tests never
  skip; they panic without `YADGAR_TEST_DSN` (through `db::dsn`).

No version-bump checker, CHANGELOG or generated file applies. Checked:
`.pre-commit-config.yaml`, `.github/workflows/ci.yaml` (calls
`yadgarhq/actions` `ci-pr.yaml`), `.github/workflows/repin.yaml`, `Makefile`,
`Cargo.toml` (no `autotests = false`, no `[[test]]`, so new files under
`tests/` are picked up), `scripts/`.

## test_cmd

`cargo test --all-features` (the `Makefile` `test` target), with `env: {}`.
The DB-backed targets need `YADGAR_TEST_DSN`, which the fleet's `test_env`
supplies.

Probe (first plan run): scratch worktree at HEAD, throwaway `mariadb:11.8.9`,
`cargo test --all-features -- promoting_an_unknown_user_is_not_found_but_re_asserting_a_flag_is_not`
exited 0 (1 passed in `tests/contract.rs`).

Probe (re-plan run): same set-up,
`cargo test --all-features -- revoke_all_bumps_the_epoch` exited 0 (1 passed
in `tests/credential_epoch.rs`).

Gap: the fleet's cargo allowlist takes no file argument (`--test <name>` is
refused), and a file path as a trailing argument becomes a test-name filter
that matches nothing and exits 0. So the command carries no `<paths>` token:
every targeted run is a full-suite run. Slower, never a false green.

## Risks

- A re-asserted flag now moves `version`. A caller that compares versions sees
  a conflict after another caller's no-op write. That fails safe (a spurious
  conflict, never a missed change) and is D8 as written ("every successful
  update"). See open decision 1.
- Epoch bumps now move `version`. A future version compare-and-swap on the
  admin flag conflicts with a concurrent password reset. Correct under D8, but
  visible. See open decision 2.
- A RevokeAllCredentials redelivery re-runs the bump today (ledger 668), so it
  moves `version` again. Same class as risk 1.

## Open decisions for Max

1. Re-assert bumps `version`. Recommended: yes (unconditional
   `version + 1`). Alternative: bump only when `is_admin` changes, which keeps
   a strict D9 "same state" reading but adds a two-valued write for no current
   consumer.
2. Credential-epoch bumps advance `version`. Recommended: yes; D8 names no
   exception, and RotateKeyIdentity (proto#99) also advances it. Alternative:
   treat `credential_epoch` as an internal counter outside D8 and leave
   `epoch.rs` alone (then drop AC2).
3. `updated_by` stays unwritten by SetUserAdmin, although `Meta` says an edit
   changes it (`common.proto:303-306`). Out of scope here; a follow-up if
   wanted.
