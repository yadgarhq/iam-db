# Every UPDATE on iam_user advances version (D8)

Status: proposed (fleet plan, yaadgaar 671). Nothing here is built.
Date: 2026-11-09, re-planned 2026-11-10 under fleet 5.0.3, and again on
2026-11-10 under fleet 5.0.6 (criteria split into new behaviour and guards).
Base: `main` at 1332c1e (the fleet branch adds only this plan doc).

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

This is a bug fix: it restores what D8 requires ("every successful update").

## Premise check (HEAD 1332c1e)

The defect reproduces. `src/service/policy.rs:44` is still
`UPDATE iam_user SET is_admin = ? WHERE id = ? AND deleted_at IS NULL`.
Reference re-map: the task cites `src/service/policy.rs:44` at 933ddea. At
1332c1e the statement is still at line 44, and the epoch statements are still
at `src/service/epoch.rs:35` and `:56`. No drift.

Measured on `mariadb:11.8.9` and on the fleet's `mariadb:11.4` (11.4.13) with
a copy of the relevant columns:

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
There is no `REPLACE` statement. The `ON DUPLICATE KEY UPDATE` clauses in
`src/service/password.rs:140`, `src/service/enrolment/redeem.rs:208`,
`src/service/policy.rs:126` and `src/service/setting.rs:145`, `:264` write
other tables. Three production statements update `iam_user`:

| Site                                                                 | Statement                                                                | version      | updated_at                     |
| -------------------------------------------------------------------- | ------------------------------------------------------------------------ | ------------ | ------------------------------ |
| `src/service/policy.rs:44` (`set_admin`, SetUserAdmin)               | `SET is_admin = ?`                                                       | not advanced | only when the value changes    |
| `src/service/epoch.rs:35` (`bump`: redemption, RevokeAllCredentials) | `SET credential_epoch = credential_epoch + 1`                            | not advanced | implicit (column always moves) |
| `src/service/epoch.rs:56` (`bump_live`: SetPassword)                 | `SET credential_epoch = credential_epoch + 1 ... AND deleted_at IS NULL` | not advanced | implicit (column always moves) |

All three have the version gap. The plan fixes all three (Max ruling 2,
2026-11-10). The other `UPDATE iam_user` lines are test fixtures (soft
deletes in `tests/`), not production writes. No existing test reads
`iam_user.version`.

Callers of the two epoch functions: `epoch::bump` at
`src/service/credential/all.rs:51` (RevokeAllCredentials) and
`src/service/enrolment/redeem.rs:190` (every redemption, flagged or not; a
replay returns at `redeem.rs:132-139` before it, and a refused redemption
never reaches it). `epoch::bump_live` at `src/service/password.rs:131`
(SetPassword). A flagged redemption calls `revoke::all`, which does not bump,
so it bumps exactly once.

## Design

1. `set_admin` (`src/service/policy.rs:44`): the UPDATE becomes
   `UPDATE iam_user SET is_admin = ?, version = version + 1, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND deleted_at IS NULL`.
   The bump is unconditional: a re-asserted flag also adds 1 (Max ruling 1).
   The `rows_affected() == 0` branch and the `live_user` re-read stay as they
   are. `sqlx-mysql` reports MATCHED rows, so the count for a live user is
   still 1 and the reported `rows` does not change.
2. `epoch::bump` and `epoch::bump_live` (`src/service/epoch.rs:35`, `:56`):
   the same two assignments are added to each statement. The statements lock
   the same row as before, so lock order and the ADR-0972 (4) argument do not
   change.
3. The coder may add one comment line per statement that names D8, and may
   correct the "running it twice reaches the same state" comment in
   `set_admin` (the flag state is the same; `version` now moves). No module
   doc change is required.

No schema change. No migration. No proto change. No new dependency.
`updated_by` stays unwritten (Max ruling 3).

## Acceptance criteria (summary; the literal examples are in the fleet json)

Four criteria. AC1 and AC2 hold only the new behaviour: every example in them
fails on 1332c1e. AC3 and AC4 hold the refusals that already write nothing
today: they pass on 1332c1e and must still pass after the fix, so they are
marked `guards_existing` with a quoted spec line. The split exists because the
fleet test judge refuses a test that passes on current code unless its
criterion guards existing behaviour (fleet 5.0.6 build wf_5cc06208-e0b
stopped there).

- AC1 `[e2e]` `tests/user_version_admin.rs` (new behaviour): each successful
  SetUserAdmin call advances `version` by exactly 1 (promote, demote and
  re-assert) and sets `updated_at`. Another person's row is untouched while
  the target's `version` moves.
- AC2 `[e2e]` `tests/user_version_epoch.rs` (new behaviour): each epoch bump
  advances `version` by exactly 1 and sets `updated_at`: RevokeAllCredentials
  (live and soft-deleted person), SetPassword, an unflagged and a flagged
  redemption. A redemption and its replay together add exactly 1: the first
  delivery adds 1, the replay adds 0 and leaves `updated_at` alone. Another
  person's row is untouched.
- AC3 `[e2e]` `tests/user_version_admin_guard.rs` (guard, passes today):
  SetUserAdmin for an unknown id or a soft-deleted person answers NOT_FOUND
  and changes neither `version` nor `updated_at` (nor `is_admin`). Spec:
  `src/service/policy.rs:51` ("A MISTYPED USER ID MUST NOT REPORT SUCCESS"),
  `:36-38` (no promotion of a soft-deleted person), `:63-65` (NOT_FOUND for
  both), and D8 (`common.proto:282-283`: only a successful update increments).
- AC4 `[e2e]` `tests/user_version_epoch_guard.rs` (guard, passes today):
  RevokeAllCredentials for an unknown user answers NOT_FOUND, SetPassword for a
  soft-deleted person answers NOT_FOUND, and an expired redemption answers
  `RedeemOutcome::Expired`. Each leaves `version` and `updated_at` unchanged.
  Spec: `iamdb.proto:705` ("NOT_FOUND MEANS NO `iam_user` ROW AT ALL."),
  `src/service/epoch.rs:49-50` (SetPassword's zero is NOT_FOUND, "decided
  before anything is written"), `iamdb.proto:462-463` (expiry evaluated in the
  statement), and D8.

Measured (this run, scratch worktree at HEAD, fleet MariaDB 11.4): the earlier
writer output for the old two criteria had exactly five tests GREEN on
current code: SetUserAdmin unknown id and soft-deleted person,
RevokeAllCredentials unknown user, SetPassword soft-deleted person, expired
redemption. Those five are AC3 and AC4. Every other test failed on its
`version` assertion. The replay test is RED because it asserts the first
delivery's +1 before the replay; AC2 keeps that form.

Each guard example asserts both the refusal (status code or outcome) and the
no-write (`version` and `updated_at` unchanged), so a stub that answers OK or
swallows the error is caught. A stub that skips the write does not apply to a
refusal: the refusal has no write. Each test file uses database names of its
own (`iam_db_version_` for AC1 and AC2, `iam_db_vguard_` for AC3 and AC4), so
two targets never share a database.

How every example seeds and compares `updated_at` (zone-independent):

- Seed: `UPDATE iam_user SET updated_at = FROM_UNIXTIME(1000000000) WHERE id = ?`.
  Never a datetime string literal. Seed after any fixture write that changes
  the row (soft delete, earlier call), then read `version`. The seed itself
  does not move `version`.
- Success: `UNIX_TIMESTAMP(updated_at) > 1000000000`.
- Refusal: `UNIX_TIMESTAMP(updated_at) = 1000000000`.
- No example seeds or compares `updated_at` with a datetime string literal.
  MariaDB reads a string literal in the session zone, while `UNIX_TIMESTAMP`
  of a `TIMESTAMP` column returns the stored UTC instant.

"Contract test against MariaDB 11.8" (the task's words): each new file is a
real-MariaDB test target on the shared `tests/db/mod.rs` fixture (`mod db;`),
as `tests/credential_epoch.rs` is. It panics without `YADGAR_TEST_DSN`, and
CI runs it on MariaDB 11.8. `version` and `updated_at` are not exposed by any
read RPC, so each test reads them with SQL on `svc.pool()`, as `stored_epoch`
does. Each file keeps its own SQL helpers; neither edits `tests/db/mod.rs`.
Each test uses its own database name, prefixed `iam_db_version_` (inside the
repo's declared `iam_db_` test-database prefix).

TDD red: every AC1 and AC2 test fails on 1332c1e on a `version` assertion.
AC3 and AC4 pass on 1332c1e by design (guards) and must still pass after the
fix.

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

`cargo test --all-features` (the `Makefile` `test` target, `Makefile:15-16`),
with `env: {}`. Each criterion is targeted with its own `test_args`: AC1
`--test user_version_admin`, AC2 `--test user_version_epoch`, AC3
`--test user_version_admin_guard`, AC4 `--test user_version_epoch_guard`. The
command carries no `<paths>` token.

The DB-backed targets need `YADGAR_TEST_DSN`. `origin/main` (2def7ba) now
declares the fleet test database in `.fleet-test-db.json` (engine `mariadb`,
major `11.4`, env `YADGAR_TEST_DSN`, test-database prefix `iam_db_`). The
fleet run hands the tests the YADGAR_TEST_DSN URL: a per-run user and
password, host 127.0.0.1, a port and a database given by the workflow, with
CREATE and DROP on databases named `iam_db_*`. The shared fixture
(`tests/db/mod.rs:30-42`) drops and creates per-test databases, and every name
this plan uses starts with `iam_db_version_` or `iam_db_vguard_`, so that grant
is enough.

Probe (this run, 2026-11-10, fleet 5.0.6): scratch worktree at 10580fc (code
identical to 1332c1e), this run's fleet database (`mariadb:11.4`), the
workflow's YADGAR_TEST_DSN URL, `cargo test --all-features --test
credential_epoch -- revoke_all_bumps_the_epoch --exact` exited 0 (1 passed,
19 filtered out).

Gap: the fleet gates test on MariaDB 11.4, not the 11.8 the task names. The
11.4 measurements above match 11.8.9, and 11.8 coverage stays with CI.

## Non-goals

- No `expect_version` compare-and-swap on SetUserAdmin or on any epoch bump.
  This plan makes `version` move; it adds no caller that checks it.
- No `updated_by` write (Max ruling 3; a follow-up if wanted).
- No change to the response of any RPC. `version` and `updated_at` stay
  unexposed by every read RPC.
- No change to `iam_user` writes outside `src/` (test fixtures in `tests/`
  keep their bare soft-delete UPDATEs).
- No change to `tests/db/mod.rs` or `tests/contract.rs`.
- No idempotency-key honouring for RevokeAllCredentials (ledger 668).
- No edit to `.fleet-test-db.json`.

## Trust boundaries (STRIDE)

The change adds no input and no trust boundary: the three statements take the
same bound `user_id` and `is_admin` as before, and the two new assignments use
no caller value. Spoofing, tampering, repudiation, information disclosure,
denial of service and elevation of privilege are unchanged; the existing
caller gate (`IAM_CALLER`) and the `deleted_at IS NULL` refusals stay. AC3
re-asserts the soft-deleted and unknown-id SetUserAdmin refusals (elevation of
privilege: no promotion of a person who is gone). AC4 re-asserts that a
refused SetPassword, an expired redemption and an unknown-user
RevokeAllCredentials write nothing (tampering).

## Risks

- A re-asserted flag now moves `version`. A caller that compares versions sees
  a conflict after another caller's no-op write. That fails safe (a spurious
  conflict, never a missed change) and is D8 as written ("every successful
  update"). Max ruling 1 accepts it.
- Epoch bumps now move `version`. A future version compare-and-swap on the
  admin flag conflicts with a concurrent password reset. Correct under D8, but
  visible. Max ruling 2 accepts it.
- A RevokeAllCredentials redelivery re-runs the bump today (ledger 668), so it
  moves `version` again. Same class as risk 1.

## Decisions (Max rulings, 2026-11-10)

1. A re-asserted admin flag still bumps `version`, with an unconditional
   `version + 1`.
2. Credential-epoch bumps (`src/service/epoch.rs:35`, `:56`) also advance
   `version`, so AC2 stays.
3. `updated_by` stays unwritten by SetUserAdmin. Out of scope; a follow-up if
   wanted.
4. Test database: route (a). The fleet's database grants the role user CREATE
   and DROP on `iam_db_%`.\*, and `.fleet-test-db.json` is on iam-db `main`
   (2def7ba). Measured by this run's probe. The fleet tests on 11.4 only; CI
   covers 11.8.

## Open decisions for Max

None. The four decisions above are ruled.
