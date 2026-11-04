"""THE APP ACCOUNT THIS CHART OWNS (yaadgaar #411, ADR-1142).

Behind `database.create` AND `database.createAppAccount` (default false) the chart renders a MariaDB `User` and `Grant` for
`database.appUser`, and a PreSync hook Job (with its own short-lived RBAC) that
creates `database.appPasswordSecret` once, only when it is absent. The pod still
connects as `database.user` (ADR-1142 rule 9): the cutover is a later change.

EVERY EQUALITY BELOW READS RENDERED OBJECTS, and the literals are literals: a
number derived from the thing under test agrees with whatever it happens to be.

Run: python3 -m pytest scripts/tests/ -q
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from pathlib import Path

import pytest
import yaml

from test_render_checks import (
    CHART,
    DATABASE_TOGGLE_ON,
    KEDA_API_VERSIONS,
    MARIADB_API_VERSIONS,
    objects,
    render,
)

GROUP = "k8s.mariadb.com/v1alpha1"
HOOK_NAME = "iam-db-app-password-init"
APP_USER = "iam_app"
APP_SECRET = "iam-db-app-password"
MARIADB_NAME = "iam-db-mariadb"
USER_OBJECT = "iam-db-mariadb-app"
GRANT_OBJECT = "iam-db-mariadb-app-all"

# (max(6, 2) + 1) x 3 + 1, at the shipped defaults.
DEFAULT_MAX_USER_CONNECTIONS = 22

HOOK_ANNOTATIONS_RBAC = {
    "argocd.argoproj.io/hook": "PreSync",
    "argocd.argoproj.io/hook-delete-policy": "HookSucceeded,BeforeHookCreation",
    "argocd.argoproj.io/sync-wave": "-10",
    "helm.sh/hook": "pre-install,pre-upgrade",
    "helm.sh/hook-weight": "-10",
    "helm.sh/hook-delete-policy": "before-hook-creation,hook-succeeded",
}
HOOK_ANNOTATIONS_JOB = HOOK_ANNOTATIONS_RBAC | {
    "argocd.argoproj.io/sync-wave": "-5",
    "helm.sh/hook-weight": "-5",
}

DIGEST_PINNED = re.compile(r"^[^@\s]+@sha256:[0-9a-f]{64}$")


APP_ACCOUNT_ON = ("--set", "database.createAppAccount=true")


def render_on(*arguments: str):
    return render(CHART, *DATABASE_TOGGLE_ON, *APP_ACCOUNT_ON, *MARIADB_API_VERSIONS, *arguments)


def rendered_on(*arguments: str) -> list[dict]:
    result = render_on(*arguments)
    assert result.returncode == 0, result.stderr
    return objects(result.stdout)


def only(documents: list[dict], kind: str, api_version: str | None = None) -> dict:
    found = [
        d
        for d in documents
        if d.get("kind") == kind and (api_version is None or d.get("apiVersion") == api_version)
    ]
    assert len(found) == 1, f"expected one {kind}, found {len(found)}"
    return found[0]


def named(documents: list[dict], kind: str, name: str) -> dict:
    found = [d for d in documents if d.get("kind") == kind and d["metadata"]["name"] == name]
    assert len(found) == 1, f"expected one {kind}/{name}, found {len(found)}"
    return found[0]


def max_user_connections(*arguments: str) -> int:
    return only(rendered_on(*arguments), "User", GROUP)["spec"]["maxUserConnections"]


def refused(result, *needles: str) -> None:
    assert result.returncode != 0, "the render succeeded"
    for needle in needles:
        assert needle in result.stderr, result.stderr


def values_file(tmp_path: Path, body: str) -> tuple[str, str]:
    path = tmp_path / "overlay.yaml"
    path.write_text(body)
    return "-f", str(path)


# ── THE USER AND THE GRANT ───────────────────────────────────────────────────


def test_the_user_renders_with_exact_fields() -> None:
    documents = rendered_on()
    user = only(documents, "User", GROUP)
    instance = only(documents, "MariaDB", GROUP)
    assert user["metadata"]["name"] == USER_OBJECT
    assert user["spec"] == {
        "name": APP_USER,
        "mariaDbRef": {"name": instance["metadata"]["name"]},
        "passwordSecretKeyRef": {"name": APP_SECRET, "key": "password"},
        "host": "%",
        "maxUserConnections": DEFAULT_MAX_USER_CONNECTIONS,
    }


def test_the_user_and_grant_inherit_what_the_operator_user_inherits() -> None:
    # mariadb-operator 26.6.0 (`mariadb_controller.go:928-929`) copies
    # `cleanupPolicy` and `inheritMetadata` off the MariaDB spec onto its own
    # user. This chart's MariaDB sets neither, so the app account carries neither.
    documents = rendered_on()
    instance = only(documents, "MariaDB", GROUP)
    for kind in ("User", "Grant"):
        spec = only(documents, kind, GROUP)["spec"]
        assert spec.get("cleanupPolicy") == instance["spec"].get("cleanupPolicy"), kind
        assert "inheritMetadata" not in instance["spec"]
        assert "cleanupPolicy" not in spec, kind
        assert set(only(documents, kind, GROUP)["metadata"]) == {"name", "labels"}, kind


def test_the_grant_renders_with_exact_fields() -> None:
    documents = rendered_on()
    grant = only(documents, "Grant", GROUP)
    user = only(documents, "User", GROUP)
    instance = only(documents, "MariaDB", GROUP)
    assert grant["metadata"]["name"] == GRANT_OBJECT
    assert grant["spec"] == {
        "mariaDbRef": {"name": instance["metadata"]["name"]},
        "privileges": ["ALL PRIVILEGES"],
        "database": instance["spec"]["database"],
        "table": "*",
        "username": user["spec"]["name"],
        "host": "%",
        "grantOption": False,
    }


def test_the_pod_still_connects_as_the_operator_user() -> None:
    # ADR-1142 rule 9: the credential cutover is a separate change.
    documents = rendered_on()
    deployment = only(documents, "Deployment")
    (container,) = deployment["spec"]["template"]["spec"]["containers"]
    env = {e["name"]: e.get("value") for e in container["env"]}
    assert env["DB_USER"] == "iam"
    secrets = [v["secret"]["secretName"] for v in deployment["spec"]["template"]["spec"]["volumes"] if "secret" in v]
    assert APP_SECRET not in secrets
    assert "iam-db-password" in secrets


# ── maxUserConnections ───────────────────────────────────────────────────────

CONNECTION_CASES = [
    pytest.param((), 22, id="defaults"),
    pytest.param(("--set", "autoscaling.maxReplicas=10"), 34, id="maxReplicas-10"),
    pytest.param(("--set", "replicaCount=8"), 28, id="replicaCount-above-maxReplicas"),
    pytest.param(("--set", "rollingUpdate.maxSurge=2"), 25, id="maxSurge-2"),
    pytest.param(("--set", "rollingUpdate.maxSurge=0"), 19, id="maxSurge-0"),
    pytest.param(("--set", "database.maxConnections=5"), 36, id="maxConnections-5"),
    pytest.param(("--set-string", "rollingUpdate.maxSurge=50%"), 28, id="maxSurge-50pct"),
    pytest.param(("--set-string", "rollingUpdate.maxSurge=25%"), 25, id="maxSurge-25pct-rounds-up"),
    pytest.param(("--set", "rollingUpdate.maxSurge=null"), 25, id="maxSurge-absent-is-25pct"),
    pytest.param(
        ("--set", "autoscaling.enabled=true", *KEDA_API_VERSIONS),
        22,
        id="autoscaling-on",
    ),
    pytest.param(
        ("--set", "autoscaling.enabled=true", "--set", "replicaCount=8", *KEDA_API_VERSIONS),
        28,
        id="autoscaling-on-replicaCount-above",
    ),
    pytest.param(
        ("--set", "autoscaling.enabled=true", "--set", "autoscaling.maxReplicas=9", *KEDA_API_VERSIONS),
        31,
        id="autoscaling-on-maxReplicas-9",
    ),
    pytest.param(
        ("--set", "autoscaling.enabled=false", "--set", "autoscaling.maxReplicas=9"),
        31,
        id="autoscaling-off-still-takes-maxReplicas",
    ),
]


@pytest.mark.parametrize("arguments, expected", CONNECTION_CASES)
def test_max_user_connections_tracks_each_input(arguments: tuple[str, ...], expected: int) -> None:
    assert max_user_connections(*arguments) == expected


def test_max_user_connections_from_a_values_file(tmp_path: Path) -> None:
    # A values-file number is a float64, not the int64 `--set` hands over.
    overlay = values_file(tmp_path, "rollingUpdate:\n  maxSurge: 2\nautoscaling:\n  maxReplicas: 7\n")
    assert max_user_connections(*overlay) == (7 + 2) * 3 + 1


@pytest.mark.parametrize(
    "arguments",
    [
        pytest.param(("--set-string", "rollingUpdate.maxSurge=abc"), id="word"),
        pytest.param(("--set-string", "rollingUpdate.maxSurge=2"), id="digit-string"),
        pytest.param(("--set", "rollingUpdate.maxSurge=-1"), id="negative"),
        pytest.param(("--set", "rollingUpdate.maxSurge=1.5"), id="fraction"),
        pytest.param(("--set-string", "rollingUpdate.maxSurge=050%"), id="leading-zero-percent"),
    ],
)
def test_an_unreadable_max_surge_is_refused(arguments: tuple[str, ...]) -> None:
    refused(render_on(*arguments), "rollingUpdate.maxSurge")


def test_the_bound_refuses_one_above_the_engine_headroom() -> None:
    # 22 against 26 - 5 = 21.
    refused(
        render_on("--set", "database.engineMaxConnections=26"),
        "maxUserConnections",
        "engineMaxConnections",
        "engineOperatorReserve",
    )


def test_the_bound_itself_renders() -> None:
    # 22 against 27 - 5 = 22.
    assert max_user_connections("--set", "database.engineMaxConnections=27") == 22


def test_the_bound_reads_the_reserve() -> None:
    # 22 against 30 - 9 = 21.
    refused(
        render_on("--set", "database.engineMaxConnections=30", "--set", "database.engineOperatorReserve=9"),
        "maxUserConnections",
    )


# ── THE NAME REFUSALS ────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "arguments, needle",
    [
        pytest.param(("--set", "database.appUser=iam"), "must differ from `database.user`", id="user-equal"),
        pytest.param(
            ("--set", "database.appPasswordSecret=iam-db-password"),
            "must differ from `database.passwordSecret`",
            id="secret-equal",
        ),
        pytest.param(
            ("--set", "database.appPasswordSecret=iam-db-mariadb-root"),
            "must differ from `database.instance.rootPasswordSecret`",
            id="secret-equal-root",
        ),
        pytest.param(
            (
                "--set",
                "database.instance.rootPasswordSecret=custom-root",
                "--set",
                "database.appPasswordSecret=custom-root",
            ),
            "must differ from `database.instance.rootPasswordSecret`",
            id="secret-equal-custom-root",
        ),
        pytest.param(("--set", "database.appUser="), "`database.appUser` must be a non-empty string", id="user-empty"),
        pytest.param(
            ("--set", "database.appPasswordSecret="),
            "`database.appPasswordSecret` must be a non-empty string",
            id="secret-empty",
        ),
        pytest.param(("--set", "database.appUser=5"), "`database.appUser` must be a non-empty string", id="user-int"),
        pytest.param(
            ("--set", "database.appPasswordSecret=Not_A_Name"),
            "`database.appPasswordSecret` must be a DNS-1123",
            id="secret-not-a-name",
        ),
        pytest.param(("--set", "database.appUser=Iam_app"), "must be a MariaDB user name", id="user-uppercase"),
        pytest.param(("--set", "database.appUser=iam-app"), "must be a MariaDB user name", id="user-dash"),
        pytest.param(("--set-string", "database.appUser=a'b"), "must be a MariaDB user name", id="user-quote"),
        pytest.param(("--set", "database.appUser=1iam"), "must be a MariaDB user name", id="user-leading-digit"),
        pytest.param(("--set", "database.appUser=" + "a" * 33), "must be a MariaDB user name", id="user-33-chars"),
    ],
)
def test_each_name_refusal_fires(arguments: tuple[str, ...], needle: str) -> None:
    refused(render_on(*arguments), needle)


def test_a_32_character_user_name_renders() -> None:
    name = "t" + "a_1" * 10 + "z"
    assert len(name) == 32
    assert only(rendered_on("--set", f"database.appUser={name}"), "User", GROUP)["spec"]["name"] == name


@pytest.mark.parametrize(
    "arguments",
    [
        pytest.param(
            ("--set", "replicaCount=2147483647", "--set", "database.maxConnections=0"),
            id="pods-over-int32",
        ),
        pytest.param(("--set", "replicaCount=2147483647"), id="replicaCount-int32-max"),
        pytest.param(("--set", "autoscaling.maxReplicas=2147483647"), id="maxReplicas-int32-max"),
        pytest.param(
            ("--set", "replicaCount=1000000", "--set", "database.maxConnections=1000000"),
            id="product-over-int32",
        ),
        pytest.param(("--set", "database.maxConnections=99999999999"), id="pool-over-int32"),
        pytest.param(
            ("--set", "database.maxConnections=99999999999999999", "--set", "replicaCount=10"),
            id="would-wrap-int64",
        ),
    ],
)
def test_an_overflowing_cap_is_refused_before_it_wraps(arguments: tuple[str, ...]) -> None:
    # Raise the engine ceiling too, so only the overflow guard can refuse.
    refused(
        render_on("--set", "database.engineMaxConnections=100000000000000000", *arguments),
        "would exceed 2147483647",
    )


def test_the_largest_cap_that_fits_renders() -> None:
    # (max(6, 2) + 1) x 306783378 + 1 = 2147483647.
    assert (
        max_user_connections(
            "--set", "database.maxConnections=306783378", "--set", "database.engineMaxConnections=2147483652"
        )
        == 2147483647
    )


@pytest.mark.parametrize(
    "toggles",
    [
        pytest.param((), id="create-off"),
        pytest.param((*DATABASE_TOGGLE_ON, *MARIADB_API_VERSIONS), id="create-on-app-account-off"),
    ],
)
def test_the_name_refusals_sit_behind_the_toggles(toggles: tuple[str, ...]) -> None:
    result = render(
        CHART,
        *toggles,
        "--set",
        "database.appUser=",
        "--set",
        "database.appPasswordSecret=",
        "--set",
        "database.engineMaxConnections=10",
        "--set-string",
        "rollingUpdate.maxSurge=abc",
    )
    assert result.returncode == 0, result.stderr


# ── THE SECOND TOGGLE'S SHAPE (ADR-0797, ADR-0850) ───────────────────────────


@pytest.mark.parametrize(
    "arguments, needle",
    [
        pytest.param(("--set-string", "database.createAppAccount=false"), "must be true or false", id="string-false"),
        pytest.param(("--set", "database.createAppAccount=1"), "must be true or false", id="number"),
        pytest.param(("--set", "database.createAppAccount=null"), "`database.createAppAccount` is absent", id="nulled"),
    ],
)
def test_a_toggle_that_is_not_a_bool_is_refused(arguments: tuple[str, ...], needle: str) -> None:
    refused(render(CHART, *DATABASE_TOGGLE_ON, *MARIADB_API_VERSIONS, *arguments), needle)


# ── THE HOOK OBJECTS ─────────────────────────────────────────────────────────


def hook_objects(documents: list[dict]) -> dict[str, dict]:
    return {
        kind: named(documents, kind, HOOK_NAME)
        for kind in ("ServiceAccount", "Role", "RoleBinding", "Job")
    }


def test_the_hook_annotations_are_exact() -> None:
    hooks = hook_objects(rendered_on())
    for kind in ("ServiceAccount", "Role", "RoleBinding"):
        assert hooks[kind]["metadata"]["annotations"] == HOOK_ANNOTATIONS_RBAC, kind
    assert hooks["Job"]["metadata"]["annotations"] == HOOK_ANNOTATIONS_JOB


def test_the_rbac_runs_before_the_job() -> None:
    hooks = hook_objects(rendered_on())
    job = hooks["Job"]["metadata"]["annotations"]
    for kind in ("ServiceAccount", "Role", "RoleBinding"):
        mine = hooks[kind]["metadata"]["annotations"]
        for key in ("helm.sh/hook-weight", "argocd.argoproj.io/sync-wave"):
            assert isinstance(mine[key], str), (kind, key)
            assert int(mine[key]) < int(job[key]), (kind, key)


def test_the_role_grants_create_on_secrets_and_nothing_else() -> None:
    # No `get`: the Job cannot read the live password, nor read back a Secret it
    # creates (ADR-1142 rule 4).
    role = hook_objects(rendered_on())["Role"]
    assert role["rules"] == [{"apiGroups": [""], "resources": ["secrets"], "verbs": ["create"]}]


def test_the_binding_wires_the_role_to_the_hook_account() -> None:
    hooks = hook_objects(rendered_on("--namespace", "a-release-ns"))
    binding = hooks["RoleBinding"]
    assert binding["roleRef"] == {
        "apiGroup": "rbac.authorization.k8s.io",
        "kind": "Role",
        "name": hooks["Role"]["metadata"]["name"],
    }
    assert binding["subjects"] == [
        {"kind": "ServiceAccount", "name": hooks["ServiceAccount"]["metadata"]["name"], "namespace": "a-release-ns"}
    ]
    pod = hooks["Job"]["spec"]["template"]["spec"]
    assert pod["serviceAccountName"] == hooks["ServiceAccount"]["metadata"]["name"]


def test_the_token_mounts_on_the_hook_pod_only() -> None:
    hooks = hook_objects(rendered_on())
    assert hooks["ServiceAccount"]["automountServiceAccountToken"] is False
    assert hooks["Job"]["spec"]["template"]["spec"]["automountServiceAccountToken"] is True


def test_the_job_is_bounded_and_locked_down() -> None:
    job = hook_objects(rendered_on())["Job"]
    spec = job["spec"]
    assert spec["activeDeadlineSeconds"] == 300
    assert spec["backoffLimit"] == 2
    assert isinstance(spec["ttlSecondsAfterFinished"], int) and spec["ttlSecondsAfterFinished"] > 0
    pod = spec["template"]["spec"]
    assert pod["restartPolicy"] == "Never"
    assert pod["securityContext"]["runAsNonRoot"] is True
    assert pod["securityContext"]["seccompProfile"] == {"type": "RuntimeDefault"}
    (container,) = pod["containers"]
    assert container["securityContext"]["readOnlyRootFilesystem"] is True
    assert container["securityContext"]["allowPrivilegeEscalation"] is False
    assert container["securityContext"]["capabilities"] == {"drop": ["ALL"]}
    assert "env" not in container and "envFrom" not in container


def test_the_deadline_covers_every_attempt() -> None:
    # Each attempt is a 30s allowance to start plus one request, capped by
    # curl's --max-time; the Job controller's backoff waits 10s, then 20s. The
    # deadline must exceed that sum, or a slow API server reads as
    # DeadlineExceeded before the retries are used.
    job = hook_objects(rendered_on())["Job"]
    (container,) = job["spec"]["template"]["spec"]["containers"]
    script = container["args"][0]
    max_times = [int(m) for m in re.findall(r"--max-time (\d+)", script)]
    connects = re.findall(r"--connect-timeout (\d+)", script)
    assert len(max_times) == 1 and len(connects) == 1, script
    attempts = job["spec"]["backoffLimit"] + 1
    assert attempts * (30 + sum(max_times)) + 10 + 20 < job["spec"]["activeDeadlineSeconds"]


def test_the_image_is_digest_pinned_and_from_values() -> None:
    job = hook_objects(rendered_on())["Job"]
    (container,) = job["spec"]["template"]["spec"]["containers"]
    values = yaml.safe_load((CHART / "values.yaml").read_text())
    assert DIGEST_PINNED.match(container["image"]), container["image"]
    assert container["image"] == values["database"]["appPasswordJob"]["image"]


def test_a_tag_only_image_is_refused() -> None:
    refused(
        render_on("--set", "database.appPasswordJob.image=curlimages/curl:8.16.0"),
        "`database.appPasswordJob.image` must be pinned by digest",
    )


def test_the_scratch_volume_is_memory_backed() -> None:
    pod = hook_objects(rendered_on())["Job"]["spec"]["template"]["spec"]
    (container,) = pod["containers"]
    (volume,) = pod["volumes"]
    assert volume["emptyDir"]["medium"] == "Memory"
    (mount,) = container["volumeMounts"]
    assert mount["name"] == volume["name"]
    assert mount["mountPath"] == "/work"


# ── THE SCRIPT ───────────────────────────────────────────────────────────────


def the_script(*arguments: str) -> str:
    (container,) = hook_objects(rendered_on(*arguments))["Job"]["spec"]["template"]["spec"]["containers"]
    assert container["command"] == ["sh", "-c"]
    return container["args"][0]


def test_the_value_goes_from_urandom_into_a_file_and_nowhere_else() -> None:
    script = the_script()
    lines = [line.strip() for line in script.splitlines() if "/dev/urandom" in line]
    assert len(lines) == 1, lines
    (line,) = lines
    count = int(re.search(r"head -c (\d+) /dev/urandom", line).group(1))
    assert count >= 32
    # A pipeline whose only exit is a redirect into the scratch file: no `$(`,
    # no variable, no argv.
    assert "$(" not in line and "`" not in line
    assert line.endswith('>> "$body"'), line
    assert 'body="/work/' in script


def test_the_secret_is_created_from_the_file() -> None:
    script = the_script()
    assert '--data-binary "@$body"' in script
    # The token goes in as a header FILE too, never on argv.
    assert '--header "@$work/auth"' in script
    assert "Bearer $" not in script


def test_the_script_never_echoes_the_body() -> None:
    script = the_script()
    # `$body` may appear only as a redirect target or as curl's `@` file.
    stripped = re.sub(r'>>? "\$body"|"@\$body"|body="/work/[a-z.]+"|wc -c < "\$body"|rm -f "\$body"', "", script)
    assert "$body" not in stripped, stripped


def test_the_secret_is_labelled_and_named_from_values() -> None:
    script = the_script("--set", "database.appPasswordSecret=other-name")
    assert '"name":"other-name"' in script
    assert '"app.kubernetes.io/component":"app-password"' in script
    # Argo's label tracking reads app.kubernetes.io/instance; the Secret must
    # not look tracked, or a prune deletes it.
    assert "app.kubernetes.io/instance" not in script


# ── THE SCRIPT, RUN ──────────────────────────────────────────────────────────
#
# THE PROOF IS EXECUTION, not a substring. The rendered script runs under `sh`
# with a stub `curl` first on PATH. The stub records its argv and its
# environment, keeps a copy of the body it was handed, prints the HTTP code it
# is told to and exits with the status it is told to. The two pod paths are
# pointed at a scratch tree. A stub `head` can shorten what /dev/urandom yields.

SA_PATH = "/var/run/secrets/kubernetes.io/serviceaccount"
TOKEN = "TOKEN-VALUE-THAT-MUST-NOT-LEAK"

STUB_CURL = r"""#!/bin/sh
printf '%s\n' "CALL" >> "$STUB/argv"
for a in "$@"; do printf '%s\n' "$a" >> "$STUB/argv"; done
env >> "$STUB/env"
for a in "$@"; do
  case "$a" in @*secret.json) cp "${a#@}" "$STUB/posted.json" ;; esac
done
printf '%s' "$STUB_CODE"
exit "$STUB_EXIT"
"""

STUB_HEAD = r"""#!/bin/sh
printf '%s' "$STUB_HEAD_OUT"
"""


def run_script(tmp_path: Path, code: str, exit_status: int = 0, head_out: str | None = None):
    script = the_script()
    assert script.count(SA_PATH) == 1 and script.count("/work") >= 2, script
    sa = tmp_path / "sa"
    work = tmp_path / "work"
    stub = tmp_path / "stub"
    for directory in (sa, work, stub):
        directory.mkdir()
    (sa / "namespace").write_text("a-ns")
    (sa / "token").write_text(TOKEN)
    (sa / "ca.crt").write_text("ca")
    (stub / "curl").write_text(STUB_CURL)
    (stub / "curl").chmod(0o755)
    if head_out is not None:
        (stub / "head").write_text(STUB_HEAD)
        (stub / "head").chmod(0o755)
    body = script.replace(SA_PATH, str(sa)).replace("/work", str(work))
    env = {
        "PATH": f"{stub}{os.pathsep}{os.environ['PATH']}",
        "STUB": str(stub),
        "STUB_CODE": code,
        "STUB_EXIT": str(exit_status),
        "STUB_HEAD_OUT": head_out or "",
    }
    result = subprocess.run(["sh", "-c", body], env=env, capture_output=True, text=True, timeout=60)
    argv = (stub / "argv").read_text() if (stub / "argv").exists() else ""
    environment = (stub / "env").read_text() if (stub / "env").exists() else ""
    posted = stub / "posted.json"
    password = json.loads(posted.read_text())["stringData"]["password"] if posted.exists() else None
    return result, argv, environment, password


SCRIPT_OUTCOMES = [
    pytest.param("201", 0, 0, id="201-created"),
    pytest.param("409", 0, 0, id="409-exists"),
    pytest.param("403", 0, 1, id="403-refused"),
    pytest.param("500", 0, 1, id="500-refused"),
    pytest.param("000", 7, 1, id="transport-failure"),
]


@pytest.mark.parametrize("code, exit_status, expected", SCRIPT_OUTCOMES)
def test_the_script_exits_on_the_answer(tmp_path: Path, code: str, exit_status: int, expected: int) -> None:
    result, argv, environment, password = run_script(tmp_path, code, exit_status)
    assert result.returncode == expected, (result.stdout, result.stderr)
    # ONE request, a POST to the collection: no GET of the Secret, ever.
    calls = argv.split("CALL\n")[1:]
    assert len(calls) == 1, argv
    (call,) = calls
    args = call.splitlines()
    assert args[-1] == "https://kubernetes.default.svc/api/v1/namespaces/a-ns/secrets", args
    assert "--data-binary" in args and "--get" not in args and "-G" not in args
    assert not any(a.upper() in ("GET", "HEAD") for a in args), args
    assert args[args.index("--output") + 1] == "/dev/null"
    # The value that was POSTed leaks nowhere, and neither does the token.
    assert password is not None and len(password) == 44, password
    for haystack in (argv, environment, result.stdout, result.stderr):
        assert password not in haystack
        assert TOKEN not in haystack


@pytest.mark.parametrize(
    "head_out",
    [pytest.param("", id="empty"), pytest.param("0123456789", id="short")],
)
def test_a_short_password_is_never_posted(tmp_path: Path, head_out: str) -> None:
    result, argv, _, password = run_script(tmp_path, "201", 0, head_out=head_out)
    assert result.returncode == 1, (result.stdout, result.stderr)
    assert argv == "" and password is None, argv


# ── WHAT THE HOOK POD IS NOT ─────────────────────────────────────────────────


def test_the_hook_pod_is_not_selected_by_the_service_pdb_or_policy() -> None:
    documents = rendered_on("--set", "networkPolicy.enabled=true")
    labels = hook_objects(documents)["Job"]["spec"]["template"]["metadata"]["labels"]
    selectors = [only(documents, "Service")["spec"]["selector"]]
    selectors.append(only(documents, "PodDisruptionBudget")["spec"]["selector"]["matchLabels"])
    policies = [d for d in documents if d.get("kind") == "NetworkPolicy"]
    assert policies, "networkPolicy.enabled=true rendered no policy"
    for policy in policies:
        selectors.append(policy["spec"]["podSelector"].get("matchLabels", {}))
        # No egress control exists, so nothing blocks the pod's call to the API.
        assert "Egress" not in policy["spec"].get("policyTypes", []), policy
    for selector in selectors:
        assert selector and not all(labels.get(k) == v for k, v in selector.items()), selector


# ── OFF ──────────────────────────────────────────────────────────────────────
#
# THE APP ACCOUNT DEFAULTS OFF EVEN WHERE `database.create` IS ON. The parent
# chart sets `database.create: true` and keeps literal registries of every object
# it renders, so a pin that added objects at the parent's settings could never
# pass its `pre_pin_parent` gate. The parent turns `createAppAccount` on in the
# PR that updates those literals, after this pin lands.

NEW_KINDS = {"User", "Grant", "Role", "RoleBinding", "Job"}


@pytest.mark.parametrize(
    "arguments",
    [
        pytest.param((), id="defaults"),
        pytest.param(("--set", "autoscaling.enabled=true", *KEDA_API_VERSIONS), id="autoscaling"),
        pytest.param((*DATABASE_TOGGLE_ON, *MARIADB_API_VERSIONS), id="create-on-app-account-off"),
        pytest.param(("--set", "database.createAppAccount=true"), id="app-account-on-create-off"),
    ],
)
def test_with_create_off_none_of_it_renders(arguments: tuple[str, ...]) -> None:
    result = render(CHART, *arguments)
    assert result.returncode == 0, result.stderr
    documents = objects(result.stdout)
    assert not [d for d in documents if d.get("kind") in NEW_KINDS]
    assert [d["metadata"]["name"] for d in documents if d.get("kind") == "ServiceAccount"] == ["iam-db"]
    assert HOOK_NAME not in result.stdout
