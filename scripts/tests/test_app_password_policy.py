"""THE ADMISSION POLICY THAT NARROWS THE HOOK'S `create` (yaadgaar #566, ADR-1142 rule 8).

The hook Role grants `create` on secrets, and `resourceNames` cannot narrow
`create`. So, behind the same two toggles as the hook, the chart renders a
ValidatingAdmissionPolicy and its binding. They let the hook ServiceAccount
create exactly one Secret: `database.appPasswordSecret`, type `Opaque`, the
hook's own labels, one `password` key, and nothing else. Every other Secret
CREATE by that account is denied. Other accounts never match the policy.

WHAT THIS SUITE PROVES, AND WHAT IT DOES NOT. It reads rendered objects: the
match, the expressions, the failure policy, the binding and the hook ordering.
It cannot run admission. CI carries helm and PyYAML and no CEL engine, and live
admission needs a cluster. The literals below are literals, so a template that
computes the wrong value cannot agree with itself.

Run: python3 -m pytest scripts/tests/ -q
"""

from __future__ import annotations

import json
import re

import pytest

from test_app_account import (
    APP_SECRET,
    HOOK_NAME,
    hook_objects,
    named,
    rendered_on,
    the_script,
)
from test_render_checks import (
    CHART,
    CHART_NAME,
    DATABASE_TOGGLE_ON,
    KEDA_API_VERSIONS,
    MARIADB_API_VERSIONS,
    helm,
    objects,
    render,
)

API = "admissionregistration.k8s.io/v1"
NAMESPACE = "a-release-ns"
POLICY_NAME = f"iam-db-app-password.{NAMESPACE}"
USERNAME = f"system:serviceaccount:{NAMESPACE}:{HOOK_NAME}"
ROOT_SECRET = "iam-db-mariadb-root"

LABELS = {
    "app.kubernetes.io/name": "iam-db",
    "app.kubernetes.io/component": "app-password",
    "app.kubernetes.io/created-by": HOOK_NAME,
}

POLICY_ANNOTATIONS = {
    "argocd.argoproj.io/hook": "PreSync",
    "argocd.argoproj.io/hook-delete-policy": "BeforeHookCreation",
    "argocd.argoproj.io/sync-wave": "-20",
    "helm.sh/hook": "pre-install,pre-upgrade",
    "helm.sh/hook-weight": "-20",
    "helm.sh/hook-delete-policy": "before-hook-creation",
}

LABEL_MAP = (
    "{'app.kubernetes.io/component': 'app-password', "
    f"'app.kubernetes.io/created-by': '{HOOK_NAME}', "
    "'app.kubernetes.io/name': 'iam-db'}"
)


def expected_validations(secret: str) -> list[dict]:
    return [
        {
            "expression": f"object.metadata.name == '{secret}'",
            "message": f"{HOOK_NAME} may create only the Secret {secret}",
            "reason": "Forbidden",
        },
        {
            "expression": "has(object.type) && object.type == 'Opaque'",
            "message": f"{HOOK_NAME} may create only a Secret of type Opaque",
            "reason": "Forbidden",
        },
        {
            "expression": f"has(object.metadata.labels) && object.metadata.labels == {LABEL_MAP}",
            "message": f"{HOOK_NAME} may create only a Secret with exactly the app-password labels",
            "reason": "Forbidden",
        },
        {
            "expression": (
                "(!has(object.metadata.annotations) || size(object.metadata.annotations) == 0)"
                " && (!has(object.metadata.ownerReferences) || size(object.metadata.ownerReferences) == 0)"
                " && (!has(object.metadata.finalizers) || size(object.metadata.finalizers) == 0)"
                " && !has(object.immutable)"
            ),
            "message": (
                f"{HOOK_NAME} may not set annotations, ownerReferences, finalizers or immutable on the Secret"
            ),
            "reason": "Forbidden",
        },
        {
            "expression": "has(object.data) && size(object.data) == 1 && 'password' in object.data",
            "message": f"{HOOK_NAME} may create only a Secret whose one key is password",
            "reason": "Forbidden",
        },
    ]


def policy_objects(*arguments: str) -> tuple[dict, dict]:
    documents = rendered_on("--namespace", NAMESPACE, *arguments)
    policies = [d for d in documents if d.get("kind") == "ValidatingAdmissionPolicy"]
    bindings = [d for d in documents if d.get("kind") == "ValidatingAdmissionPolicyBinding"]
    assert len(policies) == 1, f"expected one ValidatingAdmissionPolicy, found {len(policies)}"
    assert len(bindings) == 1, f"expected one ValidatingAdmissionPolicyBinding, found {len(bindings)}"
    return policies[0], bindings[0]


# ── THE POLICY ───────────────────────────────────────────────────────────────


def test_the_policy_and_binding_are_v1_and_cluster_scoped() -> None:
    for document in policy_objects():
        assert document["apiVersion"] == API, document["kind"]
        assert "namespace" not in document["metadata"], document["kind"]


def test_the_names_carry_chart_and_namespace_and_not_the_release() -> None:
    # Cluster-scoped, so two namespaces must not collide. One to one with the
    # hook account, whose name carries no release either.
    policy, binding = policy_objects()
    assert policy["metadata"]["name"] == POLICY_NAME
    assert binding["metadata"]["name"] == POLICY_NAME
    other, _ = policy_objects("--namespace", "other-ns")
    assert other["metadata"]["name"] == "iam-db-app-password.other-ns"
    result = helm(
        "template", "another-release", str(CHART), "-f", str(CHART / "ci" / "values.yaml"), "--namespace", NAMESPACE,
        *DATABASE_TOGGLE_ON, "--set", "database.createAppAccount=true", *MARIADB_API_VERSIONS,
    )
    assert result.returncode == 0, result.stderr
    names = {
        d["metadata"]["name"]
        for d in objects(result.stdout)
        if d.get("kind") in ("ValidatingAdmissionPolicy", "ValidatingAdmissionPolicyBinding")
    }
    assert names == {POLICY_NAME}
    assert CHART_NAME != "another-release"


def test_the_policy_fails_closed() -> None:
    policy, _ = policy_objects()
    assert policy["spec"]["failurePolicy"] == "Fail"


def test_the_policy_matches_secret_create_in_the_release_namespace() -> None:
    policy, _ = policy_objects()
    assert policy["spec"]["matchConstraints"] == {
        "matchPolicy": "Equivalent",
        "namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": NAMESPACE}},
        "resourceRules": [
            {
                "apiGroups": [""],
                "apiVersions": ["v1"],
                "operations": ["CREATE"],
                "resources": ["secrets"],
            }
        ],
    }


def test_only_the_hook_account_matches() -> None:
    # A match condition, not a validation: a request from any other account
    # evaluates it to false and skips the policy, so `Fail` never touches it.
    policy, _ = policy_objects()
    assert policy["spec"]["matchConditions"] == [
        {"name": "the-hook-account", "expression": f"request.userInfo.username == '{USERNAME}'"}
    ]


def test_the_match_condition_names_the_hook_service_account() -> None:
    documents = rendered_on("--namespace", NAMESPACE)
    account = named(documents, "ServiceAccount", HOOK_NAME)
    (condition,) = policy_objects()[0]["spec"]["matchConditions"]
    assert f":{NAMESPACE}:{account['metadata']['name']}'" in condition["expression"]


def test_the_validations_are_exact() -> None:
    policy, _ = policy_objects()
    assert policy["spec"]["validations"] == expected_validations(APP_SECRET)
    assert set(policy["spec"]) == {"failurePolicy", "matchConstraints", "matchConditions", "validations"}


def test_the_allowed_name_follows_values() -> None:
    policy, _ = policy_objects("--set", "database.appPasswordSecret=other-name")
    assert policy["spec"]["validations"] == expected_validations("other-name")


def test_the_allowed_secret_is_the_one_the_hook_posts() -> None:
    # The labels and name the policy allows are the ones the hook's body
    # carries: read off the rendered script, not restated.
    script = the_script("--set", "database.appPasswordSecret=other-name")
    match = re.search(r'"metadata":(\{"labels":\{[^}]*\},"name":"[^"]*"\})', script)
    assert match, script
    metadata = json.loads(match.group(1))
    assert metadata == {"labels": LABELS, "name": "other-name"}
    assert '"type":"Opaque"' in script
    assert '"stringData":{"password":"' in script
    policy, _ = policy_objects("--set", "database.appPasswordSecret=other-name")
    labels = policy["spec"]["validations"][2]["expression"]
    for key, value in metadata["labels"].items():
        assert f"'{key}': '{value}'" in labels
    assert labels.count(": '") == len(metadata["labels"])


# ── THE BINDING ──────────────────────────────────────────────────────────────


def test_the_binding_denies_and_names_the_policy() -> None:
    policy, binding = policy_objects()
    assert binding["spec"] == {
        "policyName": policy["metadata"]["name"],
        "validationActions": ["Deny"],
    }


# ── ORDER: THE POLICY IS LIVE BEFORE THE HOOK RUNS ───────────────────────────


def test_the_policy_is_a_hook_that_persists() -> None:
    # A plain object is applied after every PreSync hook, so on a fresh install
    # the Job would run unpoliced. No HookSucceeded: the policy stays after a
    # successful sync, and is replaced at the next one.
    for document in policy_objects():
        assert document["metadata"]["annotations"] == POLICY_ANNOTATIONS, document["kind"]


def test_the_policy_runs_before_the_rbac_and_the_job() -> None:
    hooks = hook_objects(rendered_on("--namespace", NAMESPACE))
    for document in policy_objects():
        mine = document["metadata"]["annotations"]
        for kind in ("ServiceAccount", "Role", "RoleBinding", "Job"):
            theirs = hooks[kind]["metadata"]["annotations"]
            for key in ("helm.sh/hook-weight", "argocd.argoproj.io/sync-wave"):
                assert int(mine[key]) < int(theirs[key]), (document["kind"], kind, key)


def test_the_labels_name_the_hook() -> None:
    for document in policy_objects():
        assert document["metadata"]["labels"] == {"app.kubernetes.io/name": HOOK_NAME}, document["kind"]


# ── OFF ──────────────────────────────────────────────────────────────────────


def test_the_root_secret_refusal_sits_behind_the_toggles() -> None:
    for toggles in ((), (*DATABASE_TOGGLE_ON, *MARIADB_API_VERSIONS)):
        result = render(CHART, *toggles, "--set", f"database.appPasswordSecret={ROOT_SECRET}")
        assert result.returncode == 0, result.stderr


@pytest.mark.parametrize(
    "arguments",
    [
        pytest.param((), id="defaults"),
        pytest.param(("--set", "autoscaling.enabled=true", *KEDA_API_VERSIONS), id="autoscaling"),
        pytest.param((*DATABASE_TOGGLE_ON, *MARIADB_API_VERSIONS), id="create-on-app-account-off"),
        pytest.param(("--set", "database.createAppAccount=true"), id="app-account-on-create-off"),
    ],
)
def test_with_either_toggle_off_no_policy_renders(arguments: tuple[str, ...]) -> None:
    result = render(CHART, *arguments)
    assert result.returncode == 0, result.stderr
    kinds = {d.get("kind") for d in objects(result.stdout)}
    assert not kinds & {"ValidatingAdmissionPolicy", "ValidatingAdmissionPolicyBinding"}
    assert "app-password." not in result.stdout
