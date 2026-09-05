#!/usr/bin/env bash
# ADR-0569: a configuration knob has ONE source and NO compiled-in default.
#
# This gate exists because the rule was held by attention alone. An estate-wide
# audit found no hook, no lint and no clippy.toml anywhere that would catch a
# new compiled-in default in review, and ADR-0574 rules that a defect is closed
# as a CLASS rather than as an instance: the change that ships is the one that
# makes the next occurrence impossible or visible.
#
# THE GATE ASSERTS THAT IT ACTUALLY SEARCHED SOMETHING, and prints the count it
# searched. A grep-driven check that passes because it globbed nothing is the
# fifth instance of the check-that-cannot-fail class this estate met in a week,
# and shipping one as the guard against a different class would be its own joke.
# `grep` exits 1 on no-match, which is this gate's success, and 2 on error —
# `! grep ...` cannot tell those apart, so the exit status is read explicitly.
set -euo pipefail

roots=()
for d in src tests benches; do
    [ -d "$d" ] && roots+=("$d")
done

if [ ${#roots[@]} -eq 0 ]; then
    echo "ADR-0569 gate: NO RUST SOURCE ROOT FOUND. Looked for src/, tests/ and" >&2
    echo "  benches/ under $(pwd) and none exist. This is a failure and not a" >&2
    echo "  pass: a gate that searches nothing proves nothing." >&2
    exit 1
fi

files=()
while IFS= read -r f; do files+=("$f"); done < <(find "${roots[@]}" -type f -name '*.rs' | sort)

if [ ${#files[@]} -eq 0 ]; then
    echo "ADR-0569 gate: MATCHED 0 RUST FILES under ${roots[*]}. The source roots" >&2
    echo "  exist but hold no .rs file, so this run checked nothing. A directory-" >&2
    echo "  exists check is not the same guard as a non-empty-glob check." >&2
    exit 1
fi

echo "ADR-0569 gate: searching ${#files[@]} Rust file(s) under ${roots[*]}."

fail=0

# Reports a violation when the pattern MATCHES. Reading grep's status explicitly
# keeps a grep error (2) from being mistaken for the no-match success (1).
forbid() {
    local pattern="$1" title="$2" guidance="$3" raw hits status
    set +e
    raw=$(grep -nE "$pattern" "${files[@]}")
    status=$?
    set -e
    if [ "$status" -eq 0 ]; then
        # An exception is allowed where the argument for it is written down. The
        # marker is the whole of the escape hatch, so `git grep ADR-0569-EXCEPTION`
        # answers "which knobs keep a fallback, and why" in one command.
        hits=$(printf '%s\n' "$raw" | grep -v 'ADR-0569-EXCEPTION' || true)
        if [ -n "$hits" ]; then
            echo "" >&2
            echo "ADR-0569 VIOLATION — $title" >&2
            while IFS= read -r line; do echo "  $line" >&2; done <<<"$hits"
            echo "  $guidance" >&2
            fail=1
        fi
    elif [ "$status" -ne 1 ]; then
        echo "ADR-0569 gate: grep failed with status $status while checking: $title" >&2
        exit 1
    fi
}

# The deleted signature itself. `env_or(key, default)` gave every compiled-in
# default in this binary a place to live; without it a default has no parameter
# to sit in.
forbid \
    'fn[[:space:]]+env_or\b' \
    'fn env_or is back.' \
    'Use env_required(key), which has no default parameter. ADR-0569.'

# A RENAME IS NOT A FIX. gateway already carried a second helper of this shape
# (parse_bucket_env(key, default)), so forbidding only the literal name env_or
# would pass env_or_default on day one.
forbid \
    'fn[[:space:]]+[A-Za-z0-9_]*env[A-Za-z0-9_]*[[:space:]]*(<[^>]*>)?\([^)]*default[[:space:]]*:' \
    "an environment helper takes a 'default' parameter." \
    'A knob reader must not accept a fallback. ADR-0569.'

# The inline form, which neither check above sees. An exception is allowed and
# is meant to be readable as one: mark the line ADR-0569-EXCEPTION and say why.
#
# SCANNED OVER A CHAIN-REJOINED VIEW, and that is not a refinement — without it
# this pattern misses the exact shape it forbids. `cargo fmt` breaks a method
# chain of three or more calls, so the fallback lands on its own line and a
# single-line pattern cannot see it. Measured on rustfmt's own output: the
# split form of `env::var("K").unwrap_or_else(...).parse().unwrap()` passed this
# gate with exit 0 while the one-line form in the same file was caught. A gate
# that the repository's own required formatter disarms is the check-that-cannot-
# fail class, in the guard built to close it.
#
# `nl -ba` numbers every line BEFORE the join, so the number that survives is the
# line the chain starts on and the report still points at real source.
forbid_joined() {
    local pattern="$1" title="$2" guidance="$3" raw hits f
    raw=""
    for f in "${files[@]}"; do
        local joined
        joined=$(nl -ba "$f" | perl -0pe 's/\n\s*\d+\t\s*\./\./g' | grep -E "$pattern" || true)
        if [ -n "$joined" ]; then
            raw+="$(printf '%s\n' "$joined" | sed "s|^|$f:|")"$'\n'
        fi
    done
    hits=$(printf '%s' "$raw" | grep -v 'ADR-0569-EXCEPTION' || true)
    if [ -n "$hits" ]; then
        echo "" >&2
        echo "ADR-0569 VIOLATION — $title" >&2
        while IFS= read -r line; do [ -n "$line" ] && echo "  $line" >&2; done <<<"$hits"
        echo "  $guidance" >&2
        fail=1
    fi
}

forbid_joined \
    'env::var(_os)?\(.*unwrap_or(_else|_default)?\((.*)?$' \
    'a raw environment read falls back inline.' \
    'Use env_required(key), or mark the line ADR-0569-EXCEPTION with the argument.'

if [ "$fail" -ne 0 ]; then
    echo "" >&2
    echo "ADR-0569: a knob is read from one source and refuses the boot when absent." >&2
    exit 1
fi

echo "ADR-0569 gate: no compiled-in configuration default found."
