"""No file cites a placeholder ADR id.

`LISTEN_TLS_CLIENT_AUTH` was specified under a placeholder id ("X" + "-ADR-1") before
the ADR was numbered. The ADR is ADR-0854, so a citation must use that id. A
bare working name cannot be looked up, and an adopter reading a refusal
message cannot find the rule it cites.

The checked tree is `git ls-files`, so build output and virtualenvs are out.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
# Built from parts so this file does not match its own search.
PLACEHOLDER = "X-" + "ADR-1"
REAL_ID = "ADR-0854"


def tracked_files() -> list[Path]:
    out = subprocess.run(
        ["git", "ls-files", "-z"], cwd=ROOT, check=True, capture_output=True, text=True
    ).stdout
    return [ROOT / name for name in out.split("\0") if name]


def test_no_file_cites_the_placeholder_adr_id():
    hits = []
    for path in tracked_files():
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for number, line in enumerate(text.splitlines(), 1):
            if PLACEHOLDER in line:
                hits.append(f"{path.relative_to(ROOT)}:{number}")
    assert not hits, f"cite {REAL_ID}, not {PLACEHOLDER}: {hits}"
