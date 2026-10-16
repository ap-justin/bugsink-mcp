#!/bin/bash
# installs this branch's dependencies at session start on a cloud vm.
# registered in `.claude/settings.json` as a SessionStart hook on `startup|resume`.
set -euo pipefail
[ "${CLAUDE_CODE_REMOTE:-}" = "true" ] || exit 0
cd "$CLAUDE_PROJECT_DIR"

python3 -m venv .venv
.venv/bin/pip install -q -r requirements.txt
