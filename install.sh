#!/usr/bin/env bash
# slopsquat-guard installer
# Copies slopsquat-guard.py to ~/.claude/hooks/ and registers it as a PreToolUse hook.
# Backs up settings.json before modifying.
#
# Usage:
#   ./install.sh              # install
#   ./install.sh --uninstall  # remove hook entry from settings.json (keeps script file)

set -euo pipefail

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

CLAUDE_DIR="${HOME}/.claude"
HOOKS_DIR="${CLAUDE_DIR}/hooks"
SETTINGS="${CLAUDE_DIR}/settings.json"
SCRIPT_NAME="slopsquat-guard.py"
SCRIPT_DEST="${HOOKS_DIR}/${SCRIPT_NAME}"
HOOK_COMMAND="python3 ${SCRIPT_DEST/#$HOME/~}"

say()  { printf "${GREEN}==>${NC} %s\n" "$1"; }
warn() { printf "${YELLOW}==>${NC} %s\n" "$1"; }
fail() { printf "${RED}==>${NC} %s\n" "$1" >&2; exit 1; }

require_python() {
  command -v python3 >/dev/null 2>&1 || fail "python3 not found in PATH. Please install Python 3.8+."
}

ensure_settings() {
  mkdir -p "${CLAUDE_DIR}"
  if [[ ! -f "${SETTINGS}" ]]; then
    echo '{}' > "${SETTINGS}"
    say "Created empty ${SETTINGS}"
  fi
}

backup_settings() {
  local stamp
  stamp=$(date +%s)
  cp "${SETTINGS}" "${SETTINGS}.bak.${stamp}"
  say "Backed up settings.json to settings.json.bak.${stamp}"
}

install_hook() {
  require_python
  ensure_settings
  mkdir -p "${HOOKS_DIR}"

  local source_script
  if [[ -f "$(dirname "$0")/${SCRIPT_NAME}" ]]; then
    source_script="$(dirname "$0")/${SCRIPT_NAME}"
  elif [[ -f "${SCRIPT_NAME}" ]]; then
    source_script="${SCRIPT_NAME}"
  else
    fail "${SCRIPT_NAME} not found next to install.sh."
  fi

  cp "${source_script}" "${SCRIPT_DEST}"
  chmod +x "${SCRIPT_DEST}"
  say "Installed ${SCRIPT_DEST}"

  backup_settings

  python3 - "$SETTINGS" "$HOOK_COMMAND" <<'PY'
import json, pathlib, sys
settings_path = pathlib.Path(sys.argv[1])
hook_command = sys.argv[2]
data = json.loads(settings_path.read_text())
hooks = data.setdefault("hooks", {})
pre = hooks.setdefault("PreToolUse", [])

# Remove any prior slopsquat-guard registration (idempotent install)
filtered = []
for entry in pre:
    inner = entry.get("hooks", []) or []
    if any("slopsquat-guard.py" in (h.get("command") or "") for h in inner):
        continue
    filtered.append(entry)

filtered.append({
    "matcher": "Bash",
    "hooks": [{
        "type": "command",
        "command": hook_command,
        "timeout": 10
    }]
})
hooks["PreToolUse"] = filtered
settings_path.write_text(json.dumps(data, indent=2))
print("hook registered for matcher=Bash")
PY

  say "Hook registered in ${SETTINGS}"
  say "Done. The next Bash command Claude Code runs will be checked."
}

uninstall_hook() {
  ensure_settings
  backup_settings
  python3 - "$SETTINGS" <<'PY'
import json, pathlib, sys
settings_path = pathlib.Path(sys.argv[1])
data = json.loads(settings_path.read_text())
hooks = data.get("hooks", {})
pre = hooks.get("PreToolUse", []) or []
new_pre = []
removed = 0
for entry in pre:
    inner = entry.get("hooks", []) or []
    if any("slopsquat-guard.py" in (h.get("command") or "") for h in inner):
        removed += 1
        continue
    new_pre.append(entry)
if not new_pre:
    hooks.pop("PreToolUse", None)
else:
    hooks["PreToolUse"] = new_pre
data["hooks"] = hooks
settings_path.write_text(json.dumps(data, indent=2))
print(f"removed {removed} slopsquat-guard registration(s)")
PY
  warn "Hook entry removed from settings.json. The script file at ${SCRIPT_DEST} was kept; delete it manually if desired."
}

case "${1:-}" in
  --uninstall|uninstall)
    uninstall_hook
    ;;
  ""|--install|install)
    install_hook
    ;;
  *)
    cat <<EOF
Usage:
  $0              Install slopsquat-guard hook
  $0 --uninstall  Remove the hook from settings.json
EOF
    exit 1
    ;;
esac
