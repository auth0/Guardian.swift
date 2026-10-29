# shellcheck shell=bash
#
# tools/build/common.sh — shared primitives for every build module.
#
# Sourced FIRST by build.sh. Provides the color palette and the log/die helpers
# that all other modules rely on. Contains no build logic and no side effects
# beyond defining variables/functions, so it's safe to source anywhere.
#
# NOT meant to be executed directly — it is `source`d into build.sh's shell, so
# everything it defines (colors, functions) is shared with the other modules.

# ─── Colors ───────────────────────────────────────────────────────────────────
# Enable ANSI colors only when stderr is a real terminal (so CI logs and pipes
# stay clean) and NO_COLOR isn't set (https://no-color.org). Otherwise blank.
if [[ -t 2 && -z "${NO_COLOR:-}" ]]; then
  C_RESET=$'\033[0m'; C_BOLD=$'\033[1m'; C_DIM=$'\033[2m'
  C_BLUE=$'\033[0;34m'; C_CYAN=$'\033[0;36m'; C_GREEN=$'\033[0;32m'
  C_YELLOW=$'\033[0;33m'; C_RED=$'\033[0;31m'
else
  C_RESET=''; C_BOLD=''; C_DIM=''
  C_BLUE=''; C_CYAN=''; C_GREEN=''; C_YELLOW=''; C_RED=''
fi

# ─── Logging ──────────────────────────────────────────────────────────────────
# All diagnostics go to stderr so that --dryRun's machine-readable line (and any
# future scripted consumer) can read stdout cleanly.
log()  { printf '%s[build.sh]%s %s\n' "$C_BLUE" "$C_RESET" "$*" >&2; }
warn() { printf '%s[build.sh]%s %s\n' "$C_YELLOW" "$C_RESET" "$*" >&2; }
die()  { printf '%s[build.sh] ERROR:%s %s\n' "$C_RED" "$C_RESET" "$*" >&2; exit 1; }
