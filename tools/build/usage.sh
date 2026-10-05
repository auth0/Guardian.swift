# shellcheck shell=bash
#
# tools/build/usage.sh — help text + bad-input handling.
#
# Defines usage() (concise colorized help), usage_full() (the full narrative), and
# die_usage() (error + concise usage). Sourced by build.sh after common.sh.
#
# NOTE: usage_full() prints the header comment block of build.sh itself (the file
# named by $ENTRYPOINT), so the detailed docs and the code never drift apart.

# Concise, colorized help: usage line + flags + examples.
usage() {
  cat >&2 <<EOF
${C_BOLD}build.sh${C_RESET} — one command to build/test the Guardian Swift SDK, locally and in CI.

${C_BOLD}USAGE${C_RESET}
  ${C_CYAN}./build.sh${C_RESET} [options]        ${C_DIM}# no args on a terminal = interactive menu${C_RESET}
                              ${C_DIM}# no args in CI       = debug build + lint + test${C_RESET}

${C_BOLD}OPTIONS${C_RESET} ${C_DIM}(defaults in brackets)${C_RESET}
  ${C_GREEN}--buildType${C_RESET} debug|release               ${C_DIM}[debug]${C_RESET}
  ${C_GREEN}--build${C_RESET} | ${C_GREEN}--nobuild${C_RESET}                     build the framework ${C_DIM}[--build]${C_RESET}
  ${C_GREEN}--test${C_RESET} | ${C_GREEN}--notest${C_RESET}                       run unit tests ${C_DIM}[--test]${C_RESET}
  ${C_GREEN}--lint${C_RESET} | ${C_GREEN}--nolint${C_RESET}                       run SwiftLint ${C_DIM}[--lint]${C_RESET}
  ${C_GREEN}--coverage${C_RESET} | ${C_GREEN}--nocoverage${C_RESET}               emit Slather coverage report ${C_DIM}[--nocoverage]${C_RESET}
  ${C_GREEN}--branch${C_RESET} <name>                        label for logs/artifacts
  ${C_GREEN}--skip-deps${C_RESET}                            skip dependency install ${C_DIM}[install]${C_RESET}
  ${C_GREEN}--dryRun${C_RESET}                               print the plan, run nothing
  ${C_GREEN}-h${C_RESET}, ${C_GREEN}--help${C_RESET}                             this help
  ${C_GREEN}--help-full${C_RESET}                            full docs: architecture, deps

${C_BOLD}EXAMPLES${C_RESET}
  ${C_CYAN}./build.sh${C_RESET}                                        ${C_DIM}# PR-style: lint + test + coverage${C_RESET}
  ${C_CYAN}./build.sh${C_RESET} --buildType debug --lint --coverage --test --nobuild  ${C_DIM}# what pr.yml runs${C_RESET}
  ${C_CYAN}./build.sh${C_RESET} --buildType release --notest --nolint --nocoverage    ${C_DIM}# just the framework${C_RESET}
  ${C_CYAN}./build.sh${C_RESET} --buildType release --dryRun           ${C_DIM}# show what would run${C_RESET}

${C_DIM}Run '${C_RESET}${C_CYAN}./build.sh --help-full${C_RESET}${C_DIM}' for the architecture and dependency behavior.${C_RESET}
EOF
  exit "${1:-0}"
}

# Full docs: print the header comment block of build.sh (everything from the title
# line down to just before 'set -euo pipefail'), so the narrative and code never drift.
usage_full() {
  local end
  end="$(( $(grep -n '^set -euo pipefail' "$ENTRYPOINT" | head -1 | cut -d: -f1) - 1 ))"
  sed -n "3,${end}p" "$ENTRYPOINT" | sed 's/^# \{0,1\}//' >&2
  exit "${1:-0}"
}

# Bad-input death: show WHAT was wrong, then the CONCISE usage, then exit non-zero.
die_usage() {
  printf '%s[build.sh] ERROR:%s %s\n\n' "$C_RED" "$C_RESET" "$*" >&2
  usage 1
}
