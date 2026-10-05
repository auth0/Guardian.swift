#!/usr/bin/env bash
#
# build.sh — the single, stable entrypoint for building/testing the Guardian
#            Swift SDK, usable IDENTICALLY on a developer laptop and in CI.
#
# ─────────────────────────────────────────────────────────────────────────────
# WHAT THIS IS (and just as importantly, what it is NOT)
# ─────────────────────────────────────────────────────────────────────────────
# This script is a *dispatcher*, not a build system. Its ONLY job is:
#     parse flags  ->  validate them  ->  map them to a Fastlane lane + env  ->  exec it
# No xcodebuild logic lives here. All real build logic lives one layer down, in
# fastlane/Fastfile. That keeps this file tiny, readable, and stable.
#
# It is intentionally the SAME contract (same flags, same defaults, same skeleton)
# as Guardian.Android/build.sh, trimmed to what an iOS LIBRARY needs. The Android
# SDK builds and tests a Java/Kotlin library with Gradle; this iOS SDK builds and
# tests a Swift framework with xcodebuild/scan/slather. The lane names are the same
# so the dispatcher logic (args.sh) is shared verbatim.
#
#     Layer 3  GHA / CI              ── calls ─▶  ./build.sh <flags>
#     Layer 2  build.sh (here)       ── calls ─▶  bundle exec fastlane ios <lane>
#     Layer 1  Fastlane lanes        ── call  ─▶  scan / slather / swiftlint / xcodebuild
#
# This file is deliberately THIN: it just sources the phase modules under
# tools/build/ and runs them in order. The real logic lives in those modules:
#     tools/build/common.sh        colors + log/die helpers
#     tools/build/usage.sh         --help / --help-full / bad-input handling
#     tools/build/args.sh          defaults, flag parsing, plan resolution
#     tools/build/menu.sh          the zero-arg interactive menu (TTY only)
#     tools/build/dependencies.sh  bundle install + carthage bootstrap + swiftlint
#     tools/build/prepare.sh       plan display, --dryRun, env export
#     tools/build/prebuild.sh      hook before the lanes run        (placeholder)
#     tools/build/test.sh          test-orchestration hook          (placeholder)
#     tools/build/postbuild.sh     hook after the lanes run (reports dashboard)
#     tools/build/artifacts.sh     report/collect build outputs (the framework)
#
# ─────────────────────────────────────────────────────────────────────────────
# USAGE
# ─────────────────────────────────────────────────────────────────────────────
#   ./build.sh --buildType debug|release \
#              [--build | --nobuild]          # build the framework (default: --build)
#              [--test | --notest]            # run unit tests (default: --test)
#              [--lint | --nolint]            # run SwiftLint (default: --lint)
#              [--coverage | --nocoverage]    # emit Slather coverage (default: --nocoverage)
#              [--branch <name>]              # informational label for logs/artifacts
#              [--skip-deps]                  # don't run dependency install (default: install)
#              [--dryRun]                     # print the resolved plan, run nothing
#
# DEPENDENCIES
#   By default the script makes the Ruby/Fastlane toolchain ready before building:
#   it installs bundler if missing, then runs 'bundle install'. Carthage is
#   bootstrapped for the test dependency graph (Quick/Nimble/SimpleKeychain).
#   SwiftLint is installed via Homebrew if missing. Xcode (see .xcode-version) must
#   already be on PATH via xcode-select — provided by CI or your local setup.
#   Pass --skip-deps to bypass all of the above (e.g. in CI after cached installs).
#
# EXAMPLES
#   ./build.sh                                           # PR-style: lint + test + coverage
#   ./build.sh --buildType debug --lint --coverage --test --nobuild  # what pr.yml runs
#   ./build.sh --buildType release --notest --nolint --nocoverage    # just the framework
#   ./build.sh --buildType release --dryRun              # show what would run
#
set -euo pipefail

# ─── Locate ourselves + the module dir (works regardless of caller's cwd) ─────
ENTRYPOINT="${BASH_SOURCE[0]}"
REPO_ROOT="$(cd "$(dirname "$ENTRYPOINT")" && pwd)"
MODULES_DIR="$REPO_ROOT/tools/build"
# fastlane / xcodebuild resolve relative paths from the repo root.
cd "$REPO_ROOT"

# ─── Constants specific to this repo ─────────────────────────────────────────
readonly PLATFORM="ios"

# Remember whether the user passed ANY arguments, before we parse them.
ORIG_ARGC=$#

# ─── Load the phase modules (order matters: common -> usage -> the rest) ──────
# shellcheck source=tools/build/common.sh
source "$MODULES_DIR/common.sh"
# shellcheck source=tools/build/usage.sh
source "$MODULES_DIR/usage.sh"
# shellcheck source=tools/build/args.sh
source "$MODULES_DIR/args.sh"
# shellcheck source=tools/build/menu.sh
source "$MODULES_DIR/menu.sh"
# shellcheck source=tools/build/dependencies.sh
source "$MODULES_DIR/dependencies.sh"
# shellcheck source=tools/build/prepare.sh
source "$MODULES_DIR/prepare.sh"
# shellcheck source=tools/build/prebuild.sh
source "$MODULES_DIR/prebuild.sh"
# shellcheck source=tools/build/test.sh
source "$MODULES_DIR/test.sh"
# shellcheck source=tools/build/postbuild.sh
source "$MODULES_DIR/postbuild.sh"
# shellcheck source=tools/build/artifacts.sh
source "$MODULES_DIR/artifacts.sh"

# ─── Run one lane through Fastlane ────────────────────────────────────────────
run_lane() {
  local lane="$1"
  log "▶ bundle exec fastlane ${PLATFORM} ${lane}"
  # shellcheck disable=SC2086  # intentional: split "lane arg:val arg2:val2" into words
  bundle exec fastlane "$PLATFORM" $lane
}

# ─── Orchestrate the phases ───────────────────────────────────────────────────
main() {
  parse_args "$@"        # defaults + interactive menu + flag parsing
  resolve_plan           # validate + derive VARIANT, LANES[]
  save_last_run          # remember this plan for the menu's "repeat last" (TTY only)

  print_plan             # always show what will run

  if is_dry_run; then
    print_dry_run
    exit 0
  fi

  export_env             # GUARDIAN_* env for the lanes
  ensure_dependencies    # bundle install + carthage bootstrap + swiftlint (honors --skip-deps)
  run_prebuild           # placeholder hook

  local lane
  for lane in "${LANES[@]}"; do
    run_lane "$lane"
  done

  run_test_hooks         # placeholder hook
  run_postbuild          # reports dashboard hook
  report_artifacts       # tell the user where outputs landed

  log "✅ Done: ${LANES[*]}"
}

main "$@"
