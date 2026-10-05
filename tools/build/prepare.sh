# shellcheck shell=bash
#
# tools/build/prepare.sh — surface the resolved plan and export the run's env.
#
# Runs after args are resolved but before anything is built. Defines:
#     print_plan   — human-readable summary of what will run (always printed)
#     is_dry_run / print_dry_run — handle --dryRun
#     export_env   — export GUARDIAN_* vars the lanes/postbuild read
#
# iOS note: we do NOT export BUNDLE_GEMFILE here — the root Gemfile is where
# bundler looks by default (unlike Android, where the Gemfile lives in fastlane/).

print_plan() {
  log "Resolved build plan:"
  log "  platform      = ${PLATFORM}"
  log "  buildType     = ${BUILD_TYPE}  (variant: ${VARIANT})"
  log "  build         = ${DO_BUILD}"
  log "  test          = ${DO_TEST}"
  log "  lint          = ${DO_LINT}"
  log "  coverage      = ${DO_COVERAGE}"
  log "  branch        = ${BRANCH:-<current>}"
  log "  install deps  = $([[ "$SKIP_DEPS" == true ]] && echo false || echo true)"
  log "  lanes         = ${LANES[*]}"
}

is_dry_run() { [[ "$DRY_RUN" == true ]]; }

print_dry_run() {
  log "--dryRun set: not executing. The commands that WOULD run:"
  local lane
  for lane in "${LANES[@]}"; do
    # shellcheck disable=SC2086
    printf '  bundle exec fastlane %s %s\n' "$PLATFORM" "$lane"
  done
}

export_env() {
  export GUARDIAN_BUILD_TYPE="$BUILD_TYPE"
  export GUARDIAN_BRANCH="$BRANCH"
  export GUARDIAN_DO_TEST="$DO_TEST"
  export GUARDIAN_DO_COVERAGE="$DO_COVERAGE"
  export GUARDIAN_DO_LINT="$DO_LINT"
}
