# shellcheck shell=bash
#
# tools/build/postbuild.sh — hook that runs just AFTER the lanes execute (success).
#
# Generates the unified reports.html dashboard from whatever test/lint/coverage
# reports the run produced, then leaves everything else for artifacts.sh.
#
# Candidate future uses (iOS SDK):
#   - upload the dashboard to a durable store
#   - post a build summary (Slack, PR comment)
#
# Contract: runs after ALL lanes complete successfully. Has access to plan globals.

run_postbuild() {
  generate_reports_dashboard
}

generate_reports_dashboard() {
  local has_reports=false

  # scan JUnit output
  [[ -d "$REPO_ROOT/output/scan" ]] && has_reports=true

  # slather cobertura output
  [[ -f "$REPO_ROOT/output/cobertura.xml" ]] && has_reports=true

  # swiftlint checkstyle output
  [[ -f "$REPO_ROOT/output/swiftlint-checkstyle.xml" ]] && has_reports=true

  if [[ "$has_reports" != "true" ]]; then
    log "No test/lint/coverage reports found — skipping dashboard generation."
    return 0
  fi

  log "Generating unified test dashboard..."
  local script="$MODULES_DIR/reports.sh"
  if [[ ! -x "$script" ]]; then
    warn "Dashboard script not found or not executable: $script"
    warn "Run: chmod +x $script"
    return 0
  fi

  # Run reports.sh and propagate its exit code. reports.sh generates the HTML
  # dashboard and GHA summary first (so the artifact is always complete), then
  # runs the quality gate and exits non-zero if any threshold is breached.
  local rc=0
  "$script" 2>&1 || rc=$?

  if [[ -f "$REPO_ROOT/output/reports.html" ]]; then
    log "✅ Test dashboard generated: output/reports.html"
  else
    warn "Dashboard script ran but output/reports.html not found."
  fi

  return $rc
}
