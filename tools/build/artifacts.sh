# shellcheck shell=bash
#
# tools/build/artifacts.sh — collect / report build outputs.
#
# The Guardian Swift SDK is a framework library. When the `build` lane runs,
# xcodebuild writes the framework to DerivedData. This module reports where
# outputs landed after a successful run.
#
# Defines report_artifacts(), called by build.sh after a successful run.

# Tell the user where the outputs are, if any were produced.
report_artifacts() {
  local found=false

  # Check for the reports dashboard (always report it when present)
  if [[ -f "$REPO_ROOT/output/reports.html" ]]; then
    log "  - output/reports.html (test/coverage/lint dashboard)"
    found=true
  fi

  # Check for slather coverage XML
  if [[ -f "$REPO_ROOT/output/cobertura.xml" ]]; then
    log "  - output/cobertura.xml (Codecov coverage report)"
    found=true
  fi

  # Check for scan JUnit results
  if [[ -d "$REPO_ROOT/output/scan" ]]; then
    log "  - output/scan/ (xcodebuild test results)"
    found=true
  fi

  # Producing no build artifact is a legitimate outcome for a lint/test-only run.
  if [[ "$found" == true ]]; then
    log "Build outputs are under output/."
  fi
}
