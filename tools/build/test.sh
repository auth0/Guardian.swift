# shellcheck shell=bash
#
# tools/build/test.sh — hook for test-related orchestration.
#
# PLACEHOLDER: intentionally a no-op today. Unit testing runs as a Fastlane
# lane ("test"/"coverage") selected in args.sh and executed by the lane loop —
# so there's nothing for this module to do yet.
#
# Candidate future uses (iOS SDK):
#   - gate on a coverage threshold once one is agreed
#   - run UI/integration tests on a simulator separately from unit tests
#
# Contract: has access to the resolved plan globals. `die` on failure.
run_test_hooks() {
  : # no-op for now — unit tests run via the Fastlane test/coverage lanes
}
