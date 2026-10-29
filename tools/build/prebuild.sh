# shellcheck shell=bash
#
# tools/build/prebuild.sh — hook that runs just BEFORE the lanes execute.
#
# PLACEHOLDER: intentionally a no-op today. Wired into build.sh's flow so future
# pre-build steps have an obvious, single home.
#
# Candidate future uses (iOS SDK):
#   - decode a signing certificate from a base64 secret
#   - stamp the version from CI metadata
#   - warm the DerivedData cache
#
# Contract: runs after dependencies are ready and env is exported, before the
# first lane. Has access to all resolved plan globals. `die` on failure.
run_prebuild() {
  : # no-op for now
}
