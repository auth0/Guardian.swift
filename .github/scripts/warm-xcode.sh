#!/usr/bin/env bash
# warm-xcode.sh: start Xcode once in the background, early in a CI job, so its
# slow first launch on a fresh macOS runner overlaps the simulator boot instead of
# delaying fastlane, which calls xcodebuild as it starts.
#
# On a fresh runner the first xcodebuild call took 1.5 to 2 minutes; later calls
# are fast. `xcodebuild -list` only reads the project. The job does not wait for
# it: if it is still running when fastlane starts, fastlane's own call finishes
# with it, as it would have anyway.
#
# Usage (GitHub Actions step, after setup-xcode):
#   .github/scripts/warm-xcode.sh
set -euo pipefail

log="${RUNNER_TEMP:-/tmp}/warm-xcode"

nohup xcodebuild -list -project Guardian.xcodeproj > "$log.xcode.log" 2>&1 &
echo "Warming up Xcode in the background."
