#!/usr/bin/env bash
# warm-toolchain.sh: start Xcode and fastlane once in the background, early in a
# CI job, so their slow first launch on a fresh macOS runner overlaps the rest of
# the setup instead of delaying the tests.
#
# On a fresh runner the first xcodebuild call took about 90 seconds and the first
# `bundle exec fastlane` about 45, because their files are read from a cold disk.
# Later calls are fast. Neither warm-up changes anything: `xcodebuild -list` only
# reads the project, and the Ruby process only loads fastlane and exits. The job
# does not wait for them; whatever is still running when the tests start simply
# finishes first, as it would have anyway.
#
# Usage (GitHub Actions step, after setup-xcode and the Ruby dependency install):
#   .github/scripts/warm-toolchain.sh
set -euo pipefail

log="${RUNNER_TEMP:-/tmp}/warm-toolchain"

nohup xcodebuild -list -project Guardian.xcodeproj > "$log.xcode.log" 2>&1 &
nohup bundle exec ruby -e 'require "fastlane"' > "$log.fastlane.log" 2>&1 &
echo "Warming up Xcode and fastlane in the background."
