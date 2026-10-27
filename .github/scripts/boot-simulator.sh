#!/usr/bin/env bash
# boot-simulator.sh: start booting the test simulator in the background, so the
# boot overlaps the Carthage bootstrap instead of happening when the tests start.
#
# Booting the simulator inside xcodebuild took about 2 minutes of the CI Test job.
# This picks the GUARDIAN_SCAN_DEVICE simulator on the newest iOS runtime, starts
# its boot without waiting for it, and pins the scan destination to that exact
# device through GUARDIAN_SCAN_DESTINATION (read by the Fastfile), so the tests
# run on the simulator that is already booting. If no such device exists, it
# changes nothing and the tests boot a simulator as before.
#
# Usage (GitHub Actions step): GUARDIAN_SCAN_DEVICE="iPhone 16" .github/scripts/boot-simulator.sh
set -euo pipefail

device="${GUARDIAN_SCAN_DEVICE:?set GUARDIAN_SCAN_DEVICE to a simulator name}"

udid="$(xcrun simctl list devices available -j | jq -r --arg n "$device" '
  [.devices | to_entries[] | select(.key | test("SimRuntime\\.iOS-")) | .key as $rt
   | .value[] | select(.name == $n)
   | {v: ($rt | sub(".*iOS-"; "") | split("-") | map(tonumber)), udid}]
  | sort_by(.v) | last | .udid // ""')"

if [[ -z "$udid" ]]; then
  echo "::warning::No available '$device' simulator; the tests will boot one themselves."
  exit 0
fi

# Not waited on: xcodebuild waits for the boot to finish if it is still running.
nohup xcrun simctl boot "$udid" > /tmp/simulator-boot.log 2>&1 &
echo "Booting $device ($udid) in the background."
echo "GUARDIAN_SCAN_DESTINATION=platform=iOS Simulator,id=$udid" >> "${GITHUB_ENV:-/dev/null}"
