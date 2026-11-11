#!/usr/bin/env bash
# boot-simulator.sh: boot the test simulator in the background, so the boot
# overlaps the other setup steps instead of happening when the tests start.
#
# Booting the simulator inside xcodebuild took about 2 minutes of the CI Test job,
# and on a fresh runner even listing the simulators takes over a minute while
# CoreSimulator starts. So both happen in the background, in two steps:
#
#   boot-simulator.sh start  early in the job: in the background, pick the
#                            GUARDIAN_SCAN_DEVICE simulator on the newest iOS
#                            runtime, write its id to a file and boot it.
#   boot-simulator.sh use    just before the tests: wait for the id and pin the
#                            scan destination to that device through
#                            GUARDIAN_SCAN_DESTINATION (read by the Fastfile).
#
# If no such device exists, `use` changes nothing and the tests boot a simulator
# as before.
set -euo pipefail

device="${GUARDIAN_SCAN_DEVICE:?set GUARDIAN_SCAN_DEVICE to a simulator name}"
state="${RUNNER_TEMP:-/tmp}/test-simulator"

case "${1:-}" in
  start)
    rm -f "$state.id" "$state.done"
    (
      xcrun simctl list devices available -j | jq -r --arg n "$device" '
        [.devices | to_entries[] | select(.key | test("SimRuntime\\.iOS-")) | .key as $rt
         | .value[] | select(.name == $n)
         | {v: ($rt | sub(".*iOS-"; "") | split("-") | map(tonumber)), udid}]
        | sort_by(.v) | last | .udid // ""' > "$state.id"
      touch "$state.done"
      udid="$(cat "$state.id")"
      if [[ -n "$udid" ]]; then
        # Not waited on: xcodebuild waits for the boot to finish if it is still running.
        xcrun simctl boot "$udid"
      fi
    ) > "$state.log" 2>&1 &
    echo "Looking up and booting $device in the background."
    ;;
  use)
    for _ in $(seq 1 120); do
      [[ -f "$state.done" ]] && break
      sleep 1
    done
    udid="$(cat "$state.id" 2>/dev/null || true)"
    if [[ -z "$udid" ]]; then
      echo "::warning::No available '$device' simulator; the tests will boot one themselves."
      exit 0
    fi
    echo "Testing on $device ($udid), booted in the background."
    echo "GUARDIAN_SCAN_DESTINATION=platform=iOS Simulator,id=$udid" >> "${GITHUB_ENV:-/dev/null}"
    ;;
  *)
    echo "usage: boot-simulator.sh start|use" >&2
    exit 2
    ;;
esac
