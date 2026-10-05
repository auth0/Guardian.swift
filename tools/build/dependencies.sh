# shellcheck shell=bash
#
# tools/build/dependencies.sh — make the toolchain ready before building.
#
# Defines ensure_dependencies(), called by build.sh before the lanes run.
# This is what makes "clone then ./build.sh" work on a fresh machine or CI runner.
# Honors SKIP_DEPS (set by --skip-deps).
#
# iOS specifics:
#   1. bundle install  — Fastlane + Slather + auth0_shipper (root Gemfile)
#   2. carthage bootstrap — pulls Quick/Nimble/SimpleKeychain test deps
#   3. swiftlint       — installed via Homebrew if missing (lint lane requires it)
#
# Xcode itself is NOT installed here — xcode-select / maxim-lobanov/setup-xcode
# (in CI) or your local Xcode provides it. We only verify xcodebuild is present.

ensure_dependencies() {
  if [[ "$SKIP_DEPS" == true ]]; then
    log "--skip-deps set: not installing dependencies. Assuming the toolchain is ready."
    command -v bundle    >/dev/null 2>&1 || die "bundler not found and --skip-deps was passed."
    command -v xcodebuild >/dev/null 2>&1 || die "xcodebuild not found and --skip-deps was passed."
    return 0
  fi

  command -v xcodebuild >/dev/null 2>&1 || die "xcodebuild not found. Install Xcode and run 'sudo xcode-select -s /Applications/Xcode.app'."
  command -v ruby       >/dev/null 2>&1 || die "Ruby not found. Install Ruby (see .ruby-version) then re-run."

  # bundler may be absent on a truly fresh machine.
  if ! command -v bundle >/dev/null 2>&1; then
    log "bundler not found — installing it (gem install bundler)…"
    gem install bundler || die "Failed to install bundler. Check your Ruby/gem setup."
  fi

  # Install Ruby gems (Fastlane, Slather, auth0_shipper, etc.)
  if bundle check >/dev/null 2>&1; then
    log "Ruby dependencies already satisfied — skipping 'bundle install'."
  else
    log "Installing Ruby dependencies (bundle install)…"
    bundle install || die "'bundle install' failed. Fix the errors above and re-run."
  fi

  # Bootstrap Carthage test dependencies (Quick/Nimble/SimpleKeychain).
  # Skipped if Carthage/Build is already populated (cache hit in CI).
  if [[ -d "$REPO_ROOT/Carthage/Build" ]] && [[ -n "$(ls -A "$REPO_ROOT/Carthage/Build" 2>/dev/null)" ]]; then
    log "Carthage/Build already populated — skipping bootstrap."
  else
    command -v carthage >/dev/null 2>&1 || {
      log "Carthage not found — installing via Homebrew…"
      brew install carthage || die "Failed to install Carthage. Install it manually and re-run."
    }
    log "Bootstrapping Carthage dependencies…"
    # XCODE_XCCONFIG_FILE overrides the deployment target for all Carthage deps.
    # Required on Xcode 27+ which enforces a 15.0 floor — Quick/Nimble 12.x still
    # declare iOS 13.0 in their project files. The override is intentionally scoped
    # to this bootstrap call only and doesn't affect the Guardian framework itself.
    # Must be an absolute path — Carthage runs xcodebuild from Checkouts/<dep>/,
    # so a relative path would resolve against that directory, not the repo root.
    XCODE_XCCONFIG_FILE="$REPO_ROOT/carthage_build.xcconfig" \
      carthage bootstrap --use-xcframeworks --cache-builds --platform iOS || die "carthage bootstrap failed."
  fi

  # SwiftLint — required by the lint lane.
  if ! command -v swiftlint >/dev/null 2>&1; then
    log "SwiftLint not found — installing via Homebrew…"
    brew install swiftlint || die "Failed to install SwiftLint. Install it manually and re-run."
  else
    log "SwiftLint already installed ($(swiftlint version))."
  fi
}
