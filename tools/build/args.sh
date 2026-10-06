# shellcheck shell=bash
#
# tools/build/args.sh — defaults, flag parsing, and plan resolution.
#
# Turns the command line (or the interactive menu) into a fully-resolved plan:
# a validated set of variables plus the ordered LANES[] array that execution
# runs. Defines two entry functions build.sh calls in order:
#     parse_args "$@"   — set defaults, run the menu (if applicable), parse flags
#     resolve_plan      — validate + map flags to VARIANT and the LANES[] array
#
# iOS vs Android: flags and lane names are identical; the Gradle buildType mapping
# is replaced by a simpler xcodebuild configuration mapping (debug/release).
# DO_LINT defaults to true (SwiftLint, ON by default — first-class gate like
# Android Lint). DO_COVERAGE defaults to false (must opt-in, same as Android).

# ─── Defaults ────────────────────────────────────────────────────────────────
init_defaults() {
  BUILD_TYPE="debug"
  DO_BUILD=true
  DO_TEST=true
  DO_LINT=true            # SwiftLint is a first-class gate — on by default
  DO_COVERAGE=false
  BRANCH=""
  SKIP_DEPS=false
  DRY_RUN=false
}

# ─── Argument parsing ─────────────────────────────────────────────────────────
need_value() { [[ -n "${2:-}" && "${2:0:1}" != "-" ]] || die_usage "$1 requires a value."; }

parse_args() {
  init_defaults

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --buildType)      need_value "$1" "${2:-}"; BUILD_TYPE="$2";     shift 2 ;;
      --build)          DO_BUILD=true;     shift ;;
      --nobuild)        DO_BUILD=false;    shift ;;
      --test)           DO_TEST=true;      shift ;;
      --notest)         DO_TEST=false;     shift ;;
      --lint)           DO_LINT=true;      shift ;;
      --nolint)         DO_LINT=false;     shift ;;
      --coverage)       DO_COVERAGE=true;  shift ;;
      --nocoverage)     DO_COVERAGE=false; shift ;;
      --branch)         need_value "$1" "${2:-}"; BRANCH="$2";         shift 2 ;;
      --skip-deps)      SKIP_DEPS=true;    shift ;;
      --dryRun)         DRY_RUN=true;      shift ;;
      -h|--help)        usage 0 ;;
      --help-full)      usage_full 0 ;;
      *)                die_usage "Unknown argument: $1" ;;
    esac
  done

  # No args on a terminal? Offer the numbered menu (sets flags above). No-op in CI.
  maybe_interactive
}

# ─── Resolve the plan ─────────────────────────────────────────────────────────
resolve_plan() {
  # Validate buildType.
  case "$BUILD_TYPE" in
    debug|release) ;;
    *) die_usage "--buildType must be one of: debug | release (got '$BUILD_TYPE')" ;;
  esac

  # Map buildType -> xcodebuild configuration (display only; the Fastfile lane
  # handles the actual xcodebuild -configuration flag).
  VARIANT="${BUILD_TYPE}"   # debug or release

  # Build the ordered LANES[] array.
  LANES=()

  # Lint runs first (fast feedback; gate on error-severity SwiftLint violations).
  [[ "$DO_LINT" == true ]] && LANES+=("lint")

  # Test + coverage. Coverage lane runs the tests AND emits slather output, so we
  # don't run both test and coverage — coverage subsumes test.
  if [[ "$DO_TEST" == true && "$DO_COVERAGE" == true ]]; then
    LANES+=("coverage")
  elif [[ "$DO_TEST" == true ]]; then
    LANES+=("test")
  elif [[ "$DO_COVERAGE" == true ]]; then
    LANES+=("coverage")
  fi

  # Build (framework) — informational, off for PR gate.
  [[ "$DO_BUILD" == true ]] && LANES+=("build")

  # Guard against a fully empty plan.
  if [[ ${#LANES[@]} -eq 0 ]]; then
    die_usage "Nothing to do: no build, test, lint, or coverage was requested."
  fi
}
