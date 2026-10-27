#!/usr/bin/env bash
# validate-release.sh: check that every part of a Guardian.swift release happened,
# and report each check as a row of a pass or fail table. Read-only: it never
# changes a release, it only reports. Exits 1 if any check fails.
#
# Usage: validate-release.sh X.Y.Z
#
# Environment:
#   REPO              owner/name (default auth0/Guardian.swift)
#   GH_TOKEN          token for gh (read access is enough)
#   COCOAPODS_TRUNK   "true" to check CocoaPods trunk and the CDN (default true)
#   WAIT_MINUTES      how long to wait for trunk and the CDN to list the version
#                     (default 0: check once)
#   CURRENT_RUN_ID    id of the Release run calling this, if any; that run counts
#                     as the newest Release run for the version
#   GITHUB_STEP_SUMMARY  where the table goes (default stdout)
#
# Needs gh, jq, curl, git, swift and carthage (the macOS runners have all but
# carthage, which the workflow installs).
set -uo pipefail

VERSION="${1:?usage: validate-release.sh X.Y.Z}"
REPO="${REPO:-auth0/Guardian.swift}"
COCOAPODS_TRUNK="${COCOAPODS_TRUNK:-true}"
WAIT_MINUTES="${WAIT_MINUTES:-0}"
CURRENT_RUN_ID="${CURRENT_RUN_ID:-}"
SUMMARY="${GITHUB_STEP_SUMMARY:-/dev/stdout}"

if [[ ! "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "::error::'$VERSION' is not X.Y.Z."
  exit 1
fi

rows=()
failed=0
# check RESULT NAME EXPECTED FOUND
check() {
  local mark="PASS"
  if [[ "$1" != "pass" ]]; then
    mark="FAIL"
    failed=$((failed + 1))
    echo "::error::$2: expected $3, found $4"
  fi
  rows+=("| $mark | $2 | $3 | $4 |")
}
# Runs a condition until it passes or WAIT_MINUTES is up. Returns its last status.
wait_for() {
  local deadline=$((SECONDS + WAIT_MINUTES * 60))
  until "$@"; do
    if (( SECONDS >= deadline )); then
      return 1
    fi
    sleep 15
  done
}
# file_at REF PATH: a file's content at a ref, or nothing.
file_at() {
  local content
  content="$(gh api "repos/$REPO/contents/$2?ref=$1" --jq .content 2>/dev/null)" || return 0
  base64 --decode <<<"$content" 2>/dev/null
}
# The X.Y.Z entry of a CHANGELOG on stdin, as release.yml extracts it.
changelog_entry() {
  tr -d '\r' | awk -v h="## [${VERSION}](" '
    index($0, h) == 1 { on = 1; next }
    on && /^## \[/    { exit }
    on                { print }
  '
}
# Text without CRs, trailing spaces or leading and trailing blank lines, to compare.
normalise() {
  python3 -c 'import sys; print("\n".join(l.rstrip() for l in sys.stdin.read().replace("\r", "").strip().split("\n")))'
}
at_least() {  # at_least FOUND WANTED: FOUND is WANTED or a later version
  [[ -n "$1" && "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -1)" == "$2" ]]
}

# ── GitHub Release ──────────────────────────────────────────────────────────────
release="$(gh api "repos/$REPO/releases?per_page=100" --jq \
  "[.[] | select(.tag_name == \"$VERSION\" or .name == \"$VERSION\")]" 2>/dev/null)" || release='[]'
published="$(jq -c '[.[] | select(.draft == false and .tag_name == $v)][0] // empty' --arg v "$VERSION" <<<"$release")"
drafts="$(jq '[.[] | select(.draft)] | length' <<<"$release")"
if [[ -n "$published" ]]; then
  check pass "GitHub Release" "published Release $VERSION" "published"
else
  check fail "GitHub Release" "published Release $VERSION" "$( [[ "$drafts" != "0" ]] && echo "only a draft" || echo "none")"
fi
if [[ "$drafts" == "0" ]]; then
  check pass "No leftover draft" "no draft Release for $VERSION" "none"
else
  check fail "No leftover draft" "no draft Release for $VERSION" "$drafts draft(s)"
fi

highest="$(git ls-remote --tags --refs "https://github.com/$REPO.git" 2>/dev/null \
  | sed -nE 's|.*refs/tags/([0-9]+\.[0-9]+\.[0-9]+)$|\1|p' | sort -V | tail -1)"
latest="$(gh api "repos/$REPO/releases/latest" --jq .tag_name 2>/dev/null)" || latest=""
if [[ "$highest" != "$VERSION" ]]; then
  check pass "Marked Latest" "Latest only if $VERSION is the highest version" "not the highest ($highest), Latest is $latest"
elif [[ "$latest" == "$VERSION" ]]; then
  check pass "Marked Latest" "Latest is $VERSION" "$latest"
else
  check fail "Marked Latest" "Latest is $VERSION" "${latest:-none}"
fi

if [[ -n "$published" ]]; then
  body="$(jq -r .body <<<"$published" | normalise)"
  entry="$(file_at "$VERSION" CHANGELOG.md | changelog_entry | normalise)"
  if [[ -z "$entry" ]]; then
    check fail "Release notes" "the CHANGELOG.md entry for $VERSION at the tag" "no entry at the tag"
  elif [[ "$body" == "$entry" ]]; then
    check pass "Release notes" "the CHANGELOG.md entry for $VERSION at the tag" "identical"
  else
    check fail "Release notes" "the CHANGELOG.md entry for $VERSION at the tag" "a different body"
  fi
fi

# ── Tag and commit ──────────────────────────────────────────────────────────────
# The commit the tag points at: the peeled entry for an annotated tag, else the tag.
tag_sha="$(git ls-remote --tags "https://github.com/$REPO.git" "refs/tags/$VERSION" "refs/tags/$VERSION^{}" 2>/dev/null \
  | sort -k2 | tail -1 | cut -f1)"
merge_sha="$(gh pr list --repo "$REPO" --head "release/$VERSION" --base master --state merged \
  --json mergeCommit,mergedAt --jq 'sort_by(.mergedAt) | last | .mergeCommit.oid // ""' 2>/dev/null)" || merge_sha=""
if [[ -z "$tag_sha" ]]; then
  check fail "Tag" "tag $VERSION on the release PR's merge commit" "no tag"
elif [[ -z "$merge_sha" ]]; then
  check fail "Tag" "tag $VERSION on the release PR's merge commit" "no merged release/$VERSION PR"
elif [[ "$tag_sha" == "$merge_sha" ]]; then
  check pass "Tag" "tag $VERSION on the release PR's merge commit" "${tag_sha:0:7}"
else
  check fail "Tag" "tag $VERSION on the release PR's merge commit ${merge_sha:0:7}" "${tag_sha:0:7}"
fi
if [[ -n "$tag_sha" ]]; then
  status="$(gh api "repos/$REPO/compare/$tag_sha...master" --jq .status 2>/dev/null)" || status=""
  if [[ "$status" == "ahead" || "$status" == "identical" ]]; then
    check pass "On master" "the tagged commit is in master's history" "yes ($status)"
  else
    check fail "On master" "the tagged commit is in master's history" "${status:-unknown}"
  fi
  verified="$(gh api "repos/$REPO/commits/$tag_sha" --jq .commit.verification.verified 2>/dev/null)" || verified=""
  if [[ "$verified" == "true" ]]; then
    check pass "Verified" "the tagged commit is Verified" "Verified"
  else
    check fail "Verified" "the tagged commit is Verified" "${verified:-unknown}"
  fi
fi

# ── master's version files and README ─────────────────────────────────────────
master_version="$(file_at master .version | tr -d '[:space:]')"
bad=""
at_least "$master_version" "$VERSION" || bad=".version is ${master_version:-missing}"
for plist in Guardian/Info.plist GuardianTests/Info.plist GuardianTestHost/Info.plist GuardianApp/GuardianApp/Info.plist; do
  v="$(file_at master "$plist" | grep -A1 "<key>CFBundleShortVersionString</key>" | sed -nE 's|.*<string>([^<]*)</string>.*|\1|p')"
  at_least "$v" "$VERSION" || bad="${bad:+$bad, }$plist is ${v:-missing}"
done
readme="$(file_at master README.md)"
pod_v="$(sed -nE "s/.*pod 'Guardian', '~> ([0-9]+\.[0-9]+\.[0-9]+)'.*/\1/p" <<<"$readme" | head -1)"
carthage_v="$(sed -nE 's/.*github "auth0\/Guardian\.swift" ~> ([0-9]+\.[0-9]+\.[0-9]+).*/\1/p' <<<"$readme" | head -1)"
at_least "$pod_v" "$VERSION" || bad="${bad:+$bad, }README pod line is ${pod_v:-missing}"
at_least "$carthage_v" "$VERSION" || bad="${bad:+$bad, }README Carthage line is ${carthage_v:-missing}"
if [[ -z "$bad" ]]; then
  check pass "master versions" "$VERSION or later in .version, the Info.plists and the README" "$master_version"
else
  check fail "master versions" "$VERSION or later in .version, the Info.plists and the README" "$bad"
fi

# ── Release workflow run ──────────────────────────────────────────────────────
# The version a Release run released: from a manual run's title, or the release PR
# its pushed commit belongs to.
run_version() {  # event head_sha title
  if [[ "$1" == "workflow_dispatch" ]]; then
    sed -nE 's/^Release ([0-9]+\.[0-9]+\.[0-9]+) \(manual\)$/\1/p' <<<"$3"
  else
    gh api "repos/$REPO/commits/$2/pulls" \
      --jq '[.[] | select(.merged_at != null and (.head.ref | startswith("release/")))][0].head.ref // "" | ltrimstr("release/")' 2>/dev/null
  fi
}
newest=""
while IFS=$'\t' read -r id event head_sha title conclusion; do
  [[ -z "$id" ]] && continue
  if [[ "$(run_version "$event" "$head_sha" "$title")" == "$VERSION" ]]; then
    newest="$id"$'\t'"$conclusion"
    break
  fi
done < <(gh api "repos/$REPO/actions/workflows/release.yml/runs?per_page=50" \
  --jq '.workflow_runs[] | [.id, .event, .head_sha, .display_title, (.conclusion // "running")] | @tsv' 2>/dev/null)
IFS=$'\t' read -r run_id run_conclusion <<<"$newest"
if [[ -z "${run_id:-}" ]]; then
  check fail "Release run" "the newest Release run for $VERSION succeeded" "no Release run found"
elif [[ "$run_id" == "$CURRENT_RUN_ID" ]]; then
  check pass "Release run" "the newest Release run for $VERSION succeeded" "this run ($run_id), publish succeeded"
elif [[ "$run_conclusion" == "success" ]]; then
  check pass "Release run" "the newest Release run for $VERSION succeeded" "run $run_id: success"
else
  check fail "Release run" "the newest Release run for $VERSION succeeded" "run $run_id: $run_conclusion"
fi

# ── CocoaPods trunk and CDN ───────────────────────────────────────────────────
if [[ "$COCOAPODS_TRUNK" == "true" ]]; then
  on_trunk() {
    curl -sf https://trunk.cocoapods.org/api/v1/pods/Guardian \
      | jq -e --arg v "$VERSION" 'any(.versions[]; .name == $v)' >/dev/null
  }
  if wait_for on_trunk; then
    check pass "CocoaPods trunk" "trunk lists $VERSION" "listed"
    tag="$(curl -sfL "https://trunk.cocoapods.org/api/v1/pods/Guardian/specs/$VERSION" | jq -r '.source.tag // ""')"
    if [[ "$tag" == "$VERSION" ]]; then
      check pass "Podspec source" "the trunk podspec's source is tag $VERSION" "tag $tag"
    else
      check fail "Podspec source" "the trunk podspec's source is tag $VERSION" "${tag:-unreadable}"
    fi
  else
    check fail "CocoaPods trunk" "trunk lists $VERSION" "not listed after $WAIT_MINUTES min"
  fi
  # CocoaPods clients read the version index for the pod's shard, then the podspec.
  h="$(printf 'Guardian' | { md5sum 2>/dev/null || md5 -q; } | cut -c1-3)"
  shard="${h:0:1}/${h:1:1}/${h:2:1}"
  on_cdn() {
    curl -sf "https://cdn.cocoapods.org/all_pods_versions_${shard//\//_}.txt" \
      | grep '^Guardian/' | tr '/' '\n' | grep -qxF "$VERSION" &&
    [[ "$(curl -sfL "https://cdn.cocoapods.org/Specs/$shard/Guardian/$VERSION/Guardian.podspec.json" | jq -r '.source.tag // ""')" == "$VERSION" ]]
  }
  if wait_for on_cdn; then
    check pass "CocoaPods CDN" "the CDN lists $VERSION and serves its podspec" "served"
  else
    check fail "CocoaPods CDN" "the CDN lists $VERSION and serves its podspec" "not served after $WAIT_MINUTES min"
  fi
fi

# ── Swift Package Manager and Carthage, as a consumer would ─────────────────────
scratch="$(mktemp -d)"
mkdir -p "$scratch/spm/Sources/Check" && touch "$scratch/spm/Sources/Check/Check.swift"
cat > "$scratch/spm/Package.swift" <<EOF
// swift-tools-version:5.10
import PackageDescription
let package = Package(
    name: "Check",
    platforms: [.iOS(.v12)],
    dependencies: [.package(url: "https://github.com/${REPO}.git", exact: "${VERSION}")],
    targets: [.target(name: "Check", dependencies: [.product(name: "Guardian", package: "Guardian.swift")])]
)
EOF
if (cd "$scratch/spm" && swift package resolve >"$scratch/spm.log" 2>&1); then
  pin="$(jq -r '.pins[] | select(.identity == "guardian.swift") | "\(.state.version)\t\(.state.revision)"' "$scratch/spm/Package.resolved")"
  IFS=$'\t' read -r spm_version spm_revision <<<"$pin"
  if [[ "$spm_version" == "$VERSION" && "$spm_revision" == "$tag_sha" ]]; then
    check pass "Swift Package Manager" "resolves exactly $VERSION at the tag" "$spm_version at ${spm_revision:0:7}"
  else
    check fail "Swift Package Manager" "resolves exactly $VERSION at ${tag_sha:0:7}" "${spm_version:-?} at ${spm_revision:0:7}"
  fi
else
  check fail "Swift Package Manager" "resolves exactly $VERSION" "resolve failed: $(tail -1 "$scratch/spm.log")"
fi

mkdir -p "$scratch/carthage"
echo "github \"$REPO\" == $VERSION" > "$scratch/carthage/Cartfile"
if (cd "$scratch/carthage" && carthage update --no-build >"$scratch/carthage.log" 2>&1); then
  resolved="$(sed -nE "s|^github \"$REPO\" \"([^\"]+)\"$|\1|p" "$scratch/carthage/Cartfile.resolved")"
  if [[ "$resolved" == "$VERSION" ]]; then
    check pass "Carthage" "resolves $VERSION from the tag" "$resolved"
  else
    check fail "Carthage" "resolves $VERSION from the tag" "${resolved:-nothing}"
  fi
else
  check fail "Carthage" "resolves $VERSION from the tag" "carthage failed: $(tail -1 "$scratch/carthage.log")"
fi
rm -rf "$scratch"

# ── Report ──────────────────────────────────────────────────────────────────────
{
  if (( failed == 0 )); then
    echo "### Guardian.swift $VERSION: all release checks passed"
  else
    echo "### Guardian.swift $VERSION: $failed release check(s) failed"
  fi
  echo
  echo "| | Check | Expected | Found |"
  echo "|---|---|---|---|"
  printf '%s\n' "${rows[@]}"
  if [[ "$COCOAPODS_TRUNK" != "true" ]]; then
    echo
    echo "CocoaPods trunk and CDN checks are off (COCOAPODS_TRUNK_PUBLISH is false)."
  fi
} >> "$SUMMARY"

(( failed == 0 ))
