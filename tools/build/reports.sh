#!/usr/bin/env bash
# reports.sh — parse test/coverage/lint reports and generate a single
# self-contained reports.html with all data embedded.
#
# Called by tools/build/postbuild.sh after tests/coverage/lint complete.
# Data sources (iOS):
#   Tests    — scan JUnit XML at output/scan/*.junit or output/scan/report.junit
#   Coverage — slather cobertura XML at output/cobertura.xml
#   Lint     — SwiftLint checkstyle XML at output/swiftlint-checkstyle.xml
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

OUTPUT_DIR="$REPO_ROOT/output"
OUTPUT_HTML="$OUTPUT_DIR/reports.html"

# ─── Data storage ─────────────────────────────────────────────────────────────
TESTS_PASSED=0
TESTS_FAILED=0
FAILED_TESTS=""
PASSED_TESTS=""
COVERAGE_PERCENT=0
COVERAGE_DETAILS=""
LINT_WARNINGS=0
LINT_ERRORS=0
LINT_DETAILS=""

ensure_number() {
  local val="$1"
  [[ "$val" =~ ^[0-9]+$ ]] && echo "$val" || echo "0"
}

# ─── Parse test results from scan JUnit XML ───────────────────────────────────
parse_test_results() {
  # scan writes JUnit XML to output/scan/. Look for .junit or .xml files.
  local xml_dir="$OUTPUT_DIR/scan"
  if [[ ! -d "$xml_dir" ]]; then
    echo "  No test results directory found at $xml_dir" >&2
    return 0
  fi

  local xml_files=()
  while IFS= read -r f; do xml_files+=("$f"); done < <(find "$xml_dir" -name "*.junit" -o -name "*.xml" 2>/dev/null | sort)
  if [[ ${#xml_files[@]} -eq 0 ]]; then
    echo "  No JUnit XML files found in $xml_dir" >&2
    return 0
  fi

  echo "  Parsing ${#xml_files[@]} test XML file(s)..." >&2

  for xml in "${xml_files[@]}"; do
    [[ ! -f "$xml" ]] && continue

    local tests failures errors root
    # Grand totals live on the root <testsuites> element (first match). scan emits
    # single-quoted attributes (tests='286'), but other tools use double quotes, so
    # accept either. The ['\"] class matches a single OR double quote.
    root=$(grep -E '<testsuites?[[:space:]]' "$xml" | head -1)
    tests=$(echo "$root" | grep -oE "tests=['\"][0-9]+" | grep -oE '[0-9]+')
    failures=$(echo "$root" | grep -oE "failures=['\"][0-9]+" | grep -oE '[0-9]+')
    errors=$(echo "$root" | grep -oE "errors=['\"][0-9]+" | grep -oE '[0-9]+')

    tests=$(ensure_number "$tests")
    failures=$(ensure_number "$failures")
    errors=$(ensure_number "$errors")

    local failed=$((failures + errors))
    local passed=$((tests - failed))
    TESTS_PASSED=$((TESTS_PASSED + passed))
    TESTS_FAILED=$((TESTS_FAILED + failed))

    while IFS= read -r testcase_line; do
      local test_name class_name
      # Accept single- or double-quoted attributes. For the test name, require a
      # leading space so we don't match the "name=" inside "classname=".
      test_name=$(echo "$testcase_line" | sed -nE "s/.*[[:space:]]name=['\"]([^'\"]*)['\"].*/\1/p")
      class_name=$(echo "$testcase_line" | sed -nE "s/.*classname=['\"]([^'\"]*)['\"].*/\1/p")

      if echo "$testcase_line" | grep -q "/>"; then
        PASSED_TESTS="${PASSED_TESTS}${class_name}.${test_name}|${class_name}
"
      else
        FAILED_TESTS="${FAILED_TESTS}${class_name}.${test_name}|Test failed|${class_name}
"
      fi
    done < <(grep '<testcase' "$xml")
  done
}

# ─── Parse coverage from slather cobertura XML ────────────────────────────────
parse_coverage() {
  local xml="$OUTPUT_DIR/cobertura.xml"
  if [[ ! -f "$xml" ]]; then
    echo "  No cobertura.xml found at $xml" >&2
    return 0
  fi

  echo "  Parsing slather cobertura XML: $xml" >&2

  # Use Python to parse the Cobertura XML — portable (no grep -P issues on macOS).
  local tmpscript
  tmpscript=$(mktemp)
  cat > "$tmpscript" << 'PYEOF'
import sys
import xml.etree.ElementTree as ET

tree = ET.parse(sys.argv[1])
root = tree.getroot()

# Overall line-rate from root <coverage line-rate="0.82">
overall = float(root.get('line-rate', 0)) * 100
print('OVERALL|{}'.format(int(overall)))

# Per-class breakdown
entries = []
for cls in root.findall('.//class'):
    name = cls.get('filename', cls.get('name', ''))
    rate = float(cls.get('line-rate', 0)) * 100
    if name:
        entries.append((int(rate), name))
entries.sort(key=lambda x: x[0])
for pct, name in entries:
    print('{}|{}'.format(name, pct))
PYEOF

  local output
  output=$(python3 "$tmpscript" "$xml" 2>/dev/null || echo "")
  rm -f "$tmpscript"

  local overall_line
  overall_line=$(echo "$output" | head -1)
  if [[ "$overall_line" == OVERALL\|* ]]; then
    local pct="${overall_line#OVERALL|}"
    pct=$(ensure_number "$pct")
    [[ $pct -gt 0 ]] && COVERAGE_PERCENT=$pct
    output=$(echo "$output" | tail -n +2)
  fi

  while IFS='|' read -r filename pct; do
    [[ -z "$filename" ]] && continue
    COVERAGE_DETAILS="${COVERAGE_DETAILS}${filename}|${pct}
"
  done <<< "$output"
}

# ─── Parse lint from SwiftLint checkstyle XML ────────────────────────────────
parse_lint() {
  local xml="$OUTPUT_DIR/swiftlint-checkstyle.xml"
  if [[ ! -f "$xml" ]]; then
    echo "  No swiftlint-checkstyle.xml found — skipping lint section" >&2
    return 0
  fi

  echo "  Parsing SwiftLint checkstyle XML: $xml" >&2

  # Checkstyle format: <file name="path"><error line="N" severity="warning|error" message="..."/>
  local current_file=""
  while IFS= read -r line; do
    if [[ "$line" =~ \<file\ name=\"([^\"]+)\" ]]; then
      current_file="${BASH_REMATCH[1]}"
      # Use a short relative path
      current_file="${current_file#"$REPO_ROOT"/}"
    elif [[ "$line" =~ \<error ]]; then
      local lineno severity message
      lineno=$(echo "$line" | grep -oE 'line="[0-9]+"' | head -1 | grep -oE '[0-9]+')
      severity=$(echo "$line" | grep -oE 'severity="[^"]*"' | head -1 | sed 's/severity="//; s/"//')
      message=$(echo "$line" | grep -oE 'message="[^"]*"' | head -1 | sed 's/message="//; s/"$//')
      # HTML-decode common entities
      message=$(echo "$message" | sed 's/&amp;/\&/g; s/&lt;/</g; s/&gt;/>/g; s/&quot;/"/g; s/&#39;/'"'"'/g')

      local location="${current_file}:${lineno}"
      LINT_DETAILS="${LINT_DETAILS}${message}|${severity}|${location}
"
      case "${severity}" in
        error)   LINT_ERRORS=$((LINT_ERRORS + 1)) ;;
        warning) LINT_WARNINGS=$((LINT_WARNINGS + 1)) ;;
      esac
    fi
  done < "$xml"

  echo "  SwiftLint: ${LINT_ERRORS} errors, ${LINT_WARNINGS} warnings" >&2
}

# ─── Generate HTML dashboard ──────────────────────────────────────────────────
generate_html() {
  TESTS_PASSED=$(ensure_number "$TESTS_PASSED")
  TESTS_FAILED=$(ensure_number "$TESTS_FAILED")
  COVERAGE_PERCENT=$(ensure_number "$COVERAGE_PERCENT")
  LINT_WARNINGS=$(ensure_number "$LINT_WARNINGS")
  LINT_ERRORS=$(ensure_number "$LINT_ERRORS")

  local total_tests=$((TESTS_PASSED + TESTS_FAILED))
  local pass_rate=0
  [[ $total_tests -gt 0 ]] && pass_rate=$((TESTS_PASSED * 100 / total_tests))
  local total_lint=$((LINT_WARNINGS + LINT_ERRORS))

  local coverage_color="error"
  [[ $COVERAGE_PERCENT -ge 80 ]] && coverage_color="success"
  [[ $COVERAGE_PERCENT -ge 60 && $COVERAGE_PERCENT -lt 80 ]] && coverage_color="warning"

  local current_date
  current_date=$(date '+%B %d, %Y at %l:%M %p' | sed 's/  / /g')
  local branch
  branch=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown")

  mkdir -p "$(dirname "$OUTPUT_HTML")"

  cat > "$OUTPUT_HTML" << 'EOF_TEMPLATE'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Guardian.swift SDK - Test Report Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif; background: #f5f5f5; padding: 20px; line-height: 1.6; color: #333; }
        .container { max-width: 1200px; margin: 0 auto; background: white; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); overflow: hidden; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; }
        .header h1 { font-size: 28px; margin-bottom: 10px; font-weight: 600; }
        .header p { opacity: 0.9; font-size: 14px; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; padding: 30px; background: #f8f9fa; border-bottom: 1px solid #e0e0e0; }
        .summary-card { background: white; padding: 20px; border-radius: 6px; border-left: 4px solid #ccc; box-shadow: 0 1px 3px rgba(0,0,0,0.05); }
        .summary-card.success { border-left-color: #28a745; }
        .summary-card.warning { border-left-color: #ffc107; }
        .summary-card.error   { border-left-color: #dc3545; }
        .summary-card.info    { border-left-color: #17a2b8; }
        .summary-card h3 { font-size: 13px; color: #666; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 10px; font-weight: 600; }
        .summary-card .value { font-size: 36px; font-weight: bold; color: #333; margin-bottom: 5px; }
        .summary-card .label { color: #666; font-size: 14px; }
        .section { padding: 30px; border-bottom: 1px solid #e0e0e0; }
        .section:last-child { border-bottom: none; }
        .section-title { font-size: 20px; color: #333; margin-bottom: 20px; font-weight: 600; display: flex; align-items: center; gap: 10px; }
        details { background: #f8f9fa; border: 1px solid #e0e0e0; border-radius: 6px; margin-bottom: 15px; overflow: hidden; }
        details[open] { box-shadow: 0 2px 8px rgba(0,0,0,0.08); }
        summary { padding: 20px; cursor: pointer; font-weight: 600; font-size: 16px; color: #333; background: #fff; border-left: 4px solid #667eea; display: flex; justify-content: space-between; align-items: center; }
        summary:hover { background: #f8f9fa; }
        details[open] summary { border-bottom: 1px solid #e0e0e0; background: #f8f9fa; }
        .details-content { padding: 20px; background: white; }
        .test-item, .coverage-item, .lint-item { padding: 15px; margin-bottom: 10px; background: #f8f9fa; border-left: 3px solid #ccc; border-radius: 4px; }
        .test-item.failed      { border-left-color: #dc3545; background: #fff5f5; }
        .test-item.passed      { border-left-color: #28a745; }
        .coverage-item.low     { border-left-color: #dc3545; background: #fff5f5; }
        .coverage-item.medium  { border-left-color: #ffc107; background: #fffef5; }
        .coverage-item.high    { border-left-color: #28a745; }
        .lint-item.warning     { border-left-color: #ffc107; background: #fffef5; }
        .lint-item.error       { border-left-color: #dc3545; background: #fff5f5; }
        .item-title    { font-weight: 600; font-size: 14px; margin-bottom: 8px; color: #333; }
        .item-location { font-size: 12px; color: #999; font-family: 'Monaco', 'Courier New', monospace; }
        .badge { display: inline-block; padding: 4px 8px; border-radius: 3px; font-size: 11px; font-weight: 600; text-transform: uppercase; }
        .badge.success { background: #d4edda; color: #155724; }
        .badge.error   { background: #f8d7da; color: #721c24; }
        .badge.warning { background: #fff3cd; color: #856404; }
        .badge.info    { background: #d1ecf1; color: #0c5460; }
        .progress-bar  { width: 100%; height: 8px; background: #e0e0e0; border-radius: 4px; overflow: hidden; margin-top: 8px; }
        .progress-fill { height: 100%; }
        .progress-fill.success { background: #28a745; }
        .progress-fill.warning { background: #ffc107; }
        .progress-fill.error   { background: #dc3545; }
        .empty-state { text-align: center; padding: 40px; color: #999; }
        .footer { text-align: center; padding: 20px; color: #666; font-size: 13px; background: #f8f9fa; }
        .paginated-item { display: none; }
        .paginated-item.visible { display: block; }
        .pagination { display: flex; justify-content: center; align-items: center; gap: 10px; margin-top: 15px; padding: 15px; }
        .pagination button { padding: 6px 12px; border: 1px solid #ddd; background: white; border-radius: 4px; cursor: pointer; font-size: 13px; }
        .pagination button:hover:not(:disabled) { background: #667eea; color: white; border-color: #667eea; }
        .pagination button:disabled { opacity: 0.4; cursor: not-allowed; }
        .pagination .page-info { color: #666; font-size: 13px; }
    </style>
    <script>
        function setupPagination(containerId, itemsPerPage) {
            var container = document.getElementById(containerId);
            if (!container) return;
            var items = Array.from(container.querySelectorAll('.paginated-item'));
            if (items.length <= itemsPerPage) { items.forEach(function(i){ i.classList.add('visible'); }); return; }
            var currentPage = 1;
            var totalPages = Math.ceil(items.length / itemsPerPage);
            var div = document.createElement('div'); div.className = 'pagination';
            div.innerHTML = '<button class="prev-btn">← Previous</button><span class="page-info"></span><button class="next-btn">Next →</button>';
            container.appendChild(div);
            var prevBtn = div.querySelector('.prev-btn'), nextBtn = div.querySelector('.next-btn'), pageInfo = div.querySelector('.page-info');
            function showPage(p) {
                currentPage = p; var start = (p-1)*itemsPerPage, end = start+itemsPerPage;
                items.forEach(function(item, idx){ item.classList.toggle('visible', idx >= start && idx < end); });
                pageInfo.textContent = 'Page '+p+' of '+totalPages+' ('+items.length+' total)';
                prevBtn.disabled = p === 1; nextBtn.disabled = p === totalPages;
            }
            prevBtn.addEventListener('click', function(){ showPage(currentPage-1); });
            nextBtn.addEventListener('click', function(){ showPage(currentPage+1); });
            showPage(1);
        }
        document.addEventListener('DOMContentLoaded', function() {
            setupPagination('failed-tests-list', 10); setupPagination('passed-tests-list', 20);
            setupPagination('lint-errors-list', 10);  setupPagination('lint-warnings-list', 20);
            setupPagination('coverage-low-list', 20); setupPagination('coverage-med-list', 20);
            setupPagination('coverage-good-list', 20);
        });
    </script>
</head>
<body>
<div class="container">
  <div class="header">
    <h1>Guardian.swift SDK - Test Report Dashboard</h1>
    <p>BUILD_DATE_PLACEHOLDER | Branch: BRANCH_PLACEHOLDER</p>
  </div>
  <div class="summary">
    <div class="summary-card PASS_CARD_CLASS">
      <h3>Tests Passed</h3>
      <div class="value">TESTS_PASSED_PLACEHOLDER/TOTAL_TESTS_PLACEHOLDER</div>
      <div class="label">PASS_RATE_PLACEHOLDER% pass rate</div>
      <div class="progress-bar"><div class="progress-fill success" style="width:PASS_RATE_PLACEHOLDER%;"></div></div>
    </div>
    <div class="summary-card FAIL_CARD_CLASS">
      <h3>Tests Failed</h3>
      <div class="value">TESTS_FAILED_PLACEHOLDER</div>
      <div class="label">FAIL_RATE_PLACEHOLDER% failure rate</div>
    </div>
    <div class="summary-card COVERAGE_CARD_CLASS">
      <h3>Code Coverage</h3>
      <div class="value">COVERAGE_PERCENT_PLACEHOLDER%</div>
      <div class="label">Target: 80%</div>
      <div class="progress-bar"><div class="progress-fill COVERAGE_COLOR_CLASS" style="width:COVERAGE_PERCENT_PLACEHOLDER%;"></div></div>
    </div>
    <div class="summary-card LINT_CARD_CLASS">
      <h3>Lint Issues</h3>
      <div class="value">TOTAL_LINT_PLACEHOLDER</div>
      <div class="label">LINT_ERRORS_PLACEHOLDER errors, LINT_WARNINGS_PLACEHOLDER warnings</div>
    </div>
  </div>
  TEST_SECTION_PLACEHOLDER
  COVERAGE_SECTION_PLACEHOLDER
  LINT_SECTION_PLACEHOLDER
  <div class="footer">Generated by Guardian.swift SDK CI/CD Pipeline</div>
</div>
</body>
</html>
EOF_TEMPLATE

  # Replace placeholders
  sed -i.bak "s|BUILD_DATE_PLACEHOLDER|${current_date}|g" "$OUTPUT_HTML"
  sed -i.bak "s|BRANCH_PLACEHOLDER|${branch}|g" "$OUTPUT_HTML"
  sed -i.bak "s|TESTS_PASSED_PLACEHOLDER|${TESTS_PASSED}|g" "$OUTPUT_HTML"
  sed -i.bak "s|TESTS_FAILED_PLACEHOLDER|${TESTS_FAILED}|g" "$OUTPUT_HTML"
  sed -i.bak "s|TOTAL_TESTS_PLACEHOLDER|${total_tests}|g" "$OUTPUT_HTML"
  sed -i.bak "s|PASS_RATE_PLACEHOLDER|${pass_rate}|g" "$OUTPUT_HTML"
  sed -i.bak "s|FAIL_RATE_PLACEHOLDER|$((100 - pass_rate))|g" "$OUTPUT_HTML"
  sed -i.bak "s|COVERAGE_PERCENT_PLACEHOLDER|${COVERAGE_PERCENT}|g" "$OUTPUT_HTML"
  sed -i.bak "s|LINT_ERRORS_PLACEHOLDER|${LINT_ERRORS}|g" "$OUTPUT_HTML"
  sed -i.bak "s|LINT_WARNINGS_PLACEHOLDER|${LINT_WARNINGS}|g" "$OUTPUT_HTML"
  sed -i.bak "s|COVERAGE_COLOR_CLASS|${coverage_color}|g" "$OUTPUT_HTML"
  sed -i.bak "s|TOTAL_LINT_PLACEHOLDER|${total_lint}|g" "$OUTPUT_HTML"

  local lint_card="info"
  [[ $LINT_WARNINGS -gt 0 ]] && lint_card="warning"
  [[ $LINT_ERRORS   -gt 0 ]] && lint_card="error"
  sed -i.bak "s|LINT_CARD_CLASS|${lint_card}|g" "$OUTPUT_HTML"

  local pass_card="success"; [[ $TESTS_FAILED -gt 0 ]] && pass_card="warning"
  local fail_card="success"; [[ $TESTS_FAILED -gt 0 ]] && fail_card="error"
  local cov_card="error"
  [[ $COVERAGE_PERCENT -ge 60 ]] && cov_card="warning"
  [[ $COVERAGE_PERCENT -ge 80 ]] && cov_card="success"
  sed -i.bak "s|PASS_CARD_CLASS|${pass_card}|g" "$OUTPUT_HTML"
  sed -i.bak "s|FAIL_CARD_CLASS|${fail_card}|g" "$OUTPUT_HTML"
  sed -i.bak "s|COVERAGE_CARD_CLASS|${cov_card}|g" "$OUTPUT_HTML"

  generate_test_section
  generate_coverage_section
  generate_lint_section

  rm -f "${OUTPUT_HTML}.bak"
}

# ─── Section generators ───────────────────────────────────────────────────────
generate_test_section() {
  if [[ $((TESTS_PASSED + TESTS_FAILED)) -eq 0 ]]; then
    local empty='<div class="section"><h2 class="section-title">🧪 Test Results</h2><div class="empty-state"><p>No test results available</p></div></div>'
    sed -i.bak "s|TEST_SECTION_PLACEHOLDER|${empty}|g" "$OUTPUT_HTML"
    return
  fi

  local section='<div class="section"><h2 class="section-title">🧪 Test Results</h2>'

  if [[ $TESTS_FAILED -gt 0 ]]; then
    section+="<details open><summary><span>Failed Tests (${TESTS_FAILED})</span><span class=\"badge error\">View Details</span></summary><div class=\"details-content\" id=\"failed-tests-list\">"
    while IFS='|' read -r name message location; do
      [[ -z "$name" ]] && continue
      section+="<div class=\"test-item failed paginated-item\"><div class=\"item-title\">❌ ${name}</div><div class=\"item-location\">${message} — ${location}</div></div>"
    done <<< "$FAILED_TESTS"
    section+='</div></details>'
  fi

  if [[ $TESTS_PASSED -gt 0 ]]; then
    section+="<details><summary><span>Passed Tests (${TESTS_PASSED})</span><span class=\"badge success\">View Details</span></summary><div class=\"details-content\" id=\"passed-tests-list\">"
    while IFS='|' read -r name location; do
      [[ -z "$name" ]] && continue
      section+="<div class=\"test-item passed paginated-item\"><div class=\"item-title\">✅ ${name}</div><div class=\"item-location\">${location}</div></div>"
    done <<< "$PASSED_TESTS"
    section+='</div></details>'
  fi

  section+='</div>'
  # Escape chars special to the consuming `s|PLACEHOLDER|section|` substitution:
  # the `|` delimiter, `&` (whole-match ref), and `\`. (`/` is NOT the delimiter
  # here, so it needs no escaping.) Missing `|` previously corrupted the dashboard
  # whenever a lint message/test name contained a pipe.
  section=$(echo "$section" | sed 's/[&|\\]/\\&/g')
  sed -i.bak "s|TEST_SECTION_PLACEHOLDER|${section}|g" "$OUTPUT_HTML"
}

generate_coverage_section() {
  if [[ $COVERAGE_PERCENT -eq 0 && -z "$COVERAGE_DETAILS" ]]; then
    local empty='<div class="section"><h2 class="section-title">📊 Code Coverage</h2><div class="empty-state"><p>No coverage data available</p></div></div>'
    sed -i.bak "s|COVERAGE_SECTION_PLACEHOLDER|${empty}|g" "$OUTPUT_HTML"
    return
  fi

  local cov_card="error"
  [[ $COVERAGE_PERCENT -ge 60 ]] && cov_card="warning"
  [[ $COVERAGE_PERCENT -ge 80 ]] && cov_card="success"

  local section='<div class="section"><h2 class="section-title">📊 Code Coverage</h2>'
  section+="<div class=\"details-content\" style=\"padding:12px 0;\"><div class=\"coverage-item\"><div class=\"item-title\" style=\"display:flex;justify-content:space-between;\"><span>Overall Coverage</span><span class=\"badge ${cov_card}\">${COVERAGE_PERCENT}%</span></div><div class=\"progress-bar\" style=\"margin-top:8px;\"><div class=\"progress-fill ${cov_card}\" style=\"width:${COVERAGE_PERCENT}%;\"></div></div></div></div>"

  if [[ -n "$COVERAGE_DETAILS" ]]; then
    local low_count=0 med_count=0 good_count=0
    while IFS='|' read -r filename pct; do
      [[ -z "$filename" ]] && continue
      [[ $pct -lt 60 ]] && low_count=$((low_count+1))
      [[ $pct -ge 60 && $pct -lt 80 ]] && med_count=$((med_count+1))
      [[ $pct -ge 80 ]] && good_count=$((good_count+1))
    done <<< "$COVERAGE_DETAILS"

    if [[ $low_count -gt 0 ]]; then
      section+="<details open><summary><span>Needs Coverage (${low_count})</span><span class=\"badge error\">Below 60%</span></summary><div class=\"details-content\" id=\"coverage-low-list\">"
      while IFS='|' read -r filename pct; do
        [[ -z "$filename" || $pct -ge 60 ]] && continue
        section+="<div class=\"coverage-item low paginated-item\"><div class=\"item-title\">❌ ${filename}</div><div class=\"item-location\">${pct}% coverage</div><div class=\"progress-bar\"><div class=\"progress-fill error\" style=\"width:${pct}%;\"></div></div></div>"
      done <<< "$COVERAGE_DETAILS"
      section+='</div></details>'
    fi

    if [[ $med_count -gt 0 ]]; then
      section+="<details open><summary><span>Improve Coverage (${med_count})</span><span class=\"badge warning\">60-79%</span></summary><div class=\"details-content\" id=\"coverage-med-list\">"
      while IFS='|' read -r filename pct; do
        [[ -z "$filename" || $pct -lt 60 || $pct -ge 80 ]] && continue
        section+="<div class=\"coverage-item medium paginated-item\"><div class=\"item-title\">⚠️ ${filename}</div><div class=\"item-location\">${pct}% coverage</div><div class=\"progress-bar\"><div class=\"progress-fill warning\" style=\"width:${pct}%;\"></div></div></div>"
      done <<< "$COVERAGE_DETAILS"
      section+='</div></details>'
    fi

    if [[ $good_count -gt 0 ]]; then
      section+="<details><summary><span>Good Coverage (${good_count})</span><span class=\"badge success\">80%+</span></summary><div class=\"details-content\" id=\"coverage-good-list\">"
      while IFS='|' read -r filename pct; do
        [[ -z "$filename" || $pct -lt 80 ]] && continue
        section+="<div class=\"coverage-item high paginated-item\"><div class=\"item-title\">✅ ${filename}</div><div class=\"item-location\">${pct}% coverage</div><div class=\"progress-bar\"><div class=\"progress-fill success\" style=\"width:${pct}%;\"></div></div></div>"
      done <<< "$COVERAGE_DETAILS"
      section+='</div></details>'
    fi
  fi

  section+='</div>'
  # Escape chars special to the consuming `s|PLACEHOLDER|section|` substitution:
  # the `|` delimiter, `&` (whole-match ref), and `\`. (`/` is NOT the delimiter
  # here, so it needs no escaping.) Missing `|` previously corrupted the dashboard
  # whenever a lint message/test name contained a pipe.
  section=$(echo "$section" | sed 's/[&|\\]/\\&/g')
  sed -i.bak "s|COVERAGE_SECTION_PLACEHOLDER|${section}|g" "$OUTPUT_HTML"
}

generate_lint_section() {
  local total_lint=$((LINT_WARNINGS + LINT_ERRORS))

  if [[ $total_lint -eq 0 ]]; then
    local empty='<div class="section"><h2 class="section-title">🔍 Lint Issues</h2><div class="empty-state"><p>✨ No lint issues found</p></div></div>'
    sed -i.bak "s|LINT_SECTION_PLACEHOLDER|${empty}|g" "$OUTPUT_HTML"
    return
  fi

  local section='<div class="section"><h2 class="section-title">🔍 Lint Issues (SwiftLint)</h2>'

  if [[ $LINT_ERRORS -gt 0 ]]; then
    section+="<details open><summary><span>Errors (${LINT_ERRORS})</span><span class=\"badge error\">Blocks CI</span></summary><div class=\"details-content\" id=\"lint-errors-list\">"
    while IFS='|' read -r message severity location; do
      [[ -z "$message" || "${severity}" != "error" ]] && continue
      section+="<div class=\"lint-item error paginated-item\"><div class=\"item-title\">❌ ${message}</div><div class=\"item-location\">${location}</div></div>"
    done <<< "$LINT_DETAILS"
    section+='</div></details>'
  fi

  if [[ $LINT_WARNINGS -gt 0 ]]; then
    section+="<details><summary><span>Warnings (${LINT_WARNINGS})</span><span class=\"badge warning\">Non-blocking</span></summary><div class=\"details-content\" id=\"lint-warnings-list\">"
    while IFS='|' read -r message severity location; do
      [[ -z "$message" || "${severity}" != "warning" ]] && continue
      section+="<div class=\"lint-item warning paginated-item\"><div class=\"item-title\">⚠️ ${message}</div><div class=\"item-location\">${location}</div></div>"
    done <<< "$LINT_DETAILS"
    section+='</div></details>'
  fi

  section+='</div>'
  # Escape chars special to the consuming `s|PLACEHOLDER|section|` substitution:
  # the `|` delimiter, `&` (whole-match ref), and `\`. (`/` is NOT the delimiter
  # here, so it needs no escaping.) Missing `|` previously corrupted the dashboard
  # whenever a lint message/test name contained a pipe.
  section=$(echo "$section" | sed 's/[&|\\]/\\&/g')
  sed -i.bak "s|LINT_SECTION_PLACEHOLDER|${section}|g" "$OUTPUT_HTML"
}

# ─── GitHub Actions step summary ─────────────────────────────────────────────
# Writes a markdown summary to $GITHUB_STEP_SUMMARY when running in CI.
# Appended (>>) so it is safe to call even if a prior step wrote to the file.
generate_gha_summary() {
  [[ -z "${GITHUB_STEP_SUMMARY:-}" ]] && return 0

  local total_tests=$((TESTS_PASSED + TESTS_FAILED))
  local total_lint=$((LINT_WARNINGS + LINT_ERRORS))

  local test_icon="✅"
  [[ $TESTS_FAILED -gt 0 ]] && test_icon="❌"
  [[ $total_tests -eq 0 ]]  && test_icon="⚠️"

  local cov_icon="✅"
  [[ $COVERAGE_PERCENT -lt 80 ]] && cov_icon="❌"

  local lint_icon="✅"
  [[ $LINT_ERRORS -gt 0 ]]   && lint_icon="❌"
  [[ $LINT_WARNINGS -gt 0 && $LINT_ERRORS -eq 0 ]] && lint_icon="⚠️"

  local branch
  branch=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown")

  {
    echo "## Guardian.swift — CI Summary"
    echo ""
    echo "| | Metric | Result |"
    echo "|---|---|---|"
    echo "| ${test_icon} | Tests | **${TESTS_PASSED} passed**, ${TESTS_FAILED} failed (${total_tests} total) |"
    echo "| ${cov_icon} | Coverage | **${COVERAGE_PERCENT}%** |"
    echo "| ${lint_icon} | Lint | **${LINT_ERRORS} errors**, ${LINT_WARNINGS} warnings |"
    echo ""
    echo "> Branch: \`${branch}\`"

    if [[ $TESTS_FAILED -gt 0 && -n "$FAILED_TESTS" ]]; then
      echo ""
      echo "### ❌ Failed Tests"
      echo ""
      while IFS='|' read -r name _msg _class; do
        [[ -z "$name" ]] && continue
        echo "- \`${name}\`"
      done <<< "$FAILED_TESTS"
    fi

    if [[ $total_lint -gt 0 && -n "$LINT_DETAILS" ]]; then
      echo ""
      if [[ $LINT_ERRORS -gt 0 ]]; then
        echo "### ❌ Lint Issues"
      else
        echo "### ⚠️ Lint Warnings"
      fi
      echo ""
      echo "| Severity | File | Message |"
      echo "|---|---|---|"
      while IFS='|' read -r message severity location; do
        [[ -z "$message" ]] && continue
        local sev_badge="⚠️ warning"
        [[ "$severity" == "error" ]] && sev_badge="❌ error"
        echo "| ${sev_badge} | \`${location}\` | ${message} |"
      done <<< "$LINT_DETAILS"
    fi
  } >> "$GITHUB_STEP_SUMMARY"
}

# ─── Quality gate ────────────────────────────────────────────────────────────
# Checked AFTER HTML + GHA summary are written so the artifact always carries
# the full report even when the gate fires. Exits non-zero on any breach.
# Coverage threshold: 80%. Lint errors and test failures are also gates here
# (belt-and-suspenders — the fastlane lanes already fail fast on those).
COVERAGE_THRESHOLD=80

check_quality_gate() {
  local failures=()

  [[ $TESTS_FAILED -gt 0 ]] \
    && failures+=("${TESTS_FAILED} unit test(s) failed")

  [[ $LINT_ERRORS -gt 0 ]] \
    && failures+=("${LINT_ERRORS} lint error(s) found")

  [[ $COVERAGE_PERCENT -lt $COVERAGE_THRESHOLD ]] \
    && failures+=("coverage ${COVERAGE_PERCENT}% is below the ${COVERAGE_THRESHOLD}% threshold")

  if [[ ${#failures[@]} -eq 0 ]]; then
    echo "✅ Quality gate passed" >&2
    _append_gate_summary "✅ passed"
    return 0
  fi

  echo "❌ Quality gate FAILED:" >&2
  local f; for f in "${failures[@]}"; do echo "   • $f" >&2; done
  _append_gate_summary "❌ failed" "${failures[@]}"
  return 1
}

_append_gate_summary() {
  [[ -z "${GITHUB_STEP_SUMMARY:-}" ]] && return 0
  local status="$1"; shift
  local reasons=("$@")
  {
    echo ""
    echo "### Quality Gate — ${status}"
    if [[ ${#reasons[@]} -gt 0 ]]; then
      echo ""
      local r; for r in "${reasons[@]}"; do echo "- ❌ ${r}"; done
    fi
  } >> "$GITHUB_STEP_SUMMARY"
}

# ─── Main ─────────────────────────────────────────────────────────────────────
main() {
  local do_test="${GUARDIAN_DO_TEST:-true}"
  local do_coverage="${GUARDIAN_DO_COVERAGE:-true}"
  local do_lint="${GUARDIAN_DO_LINT:-true}"

  [[ "$do_test"     == "true" ]] && parse_test_results || echo "Skipping test results"
  [[ "$do_coverage" == "true" ]] && parse_coverage     || echo "Skipping coverage data"
  [[ "$do_lint"     == "true" ]] && parse_lint         || echo "Skipping lint results"

  echo "Generating unified dashboard..." >&2
  generate_html
  rm -f "${OUTPUT_HTML}.bak"
  generate_gha_summary

  echo "✅ Dashboard generated: $OUTPUT_HTML" >&2
  echo "   Tests: $TESTS_PASSED passed, $TESTS_FAILED failed" >&2
  echo "   Coverage: ${COVERAGE_PERCENT}%" >&2
  echo "   Lint: ${LINT_WARNINGS} warnings, ${LINT_ERRORS} errors" >&2

  check_quality_gate
}

main "$@"
