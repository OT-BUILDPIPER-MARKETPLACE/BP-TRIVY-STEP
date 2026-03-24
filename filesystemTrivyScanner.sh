#!/bin/bash
source /opt/buildpiper/shell-functions/functions.sh
source /opt/buildpiper/shell-functions/mi-functions.sh
source /opt/buildpiper/shell-functions/log-functions.sh
source /opt/buildpiper/shell-functions/str-functions.sh
source /opt/buildpiper/shell-functions/file-functions.sh
source /opt/buildpiper/shell-functions/aws-functions.sh
source /opt/buildpiper/shell-functions/getDataFile.sh

if [ "$DEBUG" = true ]; then
  set -x
fi

###############################################
### EVENTS TRACKING
###############################################
EVENTS='{}'

add_event() {
  local key="${1:-}"
  local status="${2:-}"
  local reason="${3:-}"
  local message="${4:-}"

  if [ -z "$key" ] || [ -z "$status" ]; then
    echo "Error: add_event requires at least 'key' and 'status' parameters" >&2
    return 1
  fi

  key="$(echo "$key" | tr '_' ' ' | tr '-' ' ' | tr '[:upper:]' '[:lower:]')"

  EVENTS=$(jq \
    --arg k "$key" \
    --arg status "$status" \
    --arg reason "$reason" \
    --arg message "$message" \
    '. + {($k): {status: $status, reason: $reason, message: $message}}' \
    <<< "$EVENTS") || {
    echo "Error: Failed to add event to EVENTS JSON" >&2
    return 1
  }
}

###############################################
### OUTPUT FILE
###############################################
TRIVY_OUTPUT_FILE="${TRIVY_OUTPUT_FILE:-${ACTIVITY_SUB_TASK_CODE}_output.json}"
TRIVY_REPORT_CSV="${TRIVY_REPORT_CSV:-trivy.csv}"

###############################################
### THRESHOLD CONFIGURATION
###############################################
TRIVY_THRESHOLD_CRITICAL="${TRIVY_THRESHOLD_CRITICAL:-0}"
TRIVY_THRESHOLD_HIGH="${TRIVY_THRESHOLD_HIGH:--1}"
TRIVY_THRESHOLD_MEDIUM="${TRIVY_THRESHOLD_MEDIUM:--1}"
TRIVY_THRESHOLD_LOW="${TRIVY_THRESHOLD_LOW:--1}"
TRIVY_THRESHOLD_TOTAL="${TRIVY_THRESHOLD_TOTAL:--1}"

cd ${WORKSPACE}/${CODEBASE_DIR}

STATUS=0

logInfoMessage "============================"
logInfoMessage "Start Filesystem scanning"
logInfoMessage "============================"

logInfoMessage "I'll scan Filesystem ${WORKSPACE}/${CODEBASE_DIR} for only ${SCAN_SEVERITY} severities"
sleep  $SLEEP_DURATION
logInfoMessage "Executing command"

###############################################
### CREATE EXECUTION DIRECTORY
###############################################
if [ -n "${GLOBAL_TASK_ID:-}" ]; then
    EXEC_DIR="/bp/execution_dir/${GLOBAL_TASK_ID}"
    mkdir -p "${EXEC_DIR}"
    add_event "create execution dir" "Successful" "Directory created" "Created ${EXEC_DIR}"
else
    logErrorMessage "GLOBAL_TASK_ID not set; cannot proceed"
    add_event "create execution dir" "Failed" "GLOBAL_TASK_ID missing" "Cannot create execution directory"
    exit 1
fi

###############################################
### RUN TRIVY SCAN (ALWAYS GENERATE JSON)
###############################################
JSON_REPORT="${EXEC_DIR}/trivy-fs-results.json"

logInfoMessage "Generating JSON report: ${JSON_REPORT}"
logInfoMessage "trivy fs -q --severity ${SCAN_SEVERITY} --format json -o ${JSON_REPORT} ${WORKSPACE}/${CODEBASE_DIR}"

trivy fs -q --severity "${SCAN_SEVERITY}" --format json -o "${JSON_REPORT}" "${WORKSPACE}/${CODEBASE_DIR}"
STATUS=$?

logInfoMessage "Trivy scan completed with exit code: ${STATUS}"

if [[ "$STATUS" -eq 0 ]]; then
  add_event "trivy scan" "Successful" "No vulnerabilities detected" "trivy fs completed clean for ${WORKSPACE}/${CODEBASE_DIR}"
elif [[ "$STATUS" -eq 1 ]]; then
  add_event "trivy scan" "Successful" "Vulnerabilities detected" "trivy fs found vulnerabilities in ${WORKSPACE}/${CODEBASE_DIR}"
else
  add_event "trivy scan" "Failed" "Trivy execution error" "trivy fs exited with unexpected code $STATUS"
fi

###############################################
### GENERATE HTML REPORT IF REQUESTED
###############################################
if [[ "${REPORT_TYPE}" == "html" || "${REPORT_TYPE}" == "both" ]]; then
    logInfoMessage "Generating HTML report"
    HTML_REPORT="${EXEC_DIR}/trivy-fs-results.html"
    
    trivy fs -q --severity ${SCAN_SEVERITY} --format template --template @/contrib/html.tpl -o "${HTML_REPORT}" "${WORKSPACE}/${CODEBASE_DIR}"
    
    logInfoMessage "HTML report generated at ${HTML_REPORT}"
    add_event "generate html report" "Successful" "HTML created" "HTML report generated at ${HTML_REPORT}"
fi

###############################################
### PARSE RESULTS AND GENERATE CSV (ALWAYS)
###############################################
if [ -s "${JSON_REPORT}" ]; then
    CRITICAL=$(jq '([.Results[]? .Vulnerabilities[]? | select(.Severity=="CRITICAL")] | length) // 0' "${JSON_REPORT}" 2>/dev/null || echo 0)
    HIGH=$(jq '([.Results[]? .Vulnerabilities[]? | select(.Severity=="HIGH")] | length) // 0' "${JSON_REPORT}" 2>/dev/null || echo 0)
    MEDIUM=$(jq '([.Results[]? .Vulnerabilities[]? | select(.Severity=="MEDIUM")] | length) // 0' "${JSON_REPORT}" 2>/dev/null || echo 0)
    LOW=$(jq '([.Results[]? .Vulnerabilities[]? | select(.Severity=="LOW")] | length) // 0' "${JSON_REPORT}" 2>/dev/null || echo 0)
    TOTAL=$(jq '([.Results[]? .Vulnerabilities[]?] | length) // 0' "${JSON_REPORT}" 2>/dev/null || echo 0)
else
    CRITICAL=0; HIGH=0; MEDIUM=0; LOW=0; TOTAL=0
fi

add_event "parse scan results" "Successful" "Metrics extracted" "CRITICAL=${CRITICAL} HIGH=${HIGH} MEDIUM=${MEDIUM} LOW=${LOW} TOTAL=${TOTAL}"

###############################################
### CREATE CSV REPORT FOR UI TABLE (ALWAYS)
###############################################
REPORT_CSV="${EXEC_DIR}/${TRIVY_REPORT_CSV}"
echo "Library,CVE_ID,Severity,InstalledVersion,FixedVersion,Title" > "${REPORT_CSV}"

if [ -s "${JSON_REPORT}" ] && [[ "$TOTAL" -gt 0 ]]; then
    jq -r '
      .Results[]?
      | select(.Vulnerabilities != null)
      | .Vulnerabilities[]?
      | select(.Severity == "CRITICAL" or .Severity == "HIGH" or .Severity == "MEDIUM" or .Severity == "LOW")
      | [
          (.PkgName // "N/A"),
          (.VulnerabilityID // "N/A"),
          (.Severity // "N/A"),
          (.InstalledVersion // "N/A"),
          (.FixedVersion // "N/A"),
          (.Title // "N/A")
        ]
        | @csv
    ' "${JSON_REPORT}" >> "${REPORT_CSV}" 2>/dev/null || true

    logInfoMessage "Generated vulnerability CSV at ${REPORT_CSV}"
    add_event "generate csv report" "Successful" "CSV created" "Vulnerability CSV created with ${TOTAL} entries"
    
    # Display the report
    logInfoMessage "Displaying Vulnerability Report"
    python3 /opt/buildpiper/shell-functions/print_table.py "${REPORT_CSV}"
else
    echo "no-vulnerabilities,N/A,N/A,N/A,N/A,No vulnerabilities detected" >> "${REPORT_CSV}"
    logInfoMessage "No vulnerabilities found; CSV created empty"
    add_event "generate csv report" "Successful" "No vulnerabilities" "CSV created - no vulnerabilities found"
fi

###############################################
### THRESHOLD CHECK
###############################################
THRESHOLD_STATUS=0

_check() {
  local sev="$1" detected="$2" limit="$3"
  if [[ "$limit" == "-1" ]]; then
    add_event "threshold check $sev" "Successful" "${sev} threshold disabled" "TRIVY_THRESHOLD_${sev}=-1"
    return 0
  fi
  if [[ "$detected" -gt "$limit" ]]; then
    logErrorMessage "${sev} threshold breached: found $detected, allowed $limit"
    add_event "threshold check $sev" "Failed" "${sev} threshold breached" "Found $detected ${sev} vuln(s), allowed limit is $limit"
    return 1
  else
    add_event "threshold check $sev" "Successful" "Within ${sev} limit" "Found $detected ${sev} vuln(s), allowed limit is $limit"
    return 0
  fi
}

echo ""
echo "-------------------------------------------"
echo "THRESHOLD CHECK"
printf "  %-9s | %-8s | %s\n" "Severity" "Detected" "Allowed"
echo "  ----------|----------|--------"
printf "  %-9s | %-8s | %s\n" "CRITICAL" "${CRITICAL}" "$( [[ "$TRIVY_THRESHOLD_CRITICAL" == "-1" ]] && echo "disabled" || echo "$TRIVY_THRESHOLD_CRITICAL")"
printf "  %-9s | %-8s | %s\n" "HIGH"     "${HIGH}"     "$( [[ "$TRIVY_THRESHOLD_HIGH"     == "-1" ]] && echo "disabled" || echo "$TRIVY_THRESHOLD_HIGH")"
printf "  %-9s | %-8s | %s\n" "MEDIUM"   "${MEDIUM}"   "$( [[ "$TRIVY_THRESHOLD_MEDIUM"   == "-1" ]] && echo "disabled" || echo "$TRIVY_THRESHOLD_MEDIUM")"
printf "  %-9s | %-8s | %s\n" "LOW"      "${LOW}"      "$( [[ "$TRIVY_THRESHOLD_LOW"      == "-1" ]] && echo "disabled" || echo "$TRIVY_THRESHOLD_LOW")"
printf "  %-9s | %-8s | %s\n" "TOTAL"    "${TOTAL}"    "$( [[ "$TRIVY_THRESHOLD_TOTAL"    == "-1" ]] && echo "disabled" || echo "$TRIVY_THRESHOLD_TOTAL")"
echo "-------------------------------------------"

_check "critical" "${CRITICAL}" "$TRIVY_THRESHOLD_CRITICAL" || THRESHOLD_STATUS=1
_check "high"     "${HIGH}"     "$TRIVY_THRESHOLD_HIGH"     || THRESHOLD_STATUS=1
_check "medium"   "${MEDIUM}"   "$TRIVY_THRESHOLD_MEDIUM"   || THRESHOLD_STATUS=1
_check "low"      "${LOW}"      "$TRIVY_THRESHOLD_LOW"      || THRESHOLD_STATUS=1
_check "total"    "${TOTAL}"    "$TRIVY_THRESHOLD_TOTAL"    || THRESHOLD_STATUS=1

if [[ "$THRESHOLD_STATUS" -ne 0 ]]; then
  STATUS=1
fi

###############################################
### DETERMINE FINAL STATUS
###############################################
FINAL_STATUS="Successful"
FINAL_REASON="Scan completed"
FINAL_MESSAGE="Trivy filesystem scan passed. CRITICAL=${CRITICAL:-0} HIGH=${HIGH:-0} MEDIUM=${MEDIUM:-0} LOW=${LOW:-0}"

if [[ "$STATUS" -ne 0 ]]; then
  FINAL_STATUS="failed"
  FINAL_REASON="Threshold breached"
  FINAL_MESSAGE="Trivy filesystem scan failed. CRITICAL=${CRITICAL:-0} HIGH=${HIGH:-0} MEDIUM=${MEDIUM:-0} LOW=${LOW:-0}"
fi

###############################################
### BUILD ERROR EVENTS LIST
###############################################
ERROR_EVENTS=$(echo "$EVENTS" | jq '[to_entries[] | select(.value.status == "Failed") | .key]')

###############################################
### MAP STATUS TO BOOLEAN
###############################################
if [[ "$FINAL_STATUS" == "Successful" ]]; then
  STATUS_BOOL="true"
else
  STATUS_BOOL="false"
fi

###############################################
### CREATE STRUCTURED OUTPUT JSON
###############################################
jq -n \
  --argjson events "$EVENTS" \
  --argjson error_events "$ERROR_EVENTS" \
  --argjson status_bool "$STATUS_BOOL" \
  --arg final_status "$FINAL_STATUS" \
  --arg final_reason "$FINAL_REASON" \
  --arg final_message "$FINAL_MESSAGE" \
  --arg count_critical "${CRITICAL:-0}" \
  --arg count_high "${HIGH:-0}" \
  --arg count_medium "${MEDIUM:-0}" \
  --arg count_low "${LOW:-0}" \
  --arg count_total "${TOTAL:-0}" \
  --arg threshold_critical "$TRIVY_THRESHOLD_CRITICAL" \
  --arg threshold_high "$TRIVY_THRESHOLD_HIGH" \
  --arg threshold_medium "$TRIVY_THRESHOLD_MEDIUM" \
  --arg threshold_low "$TRIVY_THRESHOLD_LOW" \
  --arg threshold_total "$TRIVY_THRESHOLD_TOTAL" \
  --arg report_type "${REPORT_TYPE}" \
  '{
    build: {
      status: $status_bool,
      reason: $final_reason,
      message: $final_message,
      events: $events,
      current_error: (if $status_bool == "false" then $final_reason else "" end),
      error_events: $error_events
    },
    events: $events,
    output_vars: {
      trivy_fs_scan: {
        status: $final_status,
        reason: $final_reason,
        message: $final_message,
        results: {
          report_type: $report_type,
          vulnerabilities: {
            critical: ($count_critical | tonumber),
            high:     ($count_high | tonumber),
            medium:   ($count_medium | tonumber),
            low:      ($count_low | tonumber),
            total:    ($count_total | tonumber)
          },
          thresholds: {
            critical: $threshold_critical,
            high: $threshold_high,
            medium: $threshold_medium,
            low: $threshold_low,
            total: $threshold_total
          }
        },
        current_error: (if $final_status == "failed" then $final_reason else "" end),
        error_events: $error_events
      }
    }
  }' > "${EXEC_DIR}/${TRIVY_OUTPUT_FILE}"

logInfoMessage "Output JSON written to ${EXEC_DIR}/${TRIVY_OUTPUT_FILE}"
add_event "create output" "Successful" "Output file created" "Structured output written to ${TRIVY_OUTPUT_FILE}"

###############################################
### SIGNAL PASS/FAIL TO BUILDPIPER PIPELINE
###############################################
if [ $STATUS -eq 0 ]; then
  logInfoMessage "Congratulations trivy scan succeeded!!!"
  generateOutput ${ACTIVITY_SUB_TASK_CODE} true "$FINAL_MESSAGE"
elif [ "$VALIDATION_FAILURE_ACTION" == "FAILURE" ]; then
    logErrorMessage "Please check trivy scan failed!!!"
    generateOutput ${ACTIVITY_SUB_TASK_CODE} false "$FINAL_MESSAGE"
    exit 1
else
    logWarningMessage "Please check trivy scan failed!!!"
    generateOutput ${ACTIVITY_SUB_TASK_CODE} true "$FINAL_MESSAGE"
fi

saveTaskStatus ${STATUS} ${ACTIVITY_SUB_TASK_CODE}