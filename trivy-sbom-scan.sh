#!/usr/bin/env bash

set -euo pipefail

source /opt/buildpiper/shell-functions/functions.sh
source /opt/buildpiper/shell-functions/log-functions.sh
source /opt/buildpiper/shell-functions/file-functions.sh
source /opt/buildpiper/shell-functions/str-functions.sh
source /opt/buildpiper/shell-functions/getDataFile.sh

###############################################
### DEBUG
###############################################
if [[ "${DEBUG:-false}" == "true" ]]; then
  set -x
fi

###############################################
### INITIALIZATION
###############################################
CODEBASE_LOCATION="${WORKSPACE}/${CODEBASE_DIR}"
REPORTS_DIR="${CODEBASE_LOCATION}/reports"

mkdir -p "${REPORTS_DIR}"
chmod -R 777 "${REPORTS_DIR}" 2>/dev/null || true

logInfoMessage "REPORTS_DIR=${REPORTS_DIR}"

cd "${CODEBASE_LOCATION}"

###############################################
### EVENTS TRACKING
###############################################
EVENTS='{}'

add_event() {

  local key="${1:-}"
  local status="${2:-}"
  local reason="${3:-}"
  local message="${4:-}"

  if [[ -z "$key" || -z "$status" ]]; then
    echo "Error: add_event requires key and status" >&2
    return 1
  fi

  key="$(echo "$key" | tr '_' ' ' | tr '-' ' ' | tr '[:upper:]' '[:lower:]')"

  EVENTS=$(jq \
    --arg k "$key" \
    --arg status "$status" \
    --arg reason "$reason" \
    --arg message "$message" \
    '. + {($k): {status: $status, reason: $reason, message: $message}}' \
    <<< "$EVENTS")
}

###############################################
### OUTPUT FILES
###############################################
SBOM_SCAN_OUTPUT_FILE="${SBOM_SCAN_OUTPUT_FILE:-${ACTIVITY_SUB_TASK_CODE}_output.json}"

OUTPUT_CSV="${OUTPUT_CSV:-sbom_image_scan_report.csv}"

###############################################
### THRESHOLD CONFIGURATION
###############################################
SBOM_THRESHOLD_CRITICAL="${SBOM_THRESHOLD_CRITICAL:-0}"
SBOM_THRESHOLD_HIGH="${SBOM_THRESHOLD_HIGH:--1}"
SBOM_THRESHOLD_MEDIUM="${SBOM_THRESHOLD_MEDIUM:--1}"
SBOM_THRESHOLD_LOW="${SBOM_THRESHOLD_LOW:--1}"
SBOM_THRESHOLD_TOTAL="${SBOM_THRESHOLD_TOTAL:--1}"

VALIDATION_ACTION="${VALIDATION_FAILURE_ACTION:-FAILURE}"

###############################################
### LOGGING
###############################################
logInfoMessage "======================================="
logInfoMessage "Starting Trivy SBOM Scan"
logInfoMessage "======================================="

###############################################
### CREATE EXECUTION DIRECTORY
###############################################
if [[ -n "${GLOBAL_TASK_ID:-}" ]]; then

    EXEC_DIR="/bp/execution_dir/${GLOBAL_TASK_ID}"

    mkdir -p "${EXEC_DIR}"

    chmod -R 777 "${EXEC_DIR}" 2>/dev/null || true

    add_event "create execution dir" "Successful" \
    "Directory created" \
    "Created ${EXEC_DIR}"

else

    logErrorMessage "GLOBAL_TASK_ID not set"

    add_event "create execution dir" "Failed" \
    "GLOBAL_TASK_ID missing" \
    "Cannot create execution directory"

    exit 1
fi

###############################################
### REPORT FILES
###############################################
JSON_OUTPUT_PATH="${EXEC_DIR}/${SBOM_SCAN_REPORT_NAME}"

CSV_OUTPUT_PATH="${EXEC_DIR}/${OUTPUT_CSV}"

STATUS=0

sleep "${SLEEP_DURATION:-0}"

###############################################
### RESOLVE IMAGE DETAILS
###############################################
if [[ -z "${IMAGE_NAME:-}" || -z "${IMAGE_TAG:-}" ]]; then

    logInfoMessage "Fetching image details from BP data"

    IMAGE_NAME=$(getImageName)
    IMAGE_TAG=$(getImageTag)
fi

if [[ -z "${IMAGE_NAME:-}" || -z "${IMAGE_TAG:-}" ]]; then

    logErrorMessage "Unable to resolve IMAGE_NAME or IMAGE_TAG"

    add_event "resolve image" "Failed" \
    "Image resolution failed" \
    "IMAGE_NAME or IMAGE_TAG could not be resolved"

    generateOutput "${ACTIVITY_SUB_TASK_CODE}" false \
    "Image name/tag could not be resolved"

    exit 1
fi

FULL_IMAGE="${IMAGE_NAME}:${IMAGE_TAG}"

logInfoMessage "Image Name -> ${IMAGE_NAME}"
logInfoMessage "Image Tag  -> ${IMAGE_TAG}"

add_event "resolve image" "Successful" \
"Image resolved" \
"${FULL_IMAGE}"

###############################################
### VERIFY SBOM FILE EXISTS
###############################################
SBOM_INPUT="${EXEC_DIR}/${SBOM_REPORT_NAME}"

if [[ ! -f "${SBOM_INPUT}" ]]; then

    logErrorMessage "SBOM file not found: ${SBOM_INPUT}"

    add_event "verify sbom input" "Failed" \
    "SBOM file missing" \
    "Expected SBOM file at ${SBOM_INPUT} not found"

    generateOutput "${ACTIVITY_SUB_TASK_CODE}" false \
    "SBOM file not found"

    exit 1
fi

add_event "verify sbom input" "Successful" \
"SBOM file found" \
"${SBOM_INPUT}"

###############################################
### RUN TRIVY SBOM SCAN
###############################################
logInfoMessage "Executing Trivy SBOM scan"

logInfoMessage "Command:"
logInfoMessage "trivy sbom -q -f ${SBOM_SCAN_FORMAT} --output ${JSON_OUTPUT_PATH} ${SBOM_INPUT}"

set +e

trivy sbom \
  -q \
  -f "${SBOM_SCAN_FORMAT}" \
  --output "${JSON_OUTPUT_PATH}" \
  "${SBOM_INPUT}"

STATUS=$?

set -e

chmod 777 "${JSON_OUTPUT_PATH}" 2>/dev/null || true

logInfoMessage "Trivy SBOM scan completed with exit code ${STATUS}"

###############################################
### HANDLE TRIVY STATUS
###############################################
if [[ "${STATUS}" -eq 0 ]]; then

    add_event "sbom scan" "Successful" \
    "SBOM scan completed" \
    "Trivy successfully scanned SBOM"

else

    add_event "sbom scan" "Failed" \
    "Trivy SBOM scan failed" \
    "trivy sbom exited with code ${STATUS}"

    generateOutput "${ACTIVITY_SUB_TASK_CODE}" false \
    "Trivy SBOM scan failed"

    exit 1
fi

###############################################
### VERIFY REPORT
###############################################
if [[ -s "${JSON_OUTPUT_PATH}" ]]; then

    FILE_SIZE=$(stat -f%z "${JSON_OUTPUT_PATH}" 2>/dev/null || stat -c%s "${JSON_OUTPUT_PATH}" 2>/dev/null || echo 0)

    add_event "verify report" "Successful" \
    "Report verified" \
    "Report generated with size ${FILE_SIZE} bytes"

else

    add_event "verify report" "Failed" \
    "Report missing" \
    "SBOM JSON report not generated"

    generateOutput "${ACTIVITY_SUB_TASK_CODE}" false \
    "SBOM JSON report missing"

    exit 1
fi

###############################################
### PARSE RESULTS
###############################################
CRITICAL=$(jq '([.Results[]? .Vulnerabilities[]? | select(.Severity=="CRITICAL")] | length)' "${JSON_OUTPUT_PATH}" 2>/dev/null || echo 0)

HIGH=$(jq '([.Results[]? .Vulnerabilities[]? | select(.Severity=="HIGH")] | length)' "${JSON_OUTPUT_PATH}" 2>/dev/null || echo 0)

MEDIUM=$(jq '([.Results[]? .Vulnerabilities[]? | select(.Severity=="MEDIUM")] | length)' "${JSON_OUTPUT_PATH}" 2>/dev/null || echo 0)

LOW=$(jq '([.Results[]? .Vulnerabilities[]? | select(.Severity=="LOW")] | length)' "${JSON_OUTPUT_PATH}" 2>/dev/null || echo 0)

TOTAL=$(jq '([.Results[]? .Vulnerabilities[]?] | length)' "${JSON_OUTPUT_PATH}" 2>/dev/null || echo 0)

logInfoMessage "CRITICAL=${CRITICAL}"
logInfoMessage "HIGH=${HIGH}"
logInfoMessage "MEDIUM=${MEDIUM}"
logInfoMessage "LOW=${LOW}"
logInfoMessage "TOTAL=${TOTAL}"

add_event "parse scan results" "Successful" \
"Metrics extracted" \
"CRITICAL=${CRITICAL} HIGH=${HIGH} MEDIUM=${MEDIUM} LOW=${LOW} TOTAL=${TOTAL}"

###############################################
### GENERATE CSV REPORT
###############################################
logInfoMessage "Generating CSV report -> ${CSV_OUTPUT_PATH}"

echo "VulnerabilityID,PkgName,InstalledVersion,FixedVersion,Severity,Criticality,Title" > "${CSV_OUTPUT_PATH}"

if [[ "${TOTAL}" -gt 0 ]]; then

    jq -r '
      def severityRank(s):
        if s == "CRITICAL" then 5
        elif s == "HIGH" then 4
        elif s == "MEDIUM" then 3
        elif s == "LOW" then 2
        else 1 end;

      def criticalityRank(c):
        if c == "HIGH" or c == "high" then 3
        elif c == "MEDIUM" or c == "medium" then 2
        elif c == "LOW" or c == "low" then 1
        else 0 end;

      (
        ( .Results // [] | map(.Vulnerabilities // []) | add // [] )
        | sort_by(
            -severityRank(.Severity),
            -criticalityRank(.Criticality)
          )
        | .[]
        | [
            (.VulnerabilityID // "N/A"),
            (.PkgName // "N/A"),
            (.InstalledVersion // "N/A"),
            (.FixedVersion // "N/A"),
            (.Severity // "N/A"),
            (.Criticality // "N/A"),
            (.Title // "N/A" | gsub("[\n\r]"; " "))
          ]
      )
      | @csv
    ' "${JSON_OUTPUT_PATH}" >> "${CSV_OUTPUT_PATH}" || true

    add_event "generate csv report" "Successful" \
    "CSV report generated" \
    "Vulnerabilities exported to CSV"

else

    echo '"No vulnerabilities","N/A","N/A","N/A","N/A","N/A","Clean image"' >> "${CSV_OUTPUT_PATH}"

    add_event "generate csv report" "Successful" \
    "No vulnerabilities found" \
    "Generated clean report"
fi

chmod 777 "${CSV_OUTPUT_PATH}" 2>/dev/null || true

###############################################
### DISPLAY CSV REPORT
###############################################
if [[ -s "${CSV_OUTPUT_PATH}" ]]; then

    logInfoMessage "Displaying SBOM Scan Report"

    python3 /opt/buildpiper/shell-functions/print_table.py "${CSV_OUTPUT_PATH}" \
      || head -n 50 "${CSV_OUTPUT_PATH}"
fi

###############################################
### COPY REPORTS TO REPORTS DIRECTORY
###############################################
cp -f "${JSON_OUTPUT_PATH}" "${REPORTS_DIR}/" 2>/dev/null || true

cp -f "${CSV_OUTPUT_PATH}" "${REPORTS_DIR}/" 2>/dev/null || true

chmod -R 777 "${REPORTS_DIR}" 2>/dev/null || true

add_event "copy reports" "Successful" \
"Reports copied" \
"Reports copied to ${REPORTS_DIR}"

###############################################
### COPY REPORTS TO EXECUTION DIRECTORY
###############################################
cp -f "${JSON_OUTPUT_PATH}" "${EXEC_DIR}/" 2>/dev/null || true

cp -f "${CSV_OUTPUT_PATH}" "${EXEC_DIR}/" 2>/dev/null || true

chmod -R 777 "${EXEC_DIR}" 2>/dev/null || true

###############################################
### THRESHOLD CHECKS
###############################################
THRESHOLD_STATUS=0

check_threshold() {

    local severity="$1"
    local detected="$2"
    local threshold="$3"

    if [[ "${threshold}" == "-1" ]]; then
        return 0
    fi

    if [[ "${detected}" -gt "${threshold}" ]]; then

        logErrorMessage "${severity} threshold breached"

        add_event "threshold ${severity}" "Failed" \
        "${severity} threshold breached" \
        "Detected=${detected} Allowed=${threshold}"

        THRESHOLD_STATUS=1

    else

        add_event "threshold ${severity}" "Successful" \
        "Threshold within limit" \
        "Detected=${detected} Allowed=${threshold}"
    fi
}

check_threshold "critical" "${CRITICAL}" "${SBOM_THRESHOLD_CRITICAL}"
check_threshold "high" "${HIGH}" "${SBOM_THRESHOLD_HIGH}"
check_threshold "medium" "${MEDIUM}" "${SBOM_THRESHOLD_MEDIUM}"
check_threshold "low" "${LOW}" "${SBOM_THRESHOLD_LOW}"
check_threshold "total" "${TOTAL}" "${SBOM_THRESHOLD_TOTAL}"

if [[ "${THRESHOLD_STATUS}" -ne 0 ]]; then
    STATUS=1
fi

###############################################
### FINAL STATUS
###############################################
FINAL_MESSAGE="CRITICAL=${CRITICAL} HIGH=${HIGH} MEDIUM=${MEDIUM} LOW=${LOW} TOTAL=${TOTAL}"

if [[ "${STATUS}" -eq 0 ]]; then

    FINAL_STATUS="Successful"

    add_event "scan summary" "Successful" \
    "SBOM scan completed successfully" \
    "${FINAL_MESSAGE}"

else

    FINAL_STATUS="Failed"

    add_event "scan summary" "Failed" \
    "Threshold breached" \
    "${FINAL_MESSAGE}"
fi

###############################################
### ERROR EVENTS
###############################################
ERROR_EVENTS=$(echo "$EVENTS" | jq '[to_entries[] | select(.value.status == "Failed") | .key]')

###############################################
### OUTPUT JSON
###############################################
jq -n \
  --argjson events "$EVENTS" \
  --argjson error_events "$ERROR_EVENTS" \
  --arg final_status "$FINAL_STATUS" \
  --arg final_message "$FINAL_MESSAGE" \
  --arg image_name "${IMAGE_NAME}" \
  --arg image_tag "${IMAGE_TAG}" \
  --arg critical "${CRITICAL}" \
  --arg high "${HIGH}" \
  --arg medium "${MEDIUM}" \
  --arg low "${LOW}" \
  --arg total "${TOTAL}" \
'{
  build: {
    status: ($final_status == "Successful"),
    message: $final_message,
    events: $events,
    error_events: $error_events
  },
  output_vars: {
    sbom_scan: {
      status: $final_status,
      message: $final_message,
      image: {
        name: $image_name,
        tag: $image_tag
      },
      vulnerabilities: {
        critical: ($critical|tonumber),
        high: ($high|tonumber),
        medium: ($medium|tonumber),
        low: ($low|tonumber),
        total: ($total|tonumber)
      }
    }
  }
}' > "${EXEC_DIR}/${SBOM_SCAN_OUTPUT_FILE}"

chmod 777 "${EXEC_DIR}/${SBOM_SCAN_OUTPUT_FILE}" 2>/dev/null || true

logInfoMessage "Output written -> ${EXEC_DIR}/${SBOM_SCAN_OUTPUT_FILE}"

###############################################
### FINAL SUMMARY
###############################################
echo "========================================="
echo "Trivy SBOM Scan Summary"
echo "${FINAL_MESSAGE}"
echo "========================================="

logInfoMessage "========================================="
logInfoMessage "Trivy SBOM Scan Summary"
logInfoMessage "${FINAL_MESSAGE}"
logInfoMessage "========================================="

###############################################
### PIPELINE STATUS
###############################################
if [[ "${STATUS}" -eq 0 ]]; then

    logInfoMessage "Trivy SBOM scan completed successfully"

    generateOutput "${ACTIVITY_SUB_TASK_CODE}" true \
    "${FINAL_MESSAGE}"

else

    if [[ "${VALIDATION_ACTION}" == "FAILURE" ]]; then

        logErrorMessage "Trivy SBOM scan failed"

        generateOutput "${ACTIVITY_SUB_TASK_CODE}" false \
        "${FINAL_MESSAGE}"

        exit 1

    else

        logWarningMessage "Validation failure ignored due to NON-BLOCKING mode"

        add_event "validation mode" "Successful" \
        "Non-blocking validation" \
        "Pipeline continued despite threshold breach"

        generateOutput "${ACTIVITY_SUB_TASK_CODE}" false \
        "${FINAL_MESSAGE}"
    fi
fi

###############################################
### SAVE TASK STATUS
###############################################
saveTaskStatus "${STATUS}" "${ACTIVITY_SUB_TASK_CODE}"

exit 0