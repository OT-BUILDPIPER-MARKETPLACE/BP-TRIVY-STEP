#!/usr/bin/env bash

set -euo pipefail

source /opt/buildpiper/shell-functions/functions.sh
source /opt/buildpiper/shell-functions/mi-functions.sh
source /opt/buildpiper/shell-functions/log-functions.sh
source /opt/buildpiper/shell-functions/str-functions.sh
source /opt/buildpiper/shell-functions/file-functions.sh
source /opt/buildpiper/shell-functions/aws-functions.sh
source /opt/buildpiper/shell-functions/getDataFile.sh
source ./login.sh

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
### OUTPUT FILE
###############################################
TRIVY_OUTPUT_FILE="${TRIVY_OUTPUT_FILE:-${ACTIVITY_SUB_TASK_CODE}_output.json}"

###############################################
### THRESHOLD CONFIGURATION
###############################################
TRIVY_THRESHOLD_CRITICAL="${TRIVY_THRESHOLD_CRITICAL:-0}"
TRIVY_THRESHOLD_HIGH="${TRIVY_THRESHOLD_HIGH:--1}"
TRIVY_THRESHOLD_MEDIUM="${TRIVY_THRESHOLD_MEDIUM:--1}"
TRIVY_THRESHOLD_LOW="${TRIVY_THRESHOLD_LOW:--1}"
TRIVY_THRESHOLD_TOTAL="${TRIVY_THRESHOLD_TOTAL:--1}"

VALIDATION_ACTION="${VALIDATION_FAILURE_ACTION:-FAILURE}"

###############################################
### LOGGING
###############################################
logInfoMessage "======================================="
logInfoMessage "Starting Trivy Image Scan (Daemonless)"
logInfoMessage "======================================="

export application="${APPLICATION_NAME:-}"
export environment="$(getProjectEnv)"
export service="$(getServiceName)"
export organization="${ORGANIZATION:-}"
export source_key="${SOURCE_KEY:-}"
export report_file_path="${REPORT_FILE_PATH:-}"

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
JSON_REPORT="${EXEC_DIR}/trivy-image-sbom-gen-results.json"

HTML_REPORT="${EXEC_DIR}/trivy-image-sbom-gen-results.html"

REPORT_CSV="${REPORT_CSV:-trivy-image-sbom-gen-report.csv}"

CSV_REPORT="${EXEC_DIR}/${REPORT_CSV}"

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
### REGISTRY LOGIN
###############################################
logInfoMessage "Logging into configured registries"

if login_all_registries; then

    add_event "registry login" "Successful" \
    "Registry login completed" \
    "Authenticated successfully"

else

    add_event "registry login" "Failed" \
    "Registry login failed" \
    "Unable to authenticate"

    generateOutput "${ACTIVITY_SUB_TASK_CODE}" false \
    "Registry login failed"

    exit 1
fi

###############################################
### VALIDATE IMAGE ACCESSIBILITY
###############################################
logInfoMessage "Validating image accessibility"

if ! skopeo inspect "docker://${FULL_IMAGE}" >/dev/null 2>&1; then

    logErrorMessage "Unable to access image from registry"

    add_event "image validation" "Failed" \
    "Registry access failed" \
    "Could not access ${FULL_IMAGE}"

    generateOutput "${ACTIVITY_SUB_TASK_CODE}" false \
    "Unable to access image from registry"

    exit 1
fi

add_event "image validation" "Successful" \
"Image accessible" \
"${FULL_IMAGE} is accessible"

###############################################
### TRIVY CACHE
###############################################
export TRIVY_CACHE_DIR="/tmp/trivy-cache"

mkdir -p "${TRIVY_CACHE_DIR}"

chmod -R 777 "${TRIVY_CACHE_DIR}" 2>/dev/null || true

logInfoMessage "TRIVY_CACHE_DIR=${TRIVY_CACHE_DIR}"

###############################################
### RUN TRIVY SCAN
###############################################
logInfoMessage "Executing Trivy image scan"

logInfoMessage "Command:"
logInfoMessage "trivy image --format json -o ${JSON_REPORT} ${FULL_IMAGE}"

set +e

trivy image \
  -q \
  --timeout 30m \
  --scanners vuln \
  --severity "${SCAN_SEVERITY}" \
  --format json \
  -o "${JSON_REPORT}" \
  "${FULL_IMAGE}"

STATUS=$?

set -e

chmod 777 "${JSON_REPORT}" 2>/dev/null || true

logInfoMessage "Trivy completed with exit code ${STATUS}"

###############################################
### HANDLE TRIVY STATUS
###############################################
if [[ "${STATUS}" -eq 0 ]]; then

    add_event "trivy scan" "Successful" \
    "No vulnerabilities detected" \
    "Trivy completed successfully"

elif [[ "${STATUS}" -eq 1 ]]; then

    add_event "trivy scan" "Successful" \
    "Vulnerabilities detected" \
    "Trivy found vulnerabilities"

else

    add_event "trivy scan" "Failed" \
    "Trivy execution failed" \
    "Unexpected trivy exit code ${STATUS}"

    generateOutput "${ACTIVITY_SUB_TASK_CODE}" false \
    "Trivy execution failed"

    exit 1
fi

###############################################
### VERIFY REPORT
###############################################
if [[ -s "${JSON_REPORT}" ]]; then

    FILE_SIZE=$(stat -f%z "${JSON_REPORT}" 2>/dev/null || stat -c%s "${JSON_REPORT}" 2>/dev/null || echo 0)

    add_event "verify report" "Successful" \
    "Report verified" \
    "Report generated with size ${FILE_SIZE} bytes"

else

    add_event "verify report" "Failed" \
    "Report missing" \
    "JSON report not generated"

    generateOutput "${ACTIVITY_SUB_TASK_CODE}" false \
    "JSON report missing"

    exit 1
fi

###############################################
### GENERATE HTML REPORT
###############################################
if [[ "${REPORT_TYPE:-json}" == "html" || "${REPORT_TYPE:-json}" == "both" ]]; then

    logInfoMessage "Generating HTML report"

    trivy image \
      -q \
      --timeout 30m \
      --scanners vuln \
      --severity "${SCAN_SEVERITY}" \
      --format template \
      --template @/contrib/html.tpl \
      -o "${HTML_REPORT}" \
      "${FULL_IMAGE}"

    chmod 777 "${HTML_REPORT}" 2>/dev/null || true

    add_event "generate html report" "Successful" \
    "HTML report generated" \
    "${HTML_REPORT}"
fi

###############################################
### PARSE RESULTS
###############################################
CRITICAL=$(jq '([.Results[]? .Vulnerabilities[]? | select(.Severity=="CRITICAL")] | length)' "${JSON_REPORT}" 2>/dev/null || echo 0)

HIGH=$(jq '([.Results[]? .Vulnerabilities[]? | select(.Severity=="HIGH")] | length)' "${JSON_REPORT}" 2>/dev/null || echo 0)

MEDIUM=$(jq '([.Results[]? .Vulnerabilities[]? | select(.Severity=="MEDIUM")] | length)' "${JSON_REPORT}" 2>/dev/null || echo 0)

LOW=$(jq '([.Results[]? .Vulnerabilities[]? | select(.Severity=="LOW")] | length)' "${JSON_REPORT}" 2>/dev/null || echo 0)

TOTAL=$(jq '([.Results[]? .Vulnerabilities[]?] | length)' "${JSON_REPORT}" 2>/dev/null || echo 0)

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
logInfoMessage "Generating CSV report -> ${CSV_REPORT}"

echo "Library,CVE_ID,Severity,InstalledVersion,FixedVersion,Title" > "${CSV_REPORT}"

if [[ "${TOTAL}" -gt 0 ]]; then

    jq -r '
      .Results[]?
      | select(.Vulnerabilities != null)
      | .Vulnerabilities[]?
      | [
          (.PkgName // "N/A"),
          (.VulnerabilityID // "N/A"),
          (.Severity // "N/A"),
          (.InstalledVersion // "N/A"),
          (.FixedVersion // "N/A"),
          (.Title // "N/A")
        ]
      | @csv
    ' "${JSON_REPORT}" >> "${CSV_REPORT}" || true

    add_event "generate csv report" "Successful" \
    "CSV report generated" \
    "Vulnerabilities exported to CSV"

else

    echo '"No vulnerabilities","N/A","N/A","N/A","N/A","Clean image"' >> "${CSV_REPORT}"

    add_event "generate csv report" "Successful" \
    "No vulnerabilities found" \
    "Generated clean report"
fi

chmod 777 "${CSV_REPORT}" 2>/dev/null || true

###############################################
### COPY REPORTS TO REPORTS DIRECTORY
###############################################
cp -f "${JSON_REPORT}" "${REPORTS_DIR}/" 2>/dev/null || true

cp -f "${CSV_REPORT}" "${REPORTS_DIR}/" 2>/dev/null || true

if [[ -f "${HTML_REPORT}" ]]; then
    cp -f "${HTML_REPORT}" "${REPORTS_DIR}/" 2>/dev/null || true
fi

chmod -R 777 "${REPORTS_DIR}" 2>/dev/null || true

add_event "copy reports" "Successful" \
"Reports copied" \
"Reports copied to ${REPORTS_DIR}"

###############################################
### COPY REPORTS TO EXECUTION DIRECTORY
###############################################
cp -f "${JSON_REPORT}" "${EXEC_DIR}/" 2>/dev/null || true
cp -f "${CSV_REPORT}" "${EXEC_DIR}/" 2>/dev/null || true

if [[ -f "${HTML_REPORT}" ]]; then
    cp -f "${HTML_REPORT}" "${EXEC_DIR}/" 2>/dev/null || true
fi

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

check_threshold "critical" "${CRITICAL}" "${TRIVY_THRESHOLD_CRITICAL}"
check_threshold "high" "${HIGH}" "${TRIVY_THRESHOLD_HIGH}"
check_threshold "medium" "${MEDIUM}" "${TRIVY_THRESHOLD_MEDIUM}"
check_threshold "low" "${LOW}" "${TRIVY_THRESHOLD_LOW}"
check_threshold "total" "${TOTAL}" "${TRIVY_THRESHOLD_TOTAL}"

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
    "Scan completed successfully" \
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
    trivy_image_scan: {
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
}' > "${EXEC_DIR}/${TRIVY_OUTPUT_FILE}"

chmod 777 "${EXEC_DIR}/${TRIVY_OUTPUT_FILE}" 2>/dev/null || true

logInfoMessage "Output written -> ${EXEC_DIR}/${TRIVY_OUTPUT_FILE}"

###############################################
### FINAL SUMMARY
###############################################
echo "========================================="
echo "Trivy Image Scan Summary"
echo "${FINAL_MESSAGE}"
echo "========================================="

logInfoMessage "========================================="
logInfoMessage "Trivy Image Scan Summary"
logInfoMessage "${FINAL_MESSAGE}"
logInfoMessage "========================================="

###############################################
### PIPELINE STATUS
###############################################
if [[ "${STATUS}" -eq 0 ]]; then

    logInfoMessage "Trivy image scan completed successfully"

    generateOutput "${ACTIVITY_SUB_TASK_CODE}" true \
    "${FINAL_MESSAGE}"

else

    if [[ "${VALIDATION_ACTION}" == "FAILURE" ]]; then

        logErrorMessage "Trivy image scan failed"

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