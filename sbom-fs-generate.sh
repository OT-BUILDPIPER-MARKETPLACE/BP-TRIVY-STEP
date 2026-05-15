#!/bin/bash
source /opt/buildpiper/shell-functions/functions.sh
source /opt/buildpiper/shell-functions/mi-functions.sh
source /opt/buildpiper/shell-functions/log-functions.sh
source /opt/buildpiper/shell-functions/str-functions.sh
source /opt/buildpiper/shell-functions/file-functions.sh
source /opt/buildpiper/shell-functions/aws-functions.sh
source /opt/buildpiper/shell-functions/getDataFile.sh

cd "${WORKSPACE}/${CODEBASE_DIR}"

###############################################
### REPORT DIRECTORY
###############################################
CODEBASE_LOCATION="${WORKSPACE}/${CODEBASE_DIR}"
REPORTS_DIR="${CODEBASE_LOCATION}/reports"

mkdir -p "${REPORTS_DIR}"
chmod -R 777 "${REPORTS_DIR}" || true

logInfoMessage "REPORTS_DIR=${REPORTS_DIR}"


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
SBOM_OUTPUT_FILE="${SBOM_OUTPUT_FILE:-${ACTIVITY_SUB_TASK_CODE}_output.json}"

logInfoMessage "==============================="
logInfoMessage "Generating SBOM for filesystem"
logInfoMessage "==============================="

export application=$APPLICATION_NAME
export environment=$(getProjectEnv)
export service=$(getServiceName)
export organization=$ORGANIZATION
export source_key=$SOURCE_KEY
export report_file_path=$REPORT_FILE_PATH

logInfoMessage "I'll generate SBOM file at [${WORKSPACE}/${CODEBASE_DIR}]"

cd ${WORKSPACE}/${CODEBASE_DIR}

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

STATUS=0

logInfoMessage "I'll generate SBOM for filesystem path ${WORKSPACE}/${CODEBASE_DIR}"
sleep $SLEEP_DURATION

###############################################
### GENERATE SBOM
###############################################
SBOM_REPORT="${EXEC_DIR}/${SBOM_FS_REPORT_NAME}"

logInfoMessage "Executing command"
logInfoMessage "trivy fs --format ${SBOM_FORMAT_ARG} --output ${SBOM_REPORT} ${WORKSPACE}/${CODEBASE_DIR}"

trivy fs --format ${SBOM_FORMAT_ARG} --output "${SBOM_REPORT}" ${WORKSPACE}/${CODEBASE_DIR}
STATUS=$?

if [[ "$STATUS" -eq 0 ]]; then
  add_event "sbom generation" "Successful" "SBOM created" "Trivy successfully generated SBOM at ${SBOM_REPORT}"
  
  # Check if file exists and has content
  if [[ -s "${SBOM_REPORT}" ]]; then
    FILE_SIZE=$(stat -f%z "${SBOM_REPORT}" 2>/dev/null || stat -c%s "${SBOM_REPORT}" 2>/dev/null || echo 0)
    add_event "verify sbom file" "Successful" "File verified" "SBOM file created with size ${FILE_SIZE} bytes"
    
    logInfoMessage "Congratulations! Trivy filesystem SBOM generation succeeded!"
    logInfoMessage "SBOM file: ${SBOM_REPORT}"
    logInfoMessage "===================== Displaying first 50 lines of the SBOM report ====================="
    head -n 50 "${SBOM_REPORT}"
    logInfoMessage "========================================================================================"
  else
    add_event "verify sbom file" "Failed" "File empty or missing" "SBOM file was not created or is empty"
    STATUS=1
  fi
else
  add_event "sbom generation" "Failed" "Trivy execution error" "trivy fs exited with code $STATUS"
fi

###############################################
### DETERMINE FINAL STATUS
###############################################
FINAL_STATUS="Successful"
FINAL_REASON="SBOM generation completed"
FINAL_MESSAGE="Trivy filesystem SBOM generated successfully at ${SBOM_FS_REPORT_NAME}"

if [[ "$STATUS" -ne 0 ]]; then
  FINAL_STATUS="failed"
  FINAL_REASON="SBOM generation failed"
  FINAL_MESSAGE="Trivy filesystem SBOM generation failed"
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
  --arg sbom_format "${SBOM_FORMAT_ARG}" \
  --arg sbom_report "${SBOM_FS_REPORT_NAME}" \
  --arg codebase_path "${WORKSPACE}/${CODEBASE_DIR}" \
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
      sbom_filesystem: {
        status: $final_status,
        reason: $final_reason,
        message: $final_message,
        sbom: {
          format: $sbom_format,
          report_name: $sbom_report,
          codebase_path: $codebase_path
        },
        current_error: (if $final_status == "failed" then $final_reason else "" end),
        error_events: $error_events
      }
    }
  }' > "${EXEC_DIR}/${SBOM_OUTPUT_FILE}"

logInfoMessage "Output JSON written to ${EXEC_DIR}/${SBOM_OUTPUT_FILE}"
add_event "create output" "Successful" "Output file created" "Structured output written to ${SBOM_OUTPUT_FILE}"

###############################################
### GENERATE CSV REPORT
###############################################
SBOM_CSV_REPORT="${EXEC_DIR}/sbom-filesystem-report.csv"

logInfoMessage "Generating CSV report -> ${SBOM_CSV_REPORT}"

echo "Type,Name,Version,PURL,License" > "${SBOM_CSV_REPORT}"

COMPONENT_COUNT=$(jq '.components | length' "${SBOM_REPORT}" 2>/dev/null || echo 0)

if [[ "${COMPONENT_COUNT}" -gt 0 ]]; then

    jq -r '
      .components[]? |
      [
        (.type // "N/A"),
        (.name // "N/A"),
        (.version // "N/A"),
        (.purl // "N/A"),
        (
          if .licenses then
            (.licenses[]?.license.id // .licenses[]?.license.name // "N/A")
          else
            "N/A"
          end
        )
      ] | @csv
    ' "${SBOM_REPORT}" >> "${SBOM_CSV_REPORT}"

    add_event "generate csv report" "Successful" \
    "CSV report generated" \
    "Components exported to CSV"

else

    echo '"N/A","No Components Found","N/A","N/A","N/A"' >> "${SBOM_CSV_REPORT}"

    add_event "generate csv report" "Successful" \
    "No components found" \
    "Generated empty CSV placeholder row"

fi

chmod 777 "${SBOM_CSV_REPORT}" 2>/dev/null || true

###############################################
### COPY CSV REPORT TO REPORTS DIRECTORY
###############################################
REPORTS_CSV="${REPORTS_DIR}/sbom-filesystem-report.csv"

cp -f "${SBOM_CSV_REPORT}" "${REPORTS_CSV}" 2>/dev/null || true
cp -f "${SBOM_REPORT}" "${REPORTS_DIR}/${SBOM_FS_REPORT_NAME}" 2>/dev/null || true
chmod 777 "${REPORTS_CSV}" 2>/dev/null || true

if [[ -f "${REPORTS_CSV}" ]]; then

    add_event "copy csv report" "Successful" \
    "CSV report copied" \
    "Copied to ${REPORTS_CSV}"

    logInfoMessage "CSV report copied to reports directory"

else

    add_event "copy csv report" "Failed" \
    "Failed to copy CSV report" \
    "${REPORTS_CSV}"

    logErrorMessage "Failed to copy CSV report to reports directory"

fi

###############################################
### SIGNAL PASS/FAIL TO BUILDPIPER PIPELINE
###############################################
if [ $STATUS -eq 0 ]; then
  logInfoMessage "Congratulations! Trivy filesystem SBOM generation succeeded!"
  generateOutput ${ACTIVITY_SUB_TASK_CODE} true "$FINAL_MESSAGE"
elif [ "$VALIDATION_FAILURE_ACTION" == "FAILURE" ]; then
    logErrorMessage "Please check Trivy SBOM generation failed!"
    generateOutput ${ACTIVITY_SUB_TASK_CODE} false "$FINAL_MESSAGE"
    exit 1
else
    logWarningMessage "Trivy scan failed, but the step is configured as NON-BLOCKING (warning mode).

  If you want the pipeline to FAIL on leaks:
  - Go to job template settings
  - Set VALIDATION_FAILURE_ACTION = FAILURE

  Current setting allows pipeline to continue."
    add_event "validation mode" "Successful" "Non-blocking validation" "Scan failed but pipeline continued because VALIDATION_FAILURE_ACTION is not FAILURE"
    generateOutput ${ACTIVITY_SUB_TASK_CODE} false "$FINAL_MESSAGE"  
fi

saveTaskStatus ${STATUS} ${ACTIVITY_SUB_TASK_CODE}