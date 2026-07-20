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
SBOM_OUTPUT_FILE="${SBOM_OUTPUT_FILE:-${ACTIVITY_SUB_TASK_CODE}_output.json}"

logInfoMessage "==============================="
logInfoMessage "Generating filesystem HTML scan report"
logInfoMessage "==============================="

export application=$APPLICATION_NAME
export environment=$(getProjectEnv)
export service=$(getServiceName)
export organization=$ORGANIZATION
export source_key=$SOURCE_KEY
export report_file_path=$REPORT_FILE_PATH

logInfoMessage "Working directory: ${WORKSPACE}/${CODEBASE_DIR}"

cd "${WORKSPACE}/${CODEBASE_DIR}" || exit 1

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

logInfoMessage "Filesystem path: ${WORKSPACE}/${CODEBASE_DIR}"
sleep "${SLEEP_DURATION}"

###############################################
### GENERATE HTML REPORT
###############################################
SBOM_REPORT="${EXEC_DIR}/sbom.html"

logInfoMessage "Executing Trivy filesystem scan"

#logInfoMessage "trivy fs --scanners vuln,secret,misconfig,license --format template --template  @/opt/trivy.tpl --output ${SBOM_REPORT} ${WORKSPACE}/${CODEBASE_DIR}"
logInfoMessage "trivy fs --scanners vuln,misconfig,secret,license --security-checks vuln,config,secret,license --format template --template  @/opt/trivy.tpl --skip-db-update --output ${EXEC_DIR}/sbom.html ${WORKSPACE}/${CODEBASE_DIR}"
#trivy fs \
 # --scanners vuln,secret,misconfig,license \
  #--format template \
  #--template "@/contrib/html.tpl" \
  #--output "${SBOM_REPORT}" \
  #"${WORKSPACE}/${CODEBASE_DIR}"
#trivy fs \
 # --scanners vuln,misconfig,secret,license \
 # --security-checks vuln,config,secret,license \
 # --format template \
 # --template "@/contrib/html.tpl" \
 # --output "${EXEC_DIR}/sbom.html" \
 # "${WORKSPACE}/${CODEBASE_DIR}"
logInfoMessage "trivy fs --pkg-types os,library --scanners vuln,misconfig,secret,license --license-full --format template --template @/opt/trivy.tpl --skip-db-update --output ${EXEC_DIR}/sbom.html ${WORKSPACE}/${CODEBASE_DIR}"

#trivy fs \
 # --pkg-types os,library \
  #--scanners vuln,misconfig,secret,license \
  #--license-full \
  #--format template \
  #--template "@/contrib/html.tpl" \
  #--output "${EXEC_DIR}/sbom.html" \
  #"${WORKSPACE}/${CODEBASE_DIR}"

TRIVY_TIMEOUT="${TRIVY_TIMEOUT:-60m}"

trivy fs \
  --timeout "${TRIVY_TIMEOUT}" \
  --pkg-types os,library \
  --scanners vuln,misconfig,secret,license \
  --license-full \
  --format template \
  --template "@/opt/trivy.tpl" \
  --skip-db-update \
  --output "${SBOM_REPORT}" \
  "${WORKSPACE}/${CODEBASE_DIR}"

STATUS=$?
###############################################
### VERIFY REPORT
###############################################
if [[ "$STATUS" -eq 0 ]]; then

  add_event \
    "sbom generation" \
    "Successful" \
    "HTML report created" \
    "Trivy successfully generated HTML report at ${SBOM_REPORT}"

  if [[ -s "${SBOM_REPORT}" ]]; then

    ZIP_REPORT="${EXEC_DIR}/sbom.html.zip"

    if zip -j "${ZIP_REPORT}" "${SBOM_REPORT}" >/dev/null; then
        rm -f "${SBOM_REPORT}"
        SBOM_REPORT="${ZIP_REPORT}"

        FILE_SIZE=$(stat -f%z "${SBOM_REPORT}" 2>/dev/null || \
                    stat -c%s "${SBOM_REPORT}" 2>/dev/null || \
                    echo 0)

        add_event \
          "verify sbom file" \
          "Successful" \
          "File verified" \
          "ZIP report created with size ${FILE_SIZE} bytes"

        logInfoMessage "Congratulations! Trivy filesystem scan succeeded!"
        logInfoMessage "ZIP Report generated at: ${SBOM_REPORT}"
    else
        logErrorMessage "Failed to create ZIP report"
        STATUS=1
    fi

  else

    add_event \
      "verify sbom file" \
      "Failed" \
      "File empty or missing" \
      "HTML report was not created or is empty"

    STATUS=1
  fi

else

  add_event \
    "sbom generation" \
    "Failed" \
    "Trivy execution error" \
    "trivy fs exited with code ${STATUS}"

fi

###############################################
### DETERMINE FINAL STATUS
###############################################
FINAL_STATUS="Successful"
FINAL_REASON="Filesystem scan completed"
FINAL_MESSAGE="Trivy filesystem HTML report generated successfully"

if [[ "$STATUS" -ne 0 ]]; then
  FINAL_STATUS="failed"
  FINAL_REASON="Filesystem scan failed"
  FINAL_MESSAGE="Trivy filesystem scan failed"
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
### CREATE OUTPUT JSON
###############################################
jq -n \
  --argjson events "$EVENTS" \
  --argjson error_events "$ERROR_EVENTS" \
  --argjson status_bool "$STATUS_BOOL" \
  --arg final_status "$FINAL_STATUS" \
  --arg final_reason "$FINAL_REASON" \
  --arg final_message "$FINAL_MESSAGE" \
  --arg report_name "sbom.html.zip" \
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
        report: {
          name: $report_name,
          codebase_path: $codebase_path
        },
        current_error: (if $final_status == "failed" then $final_reason else "" end),
        error_events: $error_events
      }
    }
  }' > "${EXEC_DIR}/${SBOM_OUTPUT_FILE}"

###############################################
### OUTPUT CREATED
###############################################
logInfoMessage "Output JSON written to ${EXEC_DIR}/${SBOM_OUTPUT_FILE}"

add_event \
  "create output" \
  "Successful" \
  "Output file created" \
  "Structured output written to ${SBOM_OUTPUT_FILE}"

###############################################
### SIGNAL PASS/FAIL
###############################################
if [ "$STATUS" -eq 0 ]; then

  logInfoMessage "Congratulations! Trivy filesystem scan succeeded!"

  generateOutput \
    "${ACTIVITY_SUB_TASK_CODE}" \
    true \
    "${FINAL_MESSAGE}"

elif [ "${VALIDATION_FAILURE_ACTION}" == "FAILURE" ]; then

    logErrorMessage "Please check Trivy filesystem scan failed!"

    generateOutput \
      "${ACTIVITY_SUB_TASK_CODE}" \
      false \
      "${FINAL_MESSAGE}"

    exit 1

else

    logWarningMessage "Trivy scan failed, but pipeline is configured as NON-BLOCKING."

    add_event \
      "validation mode" \
      "Successful" \
      "Non-blocking validation" \
      "Scan failed but pipeline continued because VALIDATION_FAILURE_ACTION is not FAILURE"

    generateOutput \
      "${ACTIVITY_SUB_TASK_CODE}" \
      false \
      "${FINAL_MESSAGE}"
fi

###############################################
### SAVE TASK STATUS
###############################################
saveTaskStatus "${STATUS}" "${ACTIVITY_SUB_TASK_CODE}"
