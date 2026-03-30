#!/bin/bash

source /opt/buildpiper/shell-functions/functions.sh
source /opt/buildpiper/shell-functions/log-functions.sh
source /opt/buildpiper/shell-functions/file-functions.sh
source /opt/buildpiper/shell-functions/str-functions.sh
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
SBOM_SCAN_OUTPUT_FILE="${SBOM_SCAN_OUTPUT_FILE:-${ACTIVITY_SUB_TASK_CODE}_output.json}"
OUTPUT_CSV="${OUTPUT_CSV:-sbom_scan_report.csv}"

logInfoMessage "================================="
logInfoMessage "Start SBOM image scan step"
logInfoMessage "================================="

logInfoMessage "I'll generate report at [${WORKSPACE}/${CODEBASE_DIR}]"

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

###############################################
### RESOLVE IMAGE NAME AND TAG
###############################################
if [ -z "$IMAGE_NAME" ] || [ -z "$IMAGE_TAG" ]; then
    logInfoMessage "Image name/tag is not provided in env variable, checking BP data"
    IMAGE_NAME=$(getImageName)
    IMAGE_TAG=$(getImageTag)
    IMAGE_REGION=$(echo "$IMAGE_NAME" | awk -F'.' '{print $(NF-2)}')
    
    logInfoMessage "Image Region -> ${IMAGE_REGION}"
    logInfoMessage "Image Name -> ${IMAGE_NAME}"
    logInfoMessage "Image Tag -> ${IMAGE_TAG}"
fi

if [ -z "$IMAGE_NAME" ] || [ -z "$IMAGE_TAG" ]; then
    logErrorMessage "Image name/tag is not available in BP data as well. Please check!"
    add_event "resolve image" "Failed" "Image name/tag missing" "IMAGE_NAME or IMAGE_TAG could not be resolved"
    STATUS=1
    
    # Create error output and exit
    ERROR_EVENTS=$(echo "$EVENTS" | jq '[to_entries[] | select(.value.status == "Failed") | .key]')
    
    jq -n \
      --argjson events "$EVENTS" \
      --argjson error_events "$ERROR_EVENTS" \
      '{
        build: {
          status: false,
          reason: "Image name/tag missing",
          message: "IMAGE_NAME or IMAGE_TAG could not be resolved",
          events: $events,
          current_error: "Image name/tag missing",
          error_events: $error_events
        },
        events: $events,
        output_vars: {
          sbom_scan: {
            status: "Failed",
            reason: "Image name/tag missing",
            message: "IMAGE_NAME or IMAGE_TAG could not be resolved",
            current_error: "Image name/tag missing",
            error_events: $error_events
          }
        }
      }' > "${EXEC_DIR}/${SBOM_SCAN_OUTPUT_FILE}"
    
    generateOutput ${ACTIVITY_SUB_TASK_CODE} false "Image name/tag could not be resolved"
    exit 1
fi

add_event "resolve image" "Successful" "Image resolved" "Image: ${IMAGE_NAME}:${IMAGE_TAG}"

###############################################
### PULL IMAGE IF NOT PRESENT
###############################################
if docker image inspect "${IMAGE_NAME}:${IMAGE_TAG}" >/dev/null 2>&1; then
    logInfoMessage "Image found locally: ${IMAGE_NAME}:${IMAGE_TAG}"
    add_event "image pull" "Successful" "Image available locally" "${IMAGE_NAME}:${IMAGE_TAG} found in local docker daemon"
else
    logWarningMessage "Image not found locally. Pulling ${IMAGE_NAME}:${IMAGE_TAG}"
    
    if ! docker pull "${IMAGE_NAME}:${IMAGE_TAG}"; then
        logErrorMessage "Failed to pull image: ${IMAGE_NAME}:${IMAGE_TAG}"
        add_event "image pull" "Failed" "Docker pull failed" "Could not pull ${IMAGE_NAME}:${IMAGE_TAG}"
        
        ERROR_EVENTS=$(echo "$EVENTS" | jq '[to_entries[] | select(.value.status == "Failed") | .key]')
        
        jq -n \
          --argjson events "$EVENTS" \
          --argjson error_events "$ERROR_EVENTS" \
          '{
            build: {
              status: false,
              reason: "Docker pull failed",
              message: "Could not pull image",
              events: $events,
              current_error: "Docker pull failed",
              error_events: $error_events
            },
            events: $events,
            output_vars: {
              sbom_scan: {
                status: "Failed",
                reason: "Docker pull failed",
                message: "Could not pull image",
                current_error: "Docker pull failed",
                error_events: $error_events
              }
            }
          }' > "${EXEC_DIR}/${SBOM_SCAN_OUTPUT_FILE}"
        
        generateOutput ${ACTIVITY_SUB_TASK_CODE} false "Failed to pull image"
        exit 1
    fi
    
    logInfoMessage "Image successfully pulled: ${IMAGE_NAME}:${IMAGE_TAG}"
    add_event "image pull" "Successful" "Image pulled" "${IMAGE_NAME}:${IMAGE_TAG} pulled successfully"
fi

###############################################
### VERIFY SBOM FILE EXISTS
###############################################
# Check if SBOM file exists from previous step
SBOM_INPUT="${EXEC_DIR}/${SBOM_REPORT_NAME}"

if [ ! -f "${SBOM_INPUT}" ]; then
    logErrorMessage "SBOM file not found: ${SBOM_INPUT}"
    add_event "verify sbom input" "Failed" "SBOM file missing" "Expected SBOM file at ${SBOM_INPUT} not found"
    
    ERROR_EVENTS=$(echo "$EVENTS" | jq '[to_entries[] | select(.value.status == "Failed") | .key]')
    
    jq -n \
      --argjson events "$EVENTS" \
      --argjson error_events "$ERROR_EVENTS" \
      '{
        build: {
          status: false,
          reason: "SBOM file missing",
          message: "SBOM file not found for scanning",
          events: $events,
          current_error: "SBOM file missing",
          error_events: $error_events
        },
        events: $events,
        output_vars: {
          sbom_scan: {
            status: "Failed",
            reason: "SBOM file missing",
            message: "Expected SBOM file not found",
            current_error: "SBOM file missing",
            error_events: $error_events
          }
        }
      }' > "${EXEC_DIR}/${SBOM_SCAN_OUTPUT_FILE}"
    
    generateOutput ${ACTIVITY_SUB_TASK_CODE} false "SBOM file not found"
    exit 1
fi

add_event "verify sbom input" "Successful" "SBOM file found" "SBOM file exists at ${SBOM_INPUT}"

###############################################
### RUN SBOM SCAN
###############################################
JSON_OUTPUT_PATH="${EXEC_DIR}/${SBOM_SCAN_REPORT_NAME}"

logInfoMessage "I'll scan the SBOM ${SBOM_REPORT_NAME} for image ${IMAGE_NAME}:${IMAGE_TAG}"
sleep $SLEEP_DURATION

logInfoMessage "Executing command"
logInfoMessage "trivy sbom -f ${SBOM_SCAN_FORMAT} --output ${JSON_OUTPUT_PATH} ${SBOM_INPUT}"

trivy sbom -f "${SBOM_SCAN_FORMAT}" --output "${JSON_OUTPUT_PATH}" "${SBOM_INPUT}"
STATUS=$?

if [[ "$STATUS" -eq 0 ]]; then
  add_event "sbom scan" "Successful" "Scan completed" "Trivy successfully scanned SBOM"
else
  add_event "sbom scan" "Failed" "Trivy execution error" "trivy sbom exited with code $STATUS"
fi

###############################################
### PARSE RESULTS AND GENERATE CSV
###############################################
CSV_OUTPUT_PATH="${EXEC_DIR}/${OUTPUT_CSV}"

if [ -s "${JSON_OUTPUT_PATH}" ]; then
    if ! command -v jq >/dev/null 2>&1; then
        logErrorMessage "jq is required but not installed."
        add_event "generate csv report" "Failed" "jq not available" "jq command not found"
        exit 1
    fi

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

      ["VulnerabilityID","PkgName","InstalledVersion","FixedVersion","Severity","Criticality","Title"],

      (
        ( .Results // [] | map(.Vulnerabilities // []) | add // [] )
        | sort_by(
            -severityRank(.Severity),
            -criticalityRank(.Criticality)
          )
        | .[]
        | [
            .VulnerabilityID,
            .PkgName,
            .InstalledVersion,
            .FixedVersion,
            .Severity,
            (.Criticality // ""),
            (.Title // "" | gsub("[\n\r]"; " "))
          ]
      )
      | @csv
    ' "${JSON_OUTPUT_PATH}" > "${CSV_OUTPUT_PATH}" || true

    logInfoMessage "Generated SBOM scan CSV: ${CSV_OUTPUT_PATH}"
    
    # Count vulnerabilities
    if [[ -s "${CSV_OUTPUT_PATH}" ]]; then
        VULN_COUNT=$(($(wc -l < "${CSV_OUTPUT_PATH}") - 1))  # Subtract header row
        if [[ "$VULN_COUNT" -gt 0 ]]; then
            add_event "generate csv report" "Successful" "CSV created" "CSV report generated with ${VULN_COUNT} vulnerabilities"
            
            # Display the report
            logInfoMessage "Displaying SBOM Scan Report"
            python3 /opt/buildpiper/shell-functions/print_table.py "${CSV_OUTPUT_PATH}" || head -n 50 "${CSV_OUTPUT_PATH}"
        else
            echo "No vulnerabilities found" > "${CSV_OUTPUT_PATH}"
            VULN_COUNT=0
            add_event "generate csv report" "Successful" "No vulnerabilities" "No vulnerabilities found in SBOM scan"
        fi
    else
        echo "No vulnerabilities found" > "${CSV_OUTPUT_PATH}"
        VULN_COUNT=0
        add_event "generate csv report" "Successful" "Empty report" "CSV created - no data"
    fi
else
    logWarningMessage "No JSON report available, creating empty CSV."
    echo "No vulnerabilities found" > "${CSV_OUTPUT_PATH}"
    VULN_COUNT=0
    add_event "generate csv report" "Successful" "No scan results" "JSON report not available"
fi

###############################################
### DETERMINE FINAL STATUS
###############################################
FINAL_STATUS="Successful"
FINAL_REASON="SBOM scan completed"
FINAL_MESSAGE="Trivy SBOM scan completed. Vulnerabilities found: ${VULN_COUNT:-0}"

if [[ "$STATUS" -ne 0 ]]; then
  FINAL_STATUS="failed"
  FINAL_REASON="SBOM scan failed"
  FINAL_MESSAGE="Trivy SBOM scan failed with exit code ${STATUS}"
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
  --arg sbom_format "${SBOM_SCAN_FORMAT}" \
  --arg sbom_report "${SBOM_SCAN_REPORT_NAME}" \
  --arg image_name "${IMAGE_NAME}" \
  --arg image_tag "${IMAGE_TAG}" \
  --arg vuln_count "${VULN_COUNT:-0}" \
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
      sbom_scan: {
        status: $final_status,
        reason: $final_reason,
        message: $final_message,
        image: {
          name: $image_name,
          tag: $image_tag
        },
        scan: {
          format: $sbom_format,
          report_name: $sbom_report,
          vulnerabilities_found: ($vuln_count | tonumber)
        },
        current_error: (if $final_status == "failed" then $final_reason else "" end),
        error_events: $error_events
      }
    }
  }' > "${EXEC_DIR}/${SBOM_SCAN_OUTPUT_FILE}"

logInfoMessage "Output JSON written to ${EXEC_DIR}/${SBOM_SCAN_OUTPUT_FILE}"
add_event "create output" "Successful" "Output file created" "Structured output written to ${SBOM_SCAN_OUTPUT_FILE}"

###############################################
### SIGNAL PASS/FAIL TO BUILDPIPER PIPELINE
###############################################
if [ $STATUS -eq 0 ]; then
  logInfoMessage "Congratulations! Trivy SBOM scan succeeded!"
  logInfoMessage "===================== SBOM Scan Summary ====================="
  logInfoMessage "Vulnerabilities found: ${VULN_COUNT:-0}"
  generateOutput ${ACTIVITY_SUB_TASK_CODE} true "$FINAL_MESSAGE"
elif [ "$VALIDATION_FAILURE_ACTION" == "FAILURE" ]; then
    logErrorMessage "Please check Trivy SBOM scan failed!"
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