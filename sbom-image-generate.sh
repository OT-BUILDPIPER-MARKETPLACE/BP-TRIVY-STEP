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

logInfoMessage "============================"
logInfoMessage "Generating SBOM for Image"
logInfoMessage "============================"

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
          sbom_image: {
            status: "Failed",
            reason: "Image name/tag missing",
            message: "IMAGE_NAME or IMAGE_TAG could not be resolved",
            current_error: "Image name/tag missing",
            error_events: $error_events
          }
        }
      }' > "${EXEC_DIR}/${SBOM_OUTPUT_FILE}"
    
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
              sbom_image: {
                status: "Failed",
                reason: "Docker pull failed",
                message: "Could not pull image",
                current_error: "Docker pull failed",
                error_events: $error_events
              }
            }
          }' > "${EXEC_DIR}/${SBOM_OUTPUT_FILE}"
        
        generateOutput ${ACTIVITY_SUB_TASK_CODE} false "Failed to pull image"
        exit 1
    fi
    
    logInfoMessage "Image successfully pulled: ${IMAGE_NAME}:${IMAGE_TAG}"
    add_event "image pull" "Successful" "Image pulled" "${IMAGE_NAME}:${IMAGE_TAG} pulled successfully"
fi

###############################################
### GENERATE SBOM
###############################################
SBOM_REPORT="${EXEC_DIR}/${SBOM_REPORT_NAME}"

logInfoMessage "I'll generate SBOM for image ${IMAGE_NAME}:${IMAGE_TAG}"
sleep $SLEEP_DURATION

logInfoMessage "Executing command"
logInfoMessage "trivy image --format ${SBOM_FORMAT_ARG} --output ${SBOM_REPORT} ${IMAGE_NAME}:${IMAGE_TAG}"

trivy image --format ${SBOM_FORMAT_ARG} --output "${SBOM_REPORT}" ${IMAGE_NAME}:${IMAGE_TAG}
STATUS=$?

if [[ "$STATUS" -eq 0 ]]; then
  add_event "sbom generation" "Successful" "SBOM created" "Trivy successfully generated SBOM at ${SBOM_REPORT}"
  
  # Check if file exists and has content
  if [[ -s "${SBOM_REPORT}" ]]; then
    FILE_SIZE=$(stat -f%z "${SBOM_REPORT}" 2>/dev/null || stat -c%s "${SBOM_REPORT}" 2>/dev/null || echo 0)
    add_event "verify sbom file" "Successful" "File verified" "SBOM file created with size ${FILE_SIZE} bytes"
    
    logInfoMessage "Congratulations! Trivy image SBOM generation succeeded!"
    logInfoMessage "SBOM file: ${SBOM_REPORT}"
    logInfoMessage "===================== Displaying first 50 lines of the SBOM report ====================="
    head -n 50 "${SBOM_REPORT}"
    logInfoMessage "========================================================================================"
  else
    add_event "verify sbom file" "Failed" "File empty or missing" "SBOM file was not created or is empty"
    STATUS=1
  fi
else
  add_event "sbom generation" "Failed" "Trivy execution error" "trivy image exited with code $STATUS"
fi

###############################################
### DETERMINE FINAL STATUS
###############################################
FINAL_STATUS="Successful"
FINAL_REASON="SBOM generation completed"
FINAL_MESSAGE="Trivy image SBOM generated successfully at ${SBOM_REPORT_NAME}"

if [[ "$STATUS" -ne 0 ]]; then
  FINAL_STATUS="failed"
  FINAL_REASON="SBOM generation failed"
  FINAL_MESSAGE="Trivy image SBOM generation failed"
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
  --arg sbom_report "${SBOM_REPORT_NAME}" \
  --arg image_name "${IMAGE_NAME}" \
  --arg image_tag "${IMAGE_TAG}" \
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
      sbom_image: {
        status: $final_status,
        reason: $final_reason,
        message: $final_message,
        image: {
          name: $image_name,
          tag: $image_tag
        },
        sbom: {
          format: $sbom_format,
          report_name: $sbom_report
        },
        current_error: (if $final_status == "failed" then $final_reason else "" end),
        error_events: $error_events
      }
    }
  }' > "${EXEC_DIR}/${SBOM_OUTPUT_FILE}"

logInfoMessage "Output JSON written to ${EXEC_DIR}/${SBOM_OUTPUT_FILE}"
add_event "create output" "Successful" "Output file created" "Structured output written to ${SBOM_OUTPUT_FILE}"

###############################################
### SIGNAL PASS/FAIL TO BUILDPIPER PIPELINE
###############################################
if [ $STATUS -eq 0 ]; then
  logInfoMessage "Congratulations! Trivy image SBOM generation succeeded!"
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
    generateOutput ${ACTIVITY_SUB_TASK_CODE} true "$FINAL_MESSAGE"  
fi

saveTaskStatus ${STATUS} ${ACTIVITY_SUB_TASK_CODE}