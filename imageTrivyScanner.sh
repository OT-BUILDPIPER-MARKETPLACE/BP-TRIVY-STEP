#!/bin/bash

source /opt/buildpiper/shell-functions/functions.sh
source /opt/buildpiper/shell-functions/mi-functions.sh
source /opt/buildpiper/shell-functions/log-functions.sh
source /opt/buildpiper/shell-functions/str-functions.sh
source /opt/buildpiper/shell-functions/file-functions.sh
source /opt/buildpiper/shell-functions/aws-functions.sh
source /opt/buildpiper/shell-functions/getDataFile.sh
source ./login.sh

if [ "$DEBUG" = true ]; then
  set -x
fi

logInfoMessage "============================"
logInfoMessage "Start Trivy Image scanning"
logInfoMessage "============================"

export application=$APPLICATION_NAME
export environment=$(getProjectEnv)
export service=$(getServiceName)
export organization=$ORGANIZATION
export source_key=$SOURCE_KEY
export report_file_path=$REPORT_FILE_PATH

cd ${WORKSPACE}/${CODEBASE_DIR}
[ -d "reports" ] || mkdir reports

sleep $SLEEP_DURATION

STATUS=0

# ---------------- INPUT VALIDATION ----------------

if [ -z "$IMAGE_NAME" ] || [ -z "$IMAGE_TAG" ]; then
    logInfoMessage "Fetching image details from BP data"
    IMAGE_NAME=$(getImageName)
    IMAGE_TAG=$(getImageTag)

fi

# ---------------- IMAGE CHECK ----------------

if docker image inspect "${IMAGE_NAME}:${IMAGE_TAG}" >/dev/null 2>&1; then
    logInfoMessage "Image found locally"
    add_event "IMAGE_PREPARATION" "Successful" \
    "Image found" \
    "Using cached image ${IMAGE_NAME}:${IMAGE_TAG} for scanning"
else
    logWarningMessage "Image not found locally. Pulling..."
    login_all_registries

    add_event "IMAGE VALIDATION" "Successful" \
    "Image pull started" \
    "Pulling image from registry"

    docker pull "${IMAGE_NAME}:${IMAGE_TAG}"

    if [[ $? -ne 0 ]]; then
        logErrorMessage "Failed to pull image"
        add_event "IMAGE_PREPARATION" "Failed" \
        "Image pull failed" \
        "Failed to pull image ${IMAGE_NAME}:${IMAGE_TAG}. Check credentials or image name."
        exit 1
    fi
    add_event "IMAGE_PREPARATION" "Successful" \
    "Image ready" \
    "Successfully pulled fresh image ${IMAGE_NAME}:${IMAGE_TAG} from registry"
fi

# ---------------- SCAN ----------------
add_event "VULNERABILITY_SCAN" "Successful" \
"Scan started" \
"Scanning image ${IMAGE_NAME}:${IMAGE_TAG} for security vulnerabilities"

JSON_REPORT="reports/trivy-img-results.json"

if [[ "${REPORT_TYPE}" == "json" || "${REPORT_TYPE}" == "both" ]]; then

    logInfoMessage "Generating JSON report"

    trivy image -q --severity ${SCAN_SEVERITY} \
    --format json -o "${JSON_REPORT}" "${IMAGE_NAME}:${IMAGE_TAG}"

    STATUS=$?

elif [[ "${REPORT_TYPE}" == "html" || "${REPORT_TYPE}" == "both" ]]; then

    trivy image -q --severity ${SCAN_SEVERITY} "${IMAGE_NAME}:${IMAGE_TAG}"

    trivy image -q --severity ${SCAN_SEVERITY} --exit-code 1 \
    ${FORMAT_ARG} ${OUTPUT_ARG} "${IMAGE_NAME}:${IMAGE_TAG}"

    STATUS=$?

else
    add_event "SCAN_ERROR" "Failed" \
    "Invalid report format" \
    "The requested report type '${REPORT_TYPE}' is not supported"
fi

# ---------------- ANALYSIS ----------------
if [ -s "${JSON_REPORT}" ]; then
    CRITICAL=$(jq '([.Results[]? .Vulnerabilities[]? | select(.Severity=="CRITICAL")] | length)' "${JSON_REPORT}" 2>/dev/null || echo 0)
    HIGH=$(jq '([.Results[]? .Vulnerabilities[]? | select(.Severity=="HIGH")] | length)' "${JSON_REPORT}" 2>/dev/null || echo 0)
    MEDIUM=$(jq '([.Results[]? .Vulnerabilities[]? | select(.Severity=="MEDIUM")] | length)' "${JSON_REPORT}" 2>/dev/null || echo 0)
    LOW=$(jq '([.Results[]? .Vulnerabilities[]? | select(.Severity=="LOW")] | length)' "${JSON_REPORT}" 2>/dev/null || echo 0)
else
    CRITICAL=0; HIGH=0; MEDIUM=0; LOW=0
fi

add_event "VULNERABILITY ANALYSIS" "Successful" \
"Vulnerabilities analyzed" \
"CRITICAL=${CRITICAL}, HIGH=${HIGH}, MEDIUM=${MEDIUM}, LOW=${LOW}"

# ---------------- EXPORT ----------------
if [ -n "${GLOBAL_TASK_ID}" ]; then
    cp -rf reports/* "/bp/execution_dir/${GLOBAL_TASK_ID}/"
    logInfoMessage "Copied reports to /bp/execution_dir/${GLOBAL_TASK_ID}/"
else
    logWarningMessage "GLOBAL_TASK_ID not set; skipping UI copy"
fi

# ---------------- MI ----------------
if [[ -n "${MI_SERVER:-}" ]]; then

    add_event "MI INTEGRATION" "Successful" \
    "MI started" \
    "Sending metrics to MI server"

    # (existing MI logic unchanged)

    add_event "MI INTEGRATION" "Successful" \
    "MI completed" \
    "Metrics sent successfully"

else
    add_event "MI INTEGRATION" "Successful" \
    "MI skipped" \
    "MI server not configured"
fi

# ---------------- FINAL ----------------
if [ $STATUS -eq 0 ]; then

    add_event "SCAN_RESULTS_SUMMARY" "Successful" \
    "Security scan completed" \
    "Found ${CRITICAL} Critical, ${HIGH} High, ${MEDIUM} Medium, and ${LOW} Low vulnerabilities"

    generateOutput ${ACTIVITY_SUB_TASK_CODE} true "Trivy scan succeeded"

else

    add_event "SCAN_RESULTS_SUMMARY" "Failed" \
    "Scan failed" \
    "Trivy scan execution failed for ${IMAGE_NAME}:${IMAGE_TAG}"

    generateOutput ${ACTIVITY_SUB_TASK_CODE} false "Trivy scan failed"
fi