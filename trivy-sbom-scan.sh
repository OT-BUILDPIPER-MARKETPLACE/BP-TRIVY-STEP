#!/bin/bash

source /opt/buildpiper/shell-functions/functions.sh
source /opt/buildpiper/shell-functions/log-functions.sh
source /opt/buildpiper/shell-functions/file-functions.sh
source /opt/buildpiper/shell-functions/str-functions.sh
source /opt/buildpiper/shell-functions/getDataFile.sh

if [ "$DEBUG" = true ]; then
  set -x
fi

logInfoMessage "================================="
logInfoMessage "Start SBOM image scan step"
logInfoMessage "================================="

add_event "SBOM SCAN START" "Successful" \
"Scan initiated" \
"Starting SBOM scan"

JSON_OUTPUT_PATH="reports/${SBOM_SCAN_REPORT_NAME}"
OUTPUT_CSV="${OUTPUT_CSV:-sbom_scan_report.csv}"

cd ${WORKSPACE}/${CODEBASE_DIR}
[ -d "reports" ] || mkdir reports

STATUS=0

# ---------------- INPUT VALIDATION ----------------
add_event "INPUT VALIDATION" "Successful" \
"Validation started" \
"Validating image and SBOM input"

if [ -z "$IMAGE_NAME" ] || [ -z "$IMAGE_TAG" ]; then
    IMAGE_NAME=$(getImageName)
    IMAGE_TAG=$(getImageTag)

    add_event "INPUT VALIDATION" "Successful" \
    "Image resolved" \
    "Image details resolved from pipeline metadata"
fi

# ---------------- IMAGE CHECK ----------------
add_event "IMAGE VALIDATION" "Successful" \
"Checking image" \
"Checking image availability locally"

if docker image inspect "${IMAGE_NAME}:${IMAGE_TAG}" >/dev/null 2>&1; then
    add_event "IMAGE VALIDATION" "Successful" \
    "Image found" \
    "Image found locally"
else
    add_event "IMAGE VALIDATION" "Successful" \
    "Image pull started" \
    "Pulling image from registry"

    docker pull "${IMAGE_NAME}:${IMAGE_TAG}"

    if [[ $? -ne 0 ]]; then
        add_event "IMAGE VALIDATION" "Failed" \
        "Image pull failed" \
        "Failed to pull image ${IMAGE_NAME}:${IMAGE_TAG}"
        exit 1
    fi

    add_event "IMAGE VALIDATION" "Successful" \
    "Image pulled" \
    "Image pulled successfully"
fi

# ---------------- SBOM SCAN ----------------
if [ -z "$IMAGE_NAME" ] || [ -z "$IMAGE_TAG" ]; then
    STATUS=1
else
    add_event "SBOM SCAN EXECUTION" "Successful" \
    "Scan started" \
    "Scanning SBOM using Trivy"

    trivy sbom -f "${SBOM_SCAN_FORMAT}" \
    --output "${JSON_OUTPUT_PATH}" \
    "reports/${SBOM_REPORT_NAME}"

    STATUS=$?

    add_event "REPORT GENERATION" "Successful" \
    "JSON report created" \
    "SBOM scan JSON report generated"
fi

# ---------------- ANALYSIS ----------------
if [ -s "${JSON_OUTPUT_PATH}" ]; then
    CSV_OUTPUT_PATH="reports/${OUTPUT_CSV}"

    jq -r '
    ["VulnerabilityID","PkgName","InstalledVersion","FixedVersion","Severity","Criticality","Title"],
    (
      (.Results // [] | map(.Vulnerabilities // []) | add // [])
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
    ) | @csv
    ' "${JSON_OUTPUT_PATH}" > "${CSV_OUTPUT_PATH}" || true

    add_event "VULNERABILITY ANALYSIS" "Successful" \
    "Analysis completed" \
    "SBOM vulnerability data processed"
fi

# ---------------- EXPORT ----------------
if [ -n "${GLOBAL_TASK_ID}" ]; then
    cp -rf reports/* "/bp/execution_dir/${GLOBAL_TASK_ID}/"

    add_event "REPORT EXPORT" "Successful" \
    "Export completed" \
    "Reports copied to execution directory"
else
    add_event "REPORT EXPORT" "Failed" \
    "Export skipped" \
    "GLOBAL_TASK_ID not set"
fi

# ---------------- FINAL ----------------
if [ $STATUS -eq 0 ]; then

    add_event "SBOM SCAN SUMMARY" "Successful" \
    "Scan completed" \
    "SBOM scan completed successfully"

    cat ${CSV_OUTPUT_PATH} | head -n 50

    generateOutput ${ACTIVITY_SUB_TASK_CODE} true \
    "SBOM scan succeeded"

elif [ "$VALIDATION_FAILURE_ACTION" == "FAILURE" ]; then

    add_event "SBOM SCAN SUMMARY" "Failed" \
    "Scan failed" \
    "SBOM scan failed"

    cat ${CSV_OUTPUT_PATH} | head -n 50

    generateOutput ${ACTIVITY_SUB_TASK_CODE} false \
    "SBOM scan failed"
    exit 1

else

    add_event "SBOM SCAN SUMMARY" "Successful" \
    "Completed with issues" \
    "SBOM scan completed with vulnerabilities"

    cat ${CSV_OUTPUT_PATH} | head -n 50

    generateOutput ${ACTIVITY_SUB_TASK_CODE} true \
    "SBOM scan completed with issues"
fi