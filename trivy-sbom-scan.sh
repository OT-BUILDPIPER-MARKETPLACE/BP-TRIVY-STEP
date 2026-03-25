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

JSON_OUTPUT_PATH="reports/${SBOM_SCAN_REPORT_NAME}"
OUTPUT_CSV="${OUTPUT_CSV:-sbom_scan_report.csv}"

cd ${WORKSPACE}/${CODEBASE_DIR}
[ -d "reports" ] || mkdir reports

STATUS=0

# ---------------- INPUT VALIDATION ----------------

if [ -z "$IMAGE_NAME" ] || [ -z "$IMAGE_TAG" ]; then
    IMAGE_NAME=$(getImageName)
    IMAGE_TAG=$(getImageTag)
fi

# ---------------- IMAGE CHECK ----------------
add_event "IMAGE VALIDATION" "Successful" \
"Checking image" \
"Checking image availability locally"

if docker image inspect "${IMAGE_NAME}:${IMAGE_TAG}" >/dev/null 2>&1; then
    add_event "IMAGE_PREPARATION" "Successful" \
    "Image found" \
    "Using cached image ${IMAGE_NAME}:${IMAGE_TAG} for SBOM scanning"
else
    add_event "IMAGE_PREPARATION" "Successful" \
    "Image pull started" \
    "Pulling image ${IMAGE_NAME}:${IMAGE_TAG} from registry"

    docker pull "${IMAGE_NAME}:${IMAGE_TAG}"

    if [[ $? -ne 0 ]]; then
        add_event "IMAGE_PREPARATION" "Failed" \
        "Image pull failed" \
        "Failed to pull image ${IMAGE_NAME}:${IMAGE_TAG}"
        exit 1
    fi

    add_event "IMAGE_PREPARATION" "Successful" \
    "Image ready" \
    "Successfully pulled fresh image ${IMAGE_NAME}:${IMAGE_TAG} from registry"
fi

# ---------------- SBOM SCAN ----------------
if [ -z "$IMAGE_NAME" ] || [ -z "$IMAGE_TAG" ]; then
    STATUS=1
else
    add_event "SBOM_VULNERABILITY_SCAN" "Successful" \
    "Scan started" \
    "Scanning SBOM for image ${IMAGE_NAME}:${IMAGE_TAG} for security vulnerabilities"

    trivy sbom -f "${SBOM_SCAN_FORMAT}" \
    --output "${JSON_OUTPUT_PATH}" \
    "reports/${SBOM_REPORT_NAME}"

    STATUS=$?
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
fi

# ---------------- EXPORT ----------------
if [ -n "${GLOBAL_TASK_ID}" ]; then
    cp -rf reports/* "/bp/execution_dir/${GLOBAL_TASK_ID}/"
fi

# ---------------- FINAL ----------------
if [ $STATUS -eq 0 ]; then

    add_event "SBOM_SCAN_SUMMARY" "Successful" \
    "SBOM scan completed" \
    "SBOM security scan for ${IMAGE_NAME}:${IMAGE_TAG} completed successfully"

    cat ${CSV_OUTPUT_PATH} | head -n 50

    generateOutput ${ACTIVITY_SUB_TASK_CODE} true \
    "SBOM scan succeeded"

elif [ "$VALIDATION_FAILURE_ACTION" == "FAILURE" ]; then

    add_event "SBOM_SCAN_SUMMARY" "Failed" \
    "Scan failed" \
    "SBOM scan failed for ${IMAGE_NAME}:${IMAGE_TAG}"

    cat ${CSV_OUTPUT_PATH} | head -n 50

    generateOutput ${ACTIVITY_SUB_TASK_CODE} false \
    "SBOM scan failed"
    exit 1

else

    add_event "SBOM_SCAN_SUMMARY" "Successful" \
    "Scan completed with issues" \
    "SBOM scan for ${IMAGE_NAME}:${IMAGE_TAG} completed with security findings"

    cat ${CSV_OUTPUT_PATH} | head -n 50

    generateOutput ${ACTIVITY_SUB_TASK_CODE} true \
    "SBOM scan completed with issues"
fi