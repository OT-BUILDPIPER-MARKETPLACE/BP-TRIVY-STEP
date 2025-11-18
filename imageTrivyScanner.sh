#!/bin/bash
set -euo pipefail

source /opt/buildpiper/shell-functions/functions.sh
source /opt/buildpiper/shell-functions/mi-functions.sh
source /opt/buildpiper/shell-functions/log-functions.sh
source /opt/buildpiper/shell-functions/str-functions.sh
source /opt/buildpiper/shell-functions/file-functions.sh
source /opt/buildpiper/shell-functions/aws-functions.sh
source /opt/buildpiper/shell-functions/getDataFile.sh

export application=$APPLICATION_NAME
export environment=$(getProjectEnv)
export service=$(getServiceName)
export organization=$ORGANIZATION
export source_key=$SOURCE_KEY
export report_file_path=$REPORT_FILE_PATH

cd ${WORKSPACE}/${CODEBASE_DIR}

mkdir -p reports

STATUS=0

JSON_REPORT="reports/${SCANNER}_trivy-results.json"
SUMMARY_JSON="reports/trivy-summary.json"

# *** NEW: MI CSV same as filesystem (scanner included) ***
MI_CSV="reports/trivy_mi_${SCANNER}.csv"

# *** NEW: Horizontal CSV (same as filesystem) ***
HORIZONTAL_CSV="reports/trivy_image.csv"

SCAN_SEVERITY="${SCAN_SEVERITY:-HIGH,CRITICAL}"
SLEEP_DURATION="${SLEEP_DURATION:-5s}"

# ==============================================================================
# Resolve image details (use helper fallbacks if env not set)
# ==============================================================================
if [[ -z "${IMAGE_NAME:-}" || -z "${IMAGE_TAG:-}" ]]; then
  logWarningMessage "IMAGE_NAME or IMAGE_TAG not provided. Fetching from metadata..."
  IMAGE_NAME="$(getImageName || true)"
  IMAGE_TAG="$(getImageTag || true)"
fi

if [[ -z "${IMAGE_NAME}" || -z "${IMAGE_TAG}" ]]; then
  logErrorMessage "Unable to resolve image name/tag. Exiting."
  exit 1
fi

logInfoMessage "Target Image  : ${IMAGE_NAME}:${IMAGE_TAG}"

logInfoMessage "Executing: trivy image -q --severity ${SCAN_SEVERITY} ${IMAGE_NAME}:${IMAGE_TAG}"
trivy image -q --severity ${SCAN_SEVERITY} ${IMAGE_NAME}:${IMAGE_TAG} || true

logInfoMessage "Generating JSON report at ${JSON_REPORT}"
trivy image -q --severity ${SCAN_SEVERITY} --format json -o "${JSON_REPORT}" "${IMAGE_NAME}:${IMAGE_TAG}" || true

# ---------------------------------------------------------
# Extract CRITICAL, HIGH, MEDIUM, LOW counts using jq
# ---------------------------------------------------------
if [ -s "${JSON_REPORT}" ]; then
    CRITICAL=$(jq '([.Results[]? .Vulnerabilities[]? | select(.Severity=="CRITICAL")] | length)' "${JSON_REPORT}" 2>/dev/null || echo 0)
    HIGH=$(jq '([.Results[]? .Vulnerabilities[]? | select(.Severity=="HIGH")] | length)' "${JSON_REPORT}" 2>/dev/null || echo 0)
    MEDIUM=$(jq '([.Results[]? .Vulnerabilities[]? | select(.Severity=="MEDIUM")] | length)' "${JSON_REPORT}" 2>/dev/null || echo 0)
    LOW=$(jq '([.Results[]? .Vulnerabilities[]? | select(.Severity=="LOW")] | length)' "${JSON_REPORT}" 2>/dev/null || echo 0)
else
    CRITICAL=0; HIGH=0; MEDIUM=0; LOW=0
fi

# ---------------------------------------------------------
# Create Summary JSON (same as filesystem)
# ---------------------------------------------------------
cat > "${SUMMARY_JSON}" <<EOF
{
  "Trivy Vulnerability Summary": {
    "CRITICAL": ${CRITICAL},
    "HIGH": ${HIGH},
    "MEDIUM": ${MEDIUM},
    "LOW": ${LOW}
  }
}
EOF

logInfoMessage "Generated summary report: ${SUMMARY_JSON}"

# ---------------------------------------------------------
# Create MI CSV (Critical, High)
# ---------------------------------------------------------
echo -e "Critical\tHigh" > "${MI_CSV}"
echo -e "${CRITICAL}\t${HIGH}" >> "${MI_CSV}"

logInfoMessage "Generated MI report: ${MI_CSV}"

# ---------------------------------------------------------
# Create Horizontal CSV (same as filesystem version)
# ---------------------------------------------------------
echo "Library,CVE_ID,Severity,InstalledVersion,FixedVersion,Title" > "${HORIZONTAL_CSV}"

if [ -s "${JSON_REPORT}" ]; then
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
        ] | @csv
    ' "${JSON_REPORT}" >> "${HORIZONTAL_CSV}" || true
fi

logInfoMessage "Generated horizontal CVE CSV: ${HORIZONTAL_CSV}"

# ---------------------------------------------------------
# Copy to BP UI
# ---------------------------------------------------------
if [ -n "${GLOBAL_TASK_ID:-}" ]; then
    cp -rf reports/* "/bp/execution_dir/${GLOBAL_TASK_ID}/"
    logInfoMessage "Copied reports to /bp/execution_dir/${GLOBAL_TASK_ID}/"
else
    logWarningMessage "GLOBAL_TASK_ID not set; skipping UI copy"
fi

STATUS=0

# ---------------------------------------------------------
# Final Validation & Output
# ---------------------------------------------------------
logInfoMessage "Image vulnerabilities -> CRITICAL=${CRITICAL}, HIGH=${HIGH}, MEDIUM=${MEDIUM}, LOW=${LOW}"

if [ $STATUS -eq 0 ]; then
    generateOutput ${ACTIVITY_SUB_TASK_CODE} true "Image Trivy scan succeeded!"
else
    if [ "$VALIDATION_FAILURE_ACTION" = "FAILURE" ]; then
        generateOutput ${ACTIVITY_SUB_TASK_CODE} false "Image Trivy scan failed!"
        exit 1
    else
        generateOutput ${ACTIVITY_SUB_TASK_CODE} true "Image Trivy scan completed with warnings!"
    fi
fi

exit 0

