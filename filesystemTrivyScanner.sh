#!/bin/bash
set -euo pipefail

<<<<<<< HEAD
# filesystemTrivyScanner.sh (Updated MI CSV with SCANNER name)
=======
# filesystemTrivyScanner.sh (Updated Minimal UI Report — Status removed)
>>>>>>> fd8262b (trivy image and filescan non root step)

source /opt/buildpiper/shell-functions/functions.sh
source /opt/buildpiper/shell-functions/mi-functions.sh
source /opt/buildpiper/shell-functions/log-functions.sh
source /opt/buildpiper/shell-functions/str-functions.sh
source /opt/buildpiper/shell-functions/file-functions.sh
source /opt/buildpiper/shell-functions/aws-functions.sh
source /opt/buildpiper/shell-functions/getDataFile.sh

cd "${WORKSPACE}/${CODEBASE_DIR}" || { logErrorMessage "Failed to cd to ${WORKSPACE}/${CODEBASE_DIR}"; exit 1; }

[ ! -d "reports" ] && mkdir -p reports

STATUS=0
export OUTPUT_ARG="${SCANNER}_trivy-results.json"
TRIVY_JSON="reports/${OUTPUT_ARG}"
SUMMARY_JSON="reports/trivy-summary.json"
<<<<<<< HEAD

# *** UPDATED: Add scanner name to prevent conflict with image scan ***
MI_CSV="reports/trivy_mi_${SCANNER}.csv"

HORIZONTAL_CSV="reports/trivy_filesystem.csv"

=======
MI_CSV="reports/trivy_mi.csv"
HORIZONTAL_CSV="reports/trivy_filesystem.csv"

>>>>>>> fd8262b (trivy image and filescan non root step)
# Defaults
SCAN_SEVERITY="${SCAN_SEVERITY:-HIGH,CRITICAL}"
SLEEP_DURATION="${SLEEP_DURATION:-5s}"

logInfoMessage "I'll do the scanning for FILESYSTEM"
logInfoMessage "I'll generate report at [${WORKSPACE}/${CODEBASE_DIR}]"
logInfoMessage "I'll scan Filesystem ${WORKSPACE}/${CODEBASE_DIR} for only ${SCAN_SEVERITY} severities"
sleep "${SLEEP_DURATION}"

logInfoMessage "Executing command"
logInfoMessage "trivy fs -q --severity ${SCAN_SEVERITY} ${WORKSPACE}/${CODEBASE_DIR}"

trivy fs -q --severity "${SCAN_SEVERITY}" "${WORKSPACE}/${CODEBASE_DIR}" --exit-code 0 || true
trivy fs -q --severity "${SCAN_SEVERITY}" --format json -o "${TRIVY_JSON}" "${WORKSPACE}/${CODEBASE_DIR}" || true

# Parse severity counts
if [ -s "${TRIVY_JSON}" ]; then
    CRITICAL=$(jq '([.Results[]? .Vulnerabilities[]? | select(.Severity=="CRITICAL")] | length) // 0' "${TRIVY_JSON}" 2>/dev/null || echo 0)
    HIGH=$(jq '([.Results[]? .Vulnerabilities[]? | select(.Severity=="HIGH")] | length) // 0' "${TRIVY_JSON}" 2>/dev/null || echo 0)
    MEDIUM=$(jq '([.Results[]? .Vulnerabilities[]? | select(.Severity=="MEDIUM")] | length) // 0' "${TRIVY_JSON}" 2>/dev/null || echo 0)
    LOW=$(jq '([.Results[]? .Vulnerabilities[]? | select(.Severity=="LOW")] | length) // 0' "${TRIVY_JSON}" 2>/dev/null || echo 0)
else
    CRITICAL=0; HIGH=0; MEDIUM=0; LOW=0
fi

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

logInfoMessage "Generated summary report at ${SUMMARY_JSON}"

<<<<<<< HEAD
# *** UPDATED: MI report filename now includes scanner name ***
=======
>>>>>>> fd8262b (trivy image and filescan non root step)
echo -e "Critical\tHigh" > "${MI_CSV}"
echo -e "${CRITICAL}\t${HIGH}" >> "${MI_CSV}"
logInfoMessage "Generated MI report at ${MI_CSV}"

# -------------------------------
#   MINIMAL HORIZONTAL CSV (Status removed)
# -------------------------------
echo "Library,CVE_ID,Severity,InstalledVersion,FixedVersion,Title" > "${HORIZONTAL_CSV}"

if [ -s "${TRIVY_JSON}" ]; then
    jq -r '
      .Results[]? 
      | select(.Vulnerabilities != null) 
      | .Vulnerabilities[]? 
      | select(.Severity == "CRITICAL" or .Severity == "HIGH" or .Severity == "MEDIUM" or .Severity == "LOW")
      | [
          (.PkgName // "N/A"),
          (.VulnerabilityID // "N/A"),
          (.Severity // "N/A"),
          (.InstalledVersion // "N/A"),
          (.FixedVersion // "N/A"),
          (.Title // "N/A")
        ]
        | @csv
    ' "${TRIVY_JSON}" >> "${HORIZONTAL_CSV}" 2>/dev/null || true

    logInfoMessage "Generated minimal horizontal CVE CSV (without status) at ${HORIZONTAL_CSV}"
else
    logWarningMessage "No JSON report available; horizontal CSV created empty."
fi

# Copy reports for UI
if [ -n "${GLOBAL_TASK_ID:-}" ]; then
    mkdir -p "/bp/execution_dir/${GLOBAL_TASK_ID}/"
    cp -rf reports/* "/bp/execution_dir/${GLOBAL_TASK_ID}/"
    logInfoMessage "Copied reports to /bp/execution_dir/${GLOBAL_TASK_ID}/"
else
    logWarningMessage "GLOBAL_TASK_ID not set; skipping copy to execution_dir"
fi

# Publish MI report
<<<<<<< HEAD
if command -v storeMIReport >/dev/null 2>&1; then
    storeMIReport "${SUMMARY_JSON}" || logWarningMessage "storeMIReport failed for ${SUMMARY_JSON}"
    storeMIReport "${MI_CSV}" || logWarningMessage "storeMIReport failed for ${MI_CSV}"
else
    logWarningMessage "storeMIReport not found, skipping report publish"
fi

=======
# Publish MI report only if storeMIReport exists (silent if not available)
if command -v storeMIReport >/dev/null 2>&1; then
    storeMIReport "${SUMMARY_JSON}" || logWarningMessage "storeMIReport failed for ${SUMMARY_JSON}"
    storeMIReport "${MI_CSV}" || logWarningMessage "storeMIReport failed for ${MI_CSV}"
fi


>>>>>>> fd8262b (trivy image and filescan non root step)
logInfoMessage "Vulnerability counts -> CRITICAL=${CRITICAL}, HIGH=${HIGH}, MEDIUM=${MEDIUM}, LOW=${LOW}"

if [ "${CRITICAL:-0}" -gt 0 ] || [ "${HIGH:-0}" -gt 0 ]; then
    if [ "${VALIDATION_FAILURE_ACTION:-WARNING}" = "FAILURE" ]; then
        logErrorMessage "High/Critical vulnerabilities found. Failing step."
        generateOutput "${ACTIVITY_SUB_TASK_CODE:-BP-TRIVY-TASK}" false "Trivy scan found CRITICAL=${CRITICAL}, HIGH=${HIGH}"
        saveTaskStatus 1 "${ACTIVITY_SUB_TASK_CODE:-BP-TRIVY-TASK}"
        exit 1
    else
        logWarningMessage "High/Critical vulnerabilities found but configured to WARN."
        generateOutput "${ACTIVITY_SUB_TASK_CODE:-BP-TRIVY-TASK}" true "Trivy scan found CRITICAL=${CRITICAL}, HIGH=${HIGH}"
        saveTaskStatus 0 "${ACTIVITY_SUB_TASK_CODE:-BP-TRIVY-TASK}"
    fi
else
    logInfoMessage "No CRITICAL/HIGH vulnerabilities found."
    generateOutput "${ACTIVITY_SUB_TASK_CODE:-BP-TRIVY-TASK}" true "Trivy scan completed successfully."
    saveTaskStatus 0 "${ACTIVITY_SUB_TASK_CODE:-BP-TRIVY-TASK}"
fi

exit 0
<<<<<<< HEAD

=======
>>>>>>> fd8262b (trivy image and filescan non root step)
