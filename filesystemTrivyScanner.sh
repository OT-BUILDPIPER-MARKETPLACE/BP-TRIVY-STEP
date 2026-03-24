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

cd ${WORKSPACE}/${CODEBASE_DIR}
[ -d "reports" ] || mkdir reports

STATUS=0

logInfoMessage "============================"
logInfoMessage "Start Filesystem scanning"
logInfoMessage "============================"

add_event "TRIVY FS SCAN START" "Successful" \
"Scan initiated" \
"Starting filesystem scan"

logInfoMessage "I'll scan Filesystem ${WORKSPACE}/${CODEBASE_DIR}"
sleep $SLEEP_DURATION

# ---------------- SCAN ----------------
add_event "TRIVY FS SCAN EXECUTION" "Successful" \
"Scan started" \
"Running filesystem scan"

if [[ "${REPORT_TYPE}" == "json" || "${REPORT_TYPE}" == "both" ]]; then

    JSON_REPORT="reports/trivy-fs-results.json"

    add_event "REPORT GENERATION" "Successful" \
    "JSON report started" \
    "Generating JSON report"

    trivy fs -q --severity "${SCAN_SEVERITY}" \
    --format json -o "${JSON_REPORT}" "${WORKSPACE}/${CODEBASE_DIR}"

    STATUS=$?

elif [[ "${REPORT_TYPE}" == "html" || "${REPORT_TYPE}" == "both" ]]; then

    trivy fs -q --severity ${SCAN_SEVERITY} "${WORKSPACE}/${CODEBASE_DIR}"

    add_event "REPORT GENERATION" "Successful" \
    "HTML report started" \
    "Generating HTML report"

    trivy fs -q --severity ${SCAN_SEVERITY} --exit-code 1 \
    ${FORMAT_ARG} ${OUTPUT_FS_ARG} "${WORKSPACE}/${CODEBASE_DIR}"

    STATUS=$?

else
    add_event "REPORT GENERATION" "Failed" \
    "Invalid report type" \
    "Unsupported REPORT_TYPE"
fi

# ---------------- ANALYSIS ----------------
if [[ "${REPORT_TYPE}" == "json" || "${REPORT_TYPE}" == "both" ]]; then

    if [ -s "${JSON_REPORT}" ]; then
        CRITICAL=$(jq '([.Results[]? .Vulnerabilities[]? | select(.Severity=="CRITICAL")] | length) // 0' "${JSON_REPORT}" 2>/dev/null || echo 0)
        HIGH=$(jq '([.Results[]? .Vulnerabilities[]? | select(.Severity=="HIGH")] | length) // 0' "${JSON_REPORT}" 2>/dev/null || echo 0)
        MEDIUM=$(jq '([.Results[]? .Vulnerabilities[]? | select(.Severity=="MEDIUM")] | length) // 0' "${JSON_REPORT}" 2>/dev/null || echo 0)
        LOW=$(jq '([.Results[]? .Vulnerabilities[]? | select(.Severity=="LOW")] | length) // 0' "${JSON_REPORT}" 2>/dev/null || echo 0)

        add_event "VULNERABILITY ANALYSIS" "Successful" \
        "Analysis completed" \
        "CRITICAL=${CRITICAL}, HIGH=${HIGH}, MEDIUM=${MEDIUM}, LOW=${LOW}"
    else
        CRITICAL=0; HIGH=0; MEDIUM=0; LOW=0
    fi
fi

# ---------------- EXPORT ----------------
if [ -n "${GLOBAL_TASK_ID:-}" ]; then
    mkdir -p "/bp/execution_dir/${GLOBAL_TASK_ID}/"
    cp -rf reports/* "/bp/execution_dir/${GLOBAL_TASK_ID}/"

    add_event "REPORT EXPORT" "Successful" \
    "Reports exported" \
    "Reports copied to execution directory"
else
    add_event "REPORT EXPORT" "Failed" \
    "Export skipped" \
    "GLOBAL_TASK_ID not set"
fi

# ---------------- FINAL ----------------
if [ $STATUS -eq 0 ]; then

    add_event "TRIVY FS SCAN SUMMARY" "Successful" \
    "Scan completed" \
    "CRITICAL=${CRITICAL}, HIGH=${HIGH}"

    generateOutput ${ACTIVITY_SUB_TASK_CODE} true "Trivy scan succeeded"

elif [ "$VALIDATION_FAILURE_ACTION" == "FAILURE" ]; then

    add_event "TRIVY FS SCAN SUMMARY" "Failed" \
    "Scan failed" \
    "Filesystem scan failed"

    generateOutput ${ACTIVITY_SUB_TASK_CODE} false "Trivy scan failed"
    exit 1

else

    add_event "TRIVY FS SCAN SUMMARY" "Successful" \
    "Completed with issues" \
    "Scan completed with vulnerabilities"

    generateOutput ${ACTIVITY_SUB_TASK_CODE} true "Scan completed with issues"
fi