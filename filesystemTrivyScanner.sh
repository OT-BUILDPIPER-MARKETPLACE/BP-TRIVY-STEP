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

if [ -d "reports" ]; then
    true
else
    mkdir reports 
fi

STATUS=0

logInfoMessage "============================"
logInfoMessage "start Filesystem scan"
logInfoMessage "============================"

logInfoMessage "I'll scan Filesystem ${WORKSPACE}/${CODEBASE_DIR} for only ${SCAN_SEVERITY} severities"
sleep  $SLEEP_DURATION
logInfoMessage "Executing command"

if [[ "${REPORT_TYPE}" == "json" || "${REPORT_TYPE}" == "both" ]]; then

        JSON_REPORT="trivy-fs-results.json"
        logInfoMessage "Generating JSON report: ${JSON_REPORT}"
        logInfoMessage "trivy fs -q --severity ${SCAN_SEVERITY} --format json -o ${JSON_REPORT} ${WORKSPACE}/${CODEBASE_DIR}"
        trivy fs -q --severity "${SCAN_SEVERITY}" --format json -o "${JSON_REPORT}" "${WORKSPACE}/${CODEBASE_DIR}"
        logInfoMessage "Generating JSON report at ${JSON_REPORT}"

    elif [[ "${REPORT_TYPE}" == "html"  || "${REPORT_TYPE}" == "both" ]]; then

        logInfoMessage "Generating HTML report"
        logInfoMessage "trivy fs -q --severity ${SCAN_SEVERITY} ${WORKSPACE}/${CODEBASE_DIR}"
        trivy fs -q --severity ${SCAN_SEVERITY} "${WORKSPACE}/${CODEBASE_DIR}"

        logInfoMessage "trivy fs -q --severity ${SCAN_SEVERITY} --exit-code 1 ${FORMAT_ARG} ${OUTPUT_FS_ARG} ${WORKSPACE}/${CODEBASE_DIR}"
        trivy fs -q --severity ${SCAN_SEVERITY} --exit-code 1 ${FORMAT_ARG} ${OUTPUT_FS_ARG} "${WORKSPACE}/${CODEBASE_DIR}"
        STATUS=$?

        logWarningMessage "=============================================================="
        logInfoMessage    "CSV report is not generated when HTML report type is selected."
        logWarningMessage "=============================================================="

    else
        logErrorMessage "Invalid REPORT_TYPE provided. Supported: json, html"
fi

if [[ "${REPORT_TYPE}" == "json" || "${REPORT_TYPE}" == "both" ]]; then

    if [ -s "${JSON_REPORT}" ]; then
        CRITICAL=$(jq '([.Results[]? .Vulnerabilities[]? | select(.Severity=="CRITICAL")] | length) // 0' "${JSON_REPORT}" 2>/dev/null || echo 0)
        HIGH=$(jq '([.Results[]? .Vulnerabilities[]? | select(.Severity=="HIGH")] | length) // 0' "${JSON_REPORT}" 2>/dev/null || echo 0)
        MEDIUM=$(jq '([.Results[]? .Vulnerabilities[]? | select(.Severity=="MEDIUM")] | length) // 0' "${JSON_REPORT}" 2>/dev/null || echo 0)
        LOW=$(jq '([.Results[]? .Vulnerabilities[]? | select(.Severity=="LOW")] | length) // 0' "${JSON_REPORT}" 2>/dev/null || echo 0)
    else
        CRITICAL=0; HIGH=0; MEDIUM=0; LOW=0
    fi

    HORIZONTAL_CSV="reports/trivy_fs.csv"
    echo "Library,CVE_ID,Severity,InstalledVersion,FixedVersion,Title" > "${HORIZONTAL_CSV}"

    if [ -s "${JSON_REPORT}" ]; then
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
        ' "${JSON_REPORT}" >> "${HORIZONTAL_CSV}" 2>/dev/null || true

        logInfoMessage "Generated minimal horizontal CVE CSV (without status) at ${HORIZONTAL_CSV}"
    else
        logWarningMessage "No JSON report available; horizontal CSV created empty."
    fi

fi


if [ -n "${GLOBAL_TASK_ID:-}" ]; then
    mkdir -p "/bp/execution_dir/${GLOBAL_TASK_ID}/"
    cp -rf reports/* "/bp/execution_dir/${GLOBAL_TASK_ID}/"
    logInfoMessage "Copied reports to /bp/execution_dir/${GLOBAL_TASK_ID}/"
else
    logWarningMessage "GLOBAL_TASK_ID not set; skipping copy to execution_dir"
fi


if [ $STATUS -eq 0 ]
then
  logInfoMessage "Congratulations trivy scan succeeded!!!"
  generateOutput ${ACTIVITY_SUB_TASK_CODE} true "Congratulations trivy scan succeeded!!!"
elif [ $VALIDATION_FAILURE_ACTION == "FAILURE" ]
  then
    logErrorMessage "Please check triyv scan failed!!!"
    generateOutput ${ACTIVITY_SUB_TASK_CODE} false "Please check triyv scan failed!!!"
    exit 1
   else
    logWarningMessage "Please check triyv scan failed!!!"
    generateOutput ${ACTIVITY_SUB_TASK_CODE} true "Please check triyv scan failed!!!"
fi
