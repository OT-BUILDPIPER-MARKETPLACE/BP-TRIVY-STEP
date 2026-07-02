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
export application="$APPLICATION_NAME"
export environment="$(getProjectEnv)"
export service="$(getServiceName)"
export organization="$ORGANIZATION"
export source_key="$SOURCE_KEY"
export report_file_path="$REPORT_FILE_PATH"

# The image exposes MI_SERVER_ADDRESS, while some callers provide MI_SERVER.
MI_SERVER="${MI_SERVER:-${MI_SERVER_ADDRESS:-}}"



cd "${WORKSPACE}/${CODEBASE_DIR}" || {
    logErrorMessage "Unable to access scan directory: ${WORKSPACE}/${CODEBASE_DIR}"
    exit 1
}

mkdir -p reports

STATUS=0

logInfoMessage "============================"
logInfoMessage "Start Filesystem scanning"
logInfoMessage "============================"

logInfoMessage "I'll scan Filesystem ${WORKSPACE}/${CODEBASE_DIR} for only ${SCAN_SEVERITY} severities"
sleep  $SLEEP_DURATION
logInfoMessage "Executing command"

if [[ "${REPORT_TYPE}" == "json" || "${REPORT_TYPE}" == "both" ]]; then

        JSON_REPORT="reports/trivy-fs-results.json"
        logInfoMessage "Generating JSON report: ${JSON_REPORT}"
        logInfoMessage "trivy fs -q --severity ${SCAN_SEVERITY} --format json -o ${JSON_REPORT} ${WORKSPACE}/${CODEBASE_DIR}"

        trivy fs -q --severity "${SCAN_SEVERITY}" --format json -o "${JSON_REPORT}" "${WORKSPACE}/${CODEBASE_DIR}"

        logInfoMessage "Generating JSON report at ${JSON_REPORT}"
        STATUS=$?

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


if [[ -n "${MI_SERVER:-}" ]]; then
    logInfoMessage "MI_SERVER is set to ${MI_SERVER}. Starting MI data send process..."

    MI_SEND_STATUS=0
    MI_JSON_REPORT="${JSON_REPORT:-reports/trivy-mi-results.json}"
    MI_CSV_REPORT="reports/trivy_mi.csv"

    if [ ! -s "${MI_JSON_REPORT}" ]; then
        logInfoMessage "Generating JSON report for MI metrics at ${MI_JSON_REPORT}"
        trivy fs -q --severity "${SCAN_SEVERITY}" --format json \
            -o "${MI_JSON_REPORT}" "${WORKSPACE}/${CODEBASE_DIR}"
    fi

    if [ -s "${MI_JSON_REPORT}" ]; then
        MI_CRITICAL=$(jq '([.Results[]? .Vulnerabilities[]? | select(.Severity=="CRITICAL")] | length) // 0' "${MI_JSON_REPORT}" 2>/dev/null || echo 0)
        MI_HIGH=$(jq '([.Results[]? .Vulnerabilities[]? | select(.Severity=="HIGH")] | length) // 0' "${MI_JSON_REPORT}" 2>/dev/null || echo 0)
        printf 'Critical,High\n%s,%s\n' "${MI_CRITICAL}" "${MI_HIGH}" > "${MI_CSV_REPORT}"

        logInfoMessage "Displaying Original Report: ${MI_CSV_REPORT}"
        echo "================================================================================"
        python3 /opt/buildpiper/shell-functions/print_table.py "${MI_CSV_REPORT}"
        echo "================================================================================"

        export base64EncodedResponse
        base64EncodedResponse=$(encodeFileContent "${MI_CSV_REPORT}")
        export metrics=("trivy_critical" "trivy_high")

        for metric in "${metrics[@]}"; do
            export source_key="${metric}"
            export report_file_path="$REPORT_FILE_PATH"

            generateMIDataJson /opt/buildpiper/data/mi.template trivy.mi

            logInfoMessage "Sending ${metric} data to MI server..."
            logWarningMessage "Loading encoded data trivy.mi..."
            cat trivy.mi

            if ! sendMIData trivy.mi "${MI_SERVER}"; then
                logErrorMessage "Failed to push data for ${metric} to MI server"
                MI_SEND_STATUS=1
            else
                logInfoMessage "Successfully sent data for ${metric}"
            fi
        done
    else
        logErrorMessage "Unable to generate ${MI_JSON_REPORT}; ${MI_CSV_REPORT} was not created"
        MI_SEND_STATUS=1
    fi

    if [ "$MI_SEND_STATUS" -eq 0 ]; then
        logInfoMessage "Trivy filesystem scan succeeded, and all metrics were sent to the MI server successfully!"
    else
        logErrorMessage "Some metrics failed to send. Please check the MI server or JSON format."
    fi
else
    logWarningMessage "MI_SERVER and MI_SERVER_ADDRESS are not set. Skipping MI data send block."
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
