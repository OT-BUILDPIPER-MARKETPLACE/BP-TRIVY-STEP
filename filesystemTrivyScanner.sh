#!/bin/bash
source /app/buildpiper/shell-functions/functions.sh
source /app/buildpiper/shell-functions/log-functions.sh

CODEBASE_LOCATION="${WORKSPACE}"/"${CODEBASE_DIR}"
cd "${CODEBASE_LOCATION}" || exit

if [ -d "reports" ]; then
    true
else
    mkdir reports
fi

STATUS=0

    logInfoMessage "I'll scan file in ${CODEBASE_LOCATION} for only ${SCAN_SEVERITY} severities"
    sleep  "$SLEEP_DURATION"
    logInfoMessage "Executing command"
    logInfoMessage "trivy fs -q --severity ${SCAN_SEVERITY} --scanners ${SCAN_TYPE} --exit-code 1 --format ${FORMAT_ARG} ${CODEBASE_LOCATION}"
    trivy fs -q --severity "${SCAN_SEVERITY}" --scanners "${SCAN_TYPE}" --exit-code 1 --format "${FORMAT_ARG}" "${CODEBASE_LOCATION}"

    trivy fs -q --severity "${SCAN_SEVERITY}" --scanners "${SCAN_TYPE}" --exit-code 1 --format json -o reports/"${OUTPUT_ARG}" "${CODEBASE_LOCATION}"
TASK_STATUS=$(echo $?)

saveTaskStatus "${TASK_STATUS}" "${ACTIVITY_SUB_TASK_CODE}"
