#!/bin/bash
source /opt/buildpiper/shell-functions/functions.sh
source /opt/buildpiper/shell-functions/log-functions.sh

CODEBASE_LOCATION="${WORKSPACE}"/"${CODEBASE_DIR}"
logInfoMessage "I'll do processing at [$CODEBASE_LOCATION]"
cd "${CODEBASE_LOCATION}"

if [ -d "reports" ]; then
    true
else
    mkdir reports
fi

STATUS=0

if [ -n "${SCAN_TYPE}" ]; then
    echo "SCAN_TYPE is ${SCAN_TYPE}"
else
    echo "SCAN_TYPE is not found "
    exit 1
fi

    logInfoMessage "I'll scan file in ${WORKSPACE}/${CODEBASE_DIR} for only ${SCAN_SEVERITY} severities"
    sleep  "$SLEEP_DURATION"
    logInfoMessage "Executing command"
    logInfoMessage "trivy fs -q --severity ${SCAN_SEVERITY} --scanners ${SCAN_TYPE} --exit-code 1 --format ${FORMAT_ARG} ${WORKSPACE}/${CODEBASE_DIR}"
    trivy fs -q --severity "${SCAN_SEVERITY}" --scanners "${SCAN_TYPE}" --exit-code 1 --format "${FORMAT_ARG}" "${WORKSPACE}"/"${CODEBASE_DIR}"

    logInfoMessage "trivy fs -q --severity ${SCAN_SEVERITY} --scanners ${SCAN_TYPE} --exit-code 1 --format json -o reports/${OUTPUT_ARG} ${WORKSPACE}/${CODEBASE_DIR}"
    trivy fs -q --severity "${SCAN_SEVERITY}" --scanners "${SCAN_TYPE}" --exit-code 1 --format json -o reports/"${OUTPUT_ARG}" "${WORKSPACE}"/"${CODEBASE_DIR}"
TASK_STATUS=$(echo $?)

saveTaskStatus ${TASK_STATUS} ${ACTIVITY_SUB_TASK_CODE}
