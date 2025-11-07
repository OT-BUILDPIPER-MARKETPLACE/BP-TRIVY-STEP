#!/bin/bash
source /opt/buildpiper/shell-functions/functions.sh
source /opt/buildpiper/shell-functions/mi-functions.sh
source /opt/buildpiper/shell-functions/log-functions.sh
source /opt/buildpiper/shell-functions/str-functions.sh
source /opt/buildpiper/shell-functions/file-functions.sh
source /opt/buildpiper/shell-functions/aws-functions.sh
source /opt/buildpiper/shell-functions/getDataFile.sh

cd ${WORKSPACE}/${CODEBASE_DIR}

if [ -d "reports" ]; then
    true
else
    mkdir reports 
fi

STATUS=0

export OUTPUT_ARG="${SCANNER}_trivy-results.json"

logInfoMessage "I'll scan Filesystem ${WORKSPACE}/${CODEBASE_DIR} for only ${SCAN_SEVERITY} severities"
sleep  $SLEEP_DURATION
logInfoMessage "Executing command"
logInfoMessage "trivy fs -q --severity ${SCAN_SEVERITY} ${WORKSPACE}/${CODEBASE_DIR}"
trivy fs -q --severity ${SCAN_SEVERITY} ${WORKSPACE}/${CODEBASE_DIR}
logInfoMessage "trivy fs -q --severity ${SCAN_SEVERITY} --exit-code 1 ${FORMAT_ARG} ${OUTPUT_ARG}"
if [[ "${OUTPUT_ARG}" == *"-o "* ]]; then
    trivy fs -q --severity ${SCAN_SEVERITY} --exit-code 1 ${FORMAT_ARG} ${OUTPUT_ARG} ${WORKSPACE}/${CODEBASE_DIR}
else
    trivy fs -q --severity ${SCAN_SEVERITY} --exit-code 1 ${FORMAT_ARG} -o reports/${OUTPUT_ARG} ${WORKSPACE}/${CODEBASE_DIR}
fi

STATUS=$?

if [ $STATUS -eq 0 ]; then
    logInfoMessage "Congratulations trivy scan succeeded!!!"
    generateOutput ${ACTIVITY_SUB_TASK_CODE} true "Congratulations trivy scan succeeded!!!"
elif [ "$VALIDATION_FAILURE_ACTION" == "FAILURE" ]; then
    logErrorMessage "Please check trivy scan failed!!!"
    generateOutput ${ACTIVITY_SUB_TASK_CODE} false "Please check trivy scan failed!!!"
    exit 1
else
    logWarningMessage "Please check trivy scan failed!!!"
    generateOutput ${ACTIVITY_SUB_TASK_CODE} true "Please check trivy scan failed!!!"
fi
