#!/bin/bash
source functions.sh
source log-functions.sh
cd ${WORKSPACE}/${CODEBASE_DIR}

if [ -d "reports" ]; then
    true
else
    mkdir reports 
fi

STATUS=0

logInfoMessage "I'll scan Filesystem ${WORKSPACE}/${CODEBASE_DIR} for only ${SCAN_SEVERITY} severities"
sleep  $SLEEP_DURATION
logInfoMessage "Executing command"
logInfoMessage "trivy fs -q --severity ${SCAN_SEVERITY} ${WORKSPACE}/${CODEBASE_DIR}"
trivy fs -q --severity ${SCAN_SEVERITY} ${WORKSPACE}/${CODEBASE_DIR}
logInfoMessage "trivy fs -q --severity ${SCAN_SEVERITY} --exit-code 1 ${FORMAT_ARG} -o reports/${OUTPUT_ARG} ${WORKSPACE}/${CODEBASE_DIR}"
trivy fs -q --severity ${SCAN_SEVERITY} --exit-code 1 ${FORMAT_ARG} -o reports/${OUTPUT_ARG} ${WORKSPACE}/${CODEBASE_DIR}
STATUS=`echo $?`


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
