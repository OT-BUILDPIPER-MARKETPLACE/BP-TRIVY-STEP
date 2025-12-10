#!/bin/bash

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
logInfoMessage "I'll generate SBOM file at [${WORKSPACE}/${CODEBASE_DIR}]"

cd ${WORKSPACE}/${CODEBASE_DIR}

if [ -d "reports" ]; then
    true
else
    mkdir reports
fi

STATUS=0

logInfoMessage "I'll generate SBOM for filesystem path ${WORKSPACE}/${CODEBASE_DIR}"
sleep $SLEEP_DURATION
logInfoMessage "Executing command"
logInfoMessage "trivy fs --format ${SBOM_FORMAT_ARG} --output reports/${SBOM_FS_REPORT_NAME} ${WORKSPACE}/${CODEBASE_DIR}"

trivy fs --format ${SBOM_FORMAT_ARG} --output reports/${SBOM_FS_REPORT_NAME} ${WORKSPACE}/${CODEBASE_DIR}
STATUS=$?

if [ $STATUS -eq 0 ]; then
  logInfoMessage "Congratulations Trivy filesystem SBOM generation @ reports/${SBOM_FS_REPORT_NAME} succeeded!!!"
  ls -al reports/
  cat reports/${SBOM_FS_REPORT_NAME}
  generateOutput ${ACTIVITY_SUB_TASK_CODE} true "Congratulations Trivy SBOM generation @ reports/${SBOM_FS_REPORT_NAME} succeeded!!!"

elif [ "$VALIDATION_FAILURE_ACTION" == "FAILURE" ]; then
    logErrorMessage "Please check Trivy SBOM generation failed!!!"
    generateOutput ${ACTIVITY_SUB_TASK_CODE} false "Please check Trivy SBOM generation failed!!!"
    exit 1
else
    logWarningMessage "Please check Trivy SBOM generation failed!!!"
    generateOutput ${ACTIVITY_SUB_TASK_CODE} true "Please check Trivy SBOM generation failed!!!"
fi