#!/bin/bash

source /opt/buildpiper/shell-functions/functions.sh
source /opt/buildpiper/shell-functions/mi-functions.sh
source /opt/buildpiper/shell-functions/log-functions.sh
source /opt/buildpiper/shell-functions/str-functions.sh
source /opt/buildpiper/shell-functions/file-functions.sh
source /opt/buildpiper/shell-functions/aws-functions.sh
source /opt/buildpiper/shell-functions/getDataFile.sh

logInfoMessage "I'll generate report at [${WORKSPACE}/${CODEBASE_DIR}]"

cd ${WORKSPACE}/${CODEBASE_DIR}

if [ -d "reports" ]; then
    true
else
    mkdir reports 
fi

STATUS=0
if [ -z "$IMAGE_NAME" ] || [ -z "$IMAGE_TAG" ]
then
    logInfoMessage "Image name/tag is not provided in env variable $IMAGE_NAME checking it in BP data"
    IMAGE_NAME=$(getImageName)
    IMAGE_TAG=$(getImageTag)
    logInfoMessage "Image Name -> ${IMAGE_NAME}"
    logInfoMessage "Image Tag -> ${IMAGE_TAG}"
fi
if [ -z "$IMAGE_NAME" ] || [ -z "$IMAGE_TAG" ]
then
    logErrorMessage "Image name/tag is not available in BP data as well please check!!!!!!"
    STATUS=1
else
    logInfoMessage "I'll scan the SBOM reports/${SBOM_REPORT_NAME} for image ${IMAGE_NAME}:${IMAGE_TAG}"
    sleep  $SLEEP_DURATION
    logInfoMessage "Executing command"
    logInfoMessage "trivy sbom -s ${SCAN_SEVERITY} -f $FORMAT_ARG $OUTPUT_ARG reports/${SBOM_REPORT_NAME}"
    # trivy sbom -s ${SCAN_SEVERITY} -o reports/${SBOM_REPORT_NAME} -f ${FORMAT_ARG} --exit-code 1 reports/${SBOM_REPORT_NAME}
    trivy sbom -s ${SCAN_SEVERITY} $FORMAT_ARG $OUTPUT_ARG reports/${SBOM_REPORT_NAME}
    STATUS=`echo $?`
fi

if [ $STATUS -eq 0 ]
then
  logInfoMessage "Congratulations Trivy SBOM scan succeeded!!!"
  cat reports/$SBOM_OUTPUT
  generateOutput ${ACTIVITY_SUB_TASK_CODE} true "Congratulations Trivy SBOM scan succeeded!!!"

elif [ $VALIDATION_FAILURE_ACTION == "FAILURE" ]
  then
    logErrorMessage "Please check Trivy SBOM scan failed!!!"
    cat reports/$SBOM_OUTPUT
    generateOutput ${ACTIVITY_SUB_TASK_CODE} false "Please check Trivy SBOM scan failed!!!"
    exit 1
   else
    logWarningMessage "Please check Trivy SBOM scan failed!!!"
    cat reports/${SBOM_REPORT_NAME}
    generateOutput ${ACTIVITY_SUB_TASK_CODE} true "Please check Trivy SBOM scan failed!!!"
fi