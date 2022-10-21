#!/bin/bash
source functions.sh

logInfoMessage "I'll do the scanning for $SCANNER"
logInfoMessage "I'll generate report at [${WORKSPACE}${CODEBASE_DIR}]"

cd ${WORKSPACE}/${CODEBASE_DIR}

STATUS=0
if [ -z "$IMAGE_NAME" ] || [ -z "$IMAGE_TAG" ]
then
    logInfoMessage "Image name/tag is not provided in env variable $IMAGE_NAME checking it in BP data"
    logInfoMessage "Image Name -> ${IMAGE_NAME}"
    logInfoMessage "Image Tag -> ${IMAGE_TAG}"
    IMAGE_NAME=`getComponentName`
    IMAGE_TAG=`getRepositoryTag`
fi

if [ -z "$IMAGE_NAME" ] || [ -z "$IMAGE_TAG" ]
then
    logErrorMessage "Image name/tag is not available in BP data as well please check!!!!!!"
    logInfoMessage "Image Name -> ${IMAGE_NAME}"
    logInfoMessage "Image Tag -> ${IMAGE_TAG}"
    STATUS=1
else
    logInfoMessage "I'll scan image ${IMAGE_NAME}:${IMAGE_TAG} for only ${SCAN_SEVERITY} severities"
    sleep  $SLEEP_DURATION
    logInfoMessage "Executing command"
    trivy image --severity ${SCAN_SEVERITY} ${IMAGE_NAME}:${IMAGE_TAG} 
    logInfoMessage "trivy image --severity ${SCAN_SEVERITY} --exit-code 1 ${FORMAT_ARG} ${OUTPUT_ARG} ${IMAGE_NAME}:${IMAGE_TAG}"
    trivy image --severity ${SCAN_SEVERITY} --exit-code 1 ${FORMAT_ARG} ${OUTPUT_ARG} ${IMAGE_NAME}:${IMAGE_TAG} 
    STATUS=`echo $?`
fi

if [ $STATUS -eq 0 ]
then
  logInfoMessage "Congratulations trivy scan succeeded!!!"
  generateOutput mvn_execute true "Congratulations trivy scan succeeded!!!"
elif [ $VALIDATION_FAILURE_ACTION == "FAILURE" ]
  then
    logErrorMessage "Please check triyv scan failed!!!"
    generateOutput ${ACTIVITY_SUB_TASK_CODE} false "Please check triyv scan failed!!!"
    exit 1
   else
    logWarningMessage "Please check triyv scan failed!!!"
    generateOutput ${ACTIVITY_SUB_TASK_CODE} true "Please check triyv scan failed!!!"
fi