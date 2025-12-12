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


logInfoMessage "============================"
logInfoMessage "Generate SBOM Image "
logInfoMessage "============================"


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
if [ -z "$IMAGE_NAME" ] || [ -z "$IMAGE_TAG" ]
then
    logInfoMessage "Image name/tag is not provided in env variable $IMAGE_NAME checking it in BP data"
    IMAGE_NAME=$(getImageName)
    IMAGE_TAG=$(getImageTag)
    logInfoMessage "Image Name -> ${IMAGE_NAME}"
    logInfoMessage "Image Tag -> ${IMAGE_TAG}"
fi


if docker image inspect "${IMAGE_NAME}:${IMAGE_TAG}" >/dev/null 2>&1; then
    logInfoMessage "Image found locally: ${IMAGE_NAME}:${IMAGE_TAG}"
else
    logWarningMessage "Image not found locally. Pulling ${IMAGE_NAME}:${IMAGE_TAG}"
    docker pull "${IMAGE_NAME}:${IMAGE_TAG}"
    if [[ $? -ne 0 ]]; then
        logErrorMessage "Failed to pull image: ${IMAGE_NAME}:${IMAGE_TAG}"
        exit 1
    fi
fi

if [ -z "$IMAGE_NAME" ] || [ -z "$IMAGE_TAG" ]
then
    logErrorMessage "Image name/tag is not available in BP data as well please check!!!!!!"
    logInfoMessage "Image Name -> ${IMAGE_NAME}"
    logInfoMessage "Image Tag -> ${IMAGE_TAG}"
    STATUS=1
else
    logInfoMessage "I'll generate SBOM for image ${IMAGE_NAME}:${IMAGE_TAG}"
    sleep  $SLEEP_DURATION
    logInfoMessage "Executing command"
    logInfoMessage "trivy image --format ${SBOM_FORMAT_ARG} --output reports/${SBOM_REPORT_NAME} ${IMAGE_NAME}:${IMAGE_TAG}"
    trivy image --format ${SBOM_FORMAT_ARG} --output reports/${SBOM_REPORT_NAME} ${IMAGE_NAME}:${IMAGE_TAG}
    STATUS=`echo $?`
fi

if [ $STATUS -eq 0 ]
then
  logInfoMessage "Congratulations Trivy SBOM file generation @ reports/${SBOM_REPORT_NAME}  succeeded!!!"
  logInfoMessage "===================== Displaying first 50 lines of the SBOM Image report ====================="

  cat reports/${SBOM_FS_REPORT_NAME} | head -n 50

  generateOutput ${ACTIVITY_SUB_TASK_CODE} true "Congratulations Trivy SBOM generation @ reports/${SBOM_REPORT_NAME} succeeded!!!"

elif [ $VALIDATION_FAILURE_ACTION == "FAILURE" ]
  then
    logErrorMessage "Please check Trivy SBOM generation failed!!!"
    generateOutput ${ACTIVITY_SUB_TASK_CODE} false "Please check Trivy SBOM generation failed!!!"
    exit 1
   else
    logWarningMessage "Please check Trivy SBOM generation failed!!!"
    generateOutput ${ACTIVITY_SUB_TASK_CODE} true "Please check Trivy SBOM generation failed!!!"
fi
