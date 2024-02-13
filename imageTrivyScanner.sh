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


if [ -z "$IMAGE_NAME" ] || [ -z "$IMAGE_TAG" ]; then
    logErrorMessage "Image name/tag is not provided in env variable please check!!!!!!"
    logInfoMessage "Image Name -> ${IMAGE_NAME}"
    logInfoMessage "Image Tag -> ${IMAGE_TAG}"
    exit 1
else
    logInfoMessage "I'll scan image ${IMAGE_NAME}:${IMAGE_TAG} for only ${SCAN_SEVERITY} severities"
    sleep  "${SLEEP_DURATION}"
    logInfoMessage "Executing command"
    logInfoMessage "trivy image -q --severity ${SCAN_SEVERITY} --scanners ${SCAN_TYPE} --exit-code 1 --format ${FORMAT_ARG}  ${IMAGE_NAME}:${IMAGE_TAG}"
    trivy image -q --severity "${SCAN_SEVERITY}" --scanners "${SCAN_TYPE}" --exit-code 1 --format "${FORMAT_ARG}" "${IMAGE_NAME}":"${IMAGE_TAG}"

    trivy image -q --severity "${SCAN_SEVERITY}" --scanners "${SCAN_TYPE}" --exit-code 1 --format json -o reports/"${OUTPUT_ARG}" "${IMAGE_NAME}":"${IMAGE_TAG}"

TASK_STATUS=$(echo $?)
fi
saveTaskStatus "${TASK_STATUS}" "${ACTIVITY_SUB_TASK_CODE}"
