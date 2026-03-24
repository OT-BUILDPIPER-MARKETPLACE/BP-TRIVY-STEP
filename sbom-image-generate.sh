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
logInfoMessage "Generating SBOM for Image"
logInfoMessage "============================"

add_event "SBOM IMAGE GENERATION START" "Successful" \
"Generation initiated" \
"Starting SBOM generation for image"

export application=$APPLICATION_NAME
export environment=$(getProjectEnv)
export service=$(getServiceName)
export organization=$ORGANIZATION
export source_key=$SOURCE_KEY
export report_file_path=$REPORT_FILE_PATH

cd ${WORKSPACE}/${CODEBASE_DIR}
[ -d "reports" ] || mkdir reports

STATUS=0

# ---------------- INPUT VALIDATION ----------------
add_event "INPUT VALIDATION" "Successful" \
"Validation started" \
"Validating image name and tag"

if [ -z "$IMAGE_NAME" ] || [ -z "$IMAGE_TAG" ]; then
    IMAGE_NAME=$(getImageName)
    IMAGE_TAG=$(getImageTag)

    add_event "INPUT VALIDATION" "Successful" \
    "Image resolved" \
    "Image details resolved from pipeline metadata"
fi

# ---------------- IMAGE CHECK ----------------
add_event "IMAGE VALIDATION" "Successful" \
"Checking image" \
"Checking image availability locally"

if docker image inspect "${IMAGE_NAME}:${IMAGE_TAG}" >/dev/null 2>&1; then
    add_event "IMAGE VALIDATION" "Successful" \
    "Image found" \
    "Image found locally"
else
    add_event "IMAGE VALIDATION" "Successful" \
    "Image pull started" \
    "Pulling image from registry"

    docker pull "${IMAGE_NAME}:${IMAGE_TAG}"

    if [[ $? -ne 0 ]]; then
        add_event "IMAGE VALIDATION" "Failed" \
        "Image pull failed" \
        "Failed to pull image ${IMAGE_NAME}:${IMAGE_TAG}"
        exit 1
    fi

    add_event "IMAGE VALIDATION" "Successful" \
    "Image pulled" \
    "Image pulled successfully"
fi

# ---------------- SBOM GENERATION ----------------
if [ -z "$IMAGE_NAME" ] || [ -z "$IMAGE_TAG" ]; then
    STATUS=1
else
    add_event "SBOM GENERATION" "Successful" \
    "Generation started" \
    "Generating SBOM using Trivy"

    trivy image --format ${SBOM_FORMAT_ARG} \
    --output reports/${SBOM_REPORT_NAME} \
    ${IMAGE_NAME}:${IMAGE_TAG}

    STATUS=$?

    add_event "SBOM GENERATION" "Successful" \
    "SBOM generated" \
    "SBOM generated at reports/${SBOM_REPORT_NAME}"
fi

# ---------------- EXPORT ----------------
if [ -n "${GLOBAL_TASK_ID}" ]; then
    cp -rf reports/* "/bp/execution_dir/${GLOBAL_TASK_ID}/"

    add_event "REPORT EXPORT" "Successful" \
    "Export completed" \
    "SBOM copied to execution directory"
else
    add_event "REPORT EXPORT" "Failed" \
    "Export skipped" \
    "GLOBAL_TASK_ID not set"
fi

# ---------------- FINAL ----------------
if [ $STATUS -eq 0 ]; then

    add_event "SBOM IMAGE SUMMARY" "Successful" \
    "Generation completed" \
    "SBOM generated successfully"

    generateOutput ${ACTIVITY_SUB_TASK_CODE} true \
    "SBOM generation succeeded"

elif [ "$VALIDATION_FAILURE_ACTION" == "FAILURE" ]; then

    add_event "SBOM IMAGE SUMMARY" "Failed" \
    "Generation failed" \
    "SBOM generation failed"

    generateOutput ${ACTIVITY_SUB_TASK_CODE} false \
    "SBOM generation failed"
    exit 1

else

    add_event "SBOM IMAGE SUMMARY" "Successful" \
    "Completed with issues" \
    "SBOM generated with warnings"

    generateOutput ${ACTIVITY_SUB_TASK_CODE} true \
    "SBOM generation completed with issues"
fi