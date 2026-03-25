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
fi

# ---------------- IMAGE CHECK ----------------
add_event "IMAGE VALIDATION" "Successful" \
"Checking image" \
"Checking image availability locally"

if docker image inspect "${IMAGE_NAME}:${IMAGE_TAG}" >/dev/null 2>&1; then
    add_event "IMAGE_PREPARATION" "Successful" \
    "Image found" \
    "Using cached image ${IMAGE_NAME}:${IMAGE_TAG} for SBOM generation"
else
    add_event "IMAGE_PREPARATION" "Successful" \
    "Image pull started" \
    "Pulling image ${IMAGE_NAME}:${IMAGE_TAG} from registry"

    docker pull "${IMAGE_NAME}:${IMAGE_TAG}"

    if [[ $? -ne 0 ]]; then
        add_event "IMAGE_PREPARATION" "Failed" \
        "Image pull failed" \
        "Failed to pull image ${IMAGE_NAME}:${IMAGE_TAG}. Check credentials or image name."
        exit 1
    fi

    add_event "IMAGE_PREPARATION" "Successful" \
    "Image ready" \
    "Successfully pulled fresh image ${IMAGE_NAME}:${IMAGE_TAG} from registry"
fi

# ---------------- SBOM GENERATION ----------------
if [ -z "$IMAGE_NAME" ] || [ -z "$IMAGE_TAG" ]; then
    STATUS=1
else
    add_event "SBOM_GENERATION" "Successful" \
    "Generation started" \
    "Generating SBOM for image ${IMAGE_NAME}:${IMAGE_TAG}"

    trivy image --format ${SBOM_FORMAT_ARG} \
    --output reports/${SBOM_REPORT_NAME} \
    ${IMAGE_NAME}:${IMAGE_TAG}

    STATUS=$?
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

    add_event "SBOM_GENERATION_SUMMARY" "Successful" \
    "SBOM generation completed" \
    "SBOM for image ${IMAGE_NAME}:${IMAGE_TAG} generated successfully"

    generateOutput ${ACTIVITY_SUB_TASK_CODE} true \
    "SBOM generation succeeded"

elif [ "$VALIDATION_FAILURE_ACTION" == "FAILURE" ]; then

    add_event "SBOM_GENERATION_SUMMARY" "Failed" \
    "Generation failed" \
    "SBOM generation failed for ${IMAGE_NAME}:${IMAGE_TAG}"

    generateOutput ${ACTIVITY_SUB_TASK_CODE} false \
    "SBOM generation failed"
    exit 1

else

    add_event "SBOM_GENERATION_SUMMARY" "Successful" \
    "Generation completed with warnings" \
    "SBOM generation for ${IMAGE_NAME}:${IMAGE_TAG} completed with some warnings"

    generateOutput ${ACTIVITY_SUB_TASK_CODE} true \
    "SBOM generation completed with issues"
fi