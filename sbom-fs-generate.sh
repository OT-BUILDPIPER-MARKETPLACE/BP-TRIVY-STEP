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

logInfoMessage "==============================="
logInfoMessage "Generating SBOM for filesystem"
logInfoMessage "==============================="

add_event "SBOM FS GENERATION START" "Successful" \
"Generation initiated" \
"Starting SBOM generation for filesystem"

export application=$APPLICATION_NAME
export environment=$(getProjectEnv)
export service=$(getServiceName)
export organization=$ORGANIZATION
export source_key=$SOURCE_KEY
export report_file_path=$REPORT_FILE_PATH

cd ${WORKSPACE}/${CODEBASE_DIR}
[ -d "reports" ] || mkdir reports

STATUS=0

logInfoMessage "I'll generate SBOM for filesystem path ${WORKSPACE}/${CODEBASE_DIR}"
sleep $SLEEP_DURATION

# ---------------- SBOM GENERATION ----------------
add_event "SBOM GENERATION" "Successful" \
"Generation started" \
"Generating SBOM for filesystem"

trivy fs --format ${SBOM_FORMAT_ARG} \
--output reports/${SBOM_FS_REPORT_NAME} \
${WORKSPACE}/${CODEBASE_DIR}

STATUS=$?

if [ $STATUS -eq 0 ]; then
  add_event "SBOM GENERATION" "Successful" \
  "SBOM generated" \
  "SBOM generated at reports/${SBOM_FS_REPORT_NAME}"
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

  add_event "SBOM FS SUMMARY" "Successful" \
  "Generation completed" \
  "Filesystem SBOM generated successfully"

  logInfoMessage "Congratulations Trivy filesystem SBOM generation @ reports/${SBOM_FS_REPORT_NAME} succeeded!!!"

  cat reports/${SBOM_FS_REPORT_NAME} | head -n 50

  generateOutput ${ACTIVITY_SUB_TASK_CODE} true \
  "SBOM generation succeeded"

elif [ "$VALIDATION_FAILURE_ACTION" == "FAILURE" ]; then

  add_event "SBOM FS SUMMARY" "Failed" \
  "Generation failed" \
  "Filesystem SBOM generation failed"

  generateOutput ${ACTIVITY_SUB_TASK_CODE} false \
  "SBOM generation failed"
  exit 1

else

  add_event "SBOM FS SUMMARY" "Successful" \
  "Completed with issues" \
  "SBOM generated with warnings"

  generateOutput ${ACTIVITY_SUB_TASK_CODE} true \
  "SBOM generation completed with issues"
fi