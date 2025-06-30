#!/bin/bash

source /opt/buildpiper/shell-functions/functions.sh
source /opt/buildpiper/shell-functions/mi-functions.sh
source /opt/buildpiper/shell-functions/log-functions.sh
source /opt/buildpiper/shell-functions/str-functions.sh
source /opt/buildpiper/shell-functions/file-functions.sh
source /opt/buildpiper/shell-functions/aws-functions.sh
source /opt/buildpiper/shell-functions/getDataFile.sh

git config --global --add safe.directory "$(pwd)"

CODEBASE_LOCATION="${WORKSPACE}/${CODEBASE_DIR}"

logInfoMessage "I'll do the scanning for $SCANNER"
logInfoMessage "I'll generate report at [${WORKSPACE}/${CODEBASE_DIR}]"

case ${SCANNER} in

  IMAGE)
    ./imageTrivyScanner.sh
    ;;
  FILESYSTEM)
    ./filesystemTrivyScanner.sh
    ;;
  *)
    logWarningMessage "Please check incompatible scanner passed!!!"
    generateOutput ${ACTIVITY_SUB_TASK_CODE} true "Please check incompatible scanner passed!!!"
    ;;
esac


