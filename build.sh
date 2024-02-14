#!/bin/bash
source /app/buildpiper/shell-functions/functions.sh
source /app/buildpiper/shell-functions/log-functions.sh

logInfoMessage "I'll do the scanning for scanner -> ${SCANNER}"
if [ -n "${SCAN_TYPE}" ]; then
    logInfoMessage "I'll do the scanning for scan_type -> ${SCAN_TYPE}"
else
    logWarningMessage "SCAN_TYPE is not found "
    exit 1
fi

case "${SCANNER}" in

  IMAGE)
    ./imageTrivyScanner.sh
    ;;
  FILESYSTEM)
    ./filesystemTrivyScanner.sh
    ;;
  *)
    logErrorMessage "Please check incompatible scanner passed!!!"
    generateOutput "${ACTIVITY_SUB_TASK_CODE}" true "Please check incompatible scanner passed!!!"
    exit 1
    ;;
esac
