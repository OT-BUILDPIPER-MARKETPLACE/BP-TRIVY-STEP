#!/bin/bash
source /opt/buildpiper/shell-functions/functions.sh
source /opt/buildpiper/shell-functions/log-functions.sh

if [ -n "${SCANNER}" ]; then
logInfoMessage "I'll do the scanning for ${SCANNER}"
else
logInfoMessage "I'll generate report at [${WORKSPACE}/${CODEBASE_DIR}]"
fi

if [ -n "${SCAN_TYPE}" ]; then
    logInfoMessage "SCAN_TYPE is ${SCAN_TYPE}"
else
    logInfoMessage "SCAN_TYPE is not found "
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
    logWarningMessage "Please check incompatible scanner passed!!!"
    generateOutput "${ACTIVITY_SUB_TASK_CODE} true Please check incompatible scanner passed!!!"
    ;;
esac
