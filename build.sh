#!/bin/bash
source functions.sh
source log-functions.sh

logInfoMessage "I'll do the scanning for $SCANNER"
logInfoMessage "I'll generate report at [${WORKSPACE}/${CODEBASE_DIR}]"

case ${SCANNER} in

  IMAGE)
    ./imageTrivyScanner.sh
    ;;
  FILESYSTEM)
    ./filesystemTrivyScanner.sh
    ;;
  VULNERABILITIES)
    ./VulnerabilitiesTrivyScanner.sh
    ;;
  LICENSES)
    ./licensesTrivyScanner.sh
    ;;
  SECRETS)
    ./secretTrivyScanner.sh
    ;;
  *)
    logWarningMessage "Please check incompatible scanner passed!!!"
    generateOutput ${ACTIVITY_SUB_TASK_CODE} true "Please check incompatible scanner passed!!!"
    ;;
esac
