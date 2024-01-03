#!/bin/bash
source functions.sh
mkdir /$1
WORKSPACE=$1
git clone $2 /$1/code_to_scan
CODEBASE_DIR=code_to_scan

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


