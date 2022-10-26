#!/bin/bash
source functions.sh

logInfoMessage "I'll do the scanning for $SCANNER"
logInfoMessage "I'll generate report at [${WORKSPACE}/${CODEBASE_DIR}]"

./imageTrivyScanner.sh