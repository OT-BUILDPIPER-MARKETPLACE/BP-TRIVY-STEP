#!/bin/bash

source /opt/buildpiper/shell-functions/functions.sh
source /opt/buildpiper/shell-functions/log-functions.sh
source /opt/buildpiper/shell-functions/file-functions.sh
source /opt/buildpiper/shell-functions/str-functions.sh
source /opt/buildpiper/shell-functions/getDataFile.sh

if [ "$DEBUG" = true ]; then
  set -x
fi


logInfoMessage "================================="
logInfoMessage "start SBOM image scan step"
logInfoMessage "================================="

JSON_OUTPUT_PATH="report/${SBOM_SCAN_REPORT_NAME}"
OUTPUT_CSV="${OUTPUT_CSV:-sbom_scan_report.csv}"

logInfoMessage "I'll generate report at [${WORKSPACE}/${CODEBASE_DIR}]"

cd ${WORKSPACE}/${CODEBASE_DIR}

if [ -d "report" ]; then
    true
else
    mkdir report
fi

STATUS=0
if [ -z "$IMAGE_NAME" ] || [ -z "$IMAGE_TAG" ]
then
    logInfoMessage "Image name/tag is not provided in env variable $IMAGE_NAME checking it in BP data"
    IMAGE_NAME=$(getImageName)
    IMAGE_TAG=$(getImageTag)
    logInfoMessage "Image Name -> ${IMAGE_NAME}"
    logInfoMessage "Image Tag -> ${IMAGE_TAG}"
fi

if docker image inspect "${IMAGE_NAME}:${IMAGE_TAG}" >/dev/null 2>&1; then
    logInfoMessage " Image found locally: ${IMAGE_NAME}:${IMAGE_TAG}"
else
    logWarningMessage "Image not found locally. Pulling ${IMAGE_NAME}:${IMAGE_TAG}"
    docker pull "${IMAGE_NAME}:${IMAGE_TAG}"
    if [[ $? -ne 0 ]]; then
        logErrorMessage "Failed to pull image: ${IMAGE_NAME}:${IMAGE_TAG}"
        exit 1
    fi
fi

if [ -z "$IMAGE_NAME" ] || [ -z "$IMAGE_TAG" ]
then
    logErrorMessage "Image name/tag is not available in BP data as well please check!!!!!!"
    STATUS=1
else
    logInfoMessage "I'll scan the SBOM report/${SBOM_REPORT_NAME} for image ${IMAGE_NAME}:${IMAGE_TAG}"
    sleep  $SLEEP_DURATION
    logInfoMessage "Executing command"
    logInfoMessage "trivy sbom -s ${SCAN_SEVERITY} -o report/${OUTPUT_ARG} -f ${FORMAT_ARG} --exit-code 1 report/${SBOM_REPORT_NAME}"

    trivy sbom --skip-db-update --offline-scan -f "${SBOM_SCAN_FORMAT}" --output "${JSON_OUTPUT_PATH}" "report/${SBOM_REPORT_NAME}"
    #trivy sbom -s ${SCAN_SEVERITY} --exit-code 1 report/${SBOM_REPORT_NAME}
    #logInfoMessage "trivy sbom --cache-dir ${TRIVY_CACHE_DIR} --skip-db-update --offline-scan --format ${SBOM_SCAN_FORMAT} --output ${JSON_OUTPUT_PATH} report/${SBOM_REPORT_NAME}"

    #trivy sbom --cache-dir "${TRIVY_CACHE_DIR}" --skip-db-update --offline-scan --format "${SBOM_SCAN_FORMAT}" --output "${JSON_OUTPUT_PATH}" "report/${SBOM_REPORT_NAME}"
    #trivy sbom -f "${SBOM_SCAN_FORMAT}" --output "${JSON_OUTPUT_PATH}" "report/${SBOM_REPORT_NAME}"

    STATUS=`echo $?`
fi
--format json
 if [ -s "${JSON_OUTPUT_PATH}" ]; then
    CSV_OUTPUT_PATH="report/${OUTPUT_CSV}"
      if ! command -v jq >/dev/null 2>&1; then
        logErrorMessage "jq is required but not installed."
        exit 1
      fi

  jq -r '
    def severityRank(s):
      if s == "CRITICAL" then 5
      elif s == "HIGH" then 4
      elif s == "MEDIUM" then 3
      elif s == "LOW" then 2
      else 1 end;

    def criticalityRank(c):
      if c == "HIGH" or c == "high" then 3
      elif c == "MEDIUM" or c == "medium" then 2
      elif c == "LOW" or c == "low" then 1
      else 0 end;

    ["VulnerabilityID","PkgName","InstalledVersion","FixedVersion","Severity","Criticality","Title"],

    (
      ( .Results // [] | map(.Vulnerabilities // []) | add // [] )
      | sort_by(
          -severityRank(.Severity),
          -criticalityRank(.Criticality)
        )
      | .[]
      | [
          .VulnerabilityID,
          .PkgName,
          .InstalledVersion,
          .FixedVersion,
          .Severity,
          (.Criticality // ""),
          (.Title // "" | gsub("[\n\r]"; " "))
        ]
    )
    | @csv
  ' "${JSON_OUTPUT_PATH}" > "${CSV_OUTPUT_PATH}" || true


    logInfoMessage "Generated sbom CSV: ${CSV_OUTPUT_PATH}"
  else
    logWarningMessage "No JSON report available, CSV created empty."
fi

[[ -s "${JSON_OUTPUT_PATH}" ]] && \
  logInfoMessage "JSON vulnerability report created: ${JSON_OUTPUT_PATH}" || \
  logWarningMessage "JSON report is empty."

[[ -s "${CSV_OUTPUT_PATH}" ]] && \
  logInfoMessage "CSV vulnerability report created: ${CSV_OUTPUT_PATH}" || \
  logWarningMessage "CSV report is empty."

if [[ ! -s "${CSV_OUTPUT_PATH}" || $(wc -l < "${CSV_OUTPUT_PATH}") -le 1 ]]; then
    logInfoMessage "No vulnerabilities found. Updating CSV file."
    echo "No vulnerabilities found" > "${CSV_OUTPUT_PATH}"
fi


if [ $STATUS -eq 0 ]
then
  logInfoMessage "Congratulations Trivy SBOM scan succeeded!!!"
  cat report/${CSV_OUTPUT_PATH}
  generateOutput ${ACTIVITY_SUB_TASK_CODE} true "Congratulations Trivy SBOM scan succeeded!!!"

elif [ $VALIDATION_FAILURE_ACTION == "FAILURE" ]
  then
    logErrorMessage "Please check Trivy SBOM scan failed!!!"
    cat report/${CSV_OUTPUT_PATH}
    generateOutput ${ACTIVITY_SUB_TASK_CODE} false "Please check Trivy SBOM scan failed!!!"
    exit 1
   else
    logWarningMessage "Please check Trivy SBOM scan failed!!!"
    cat report/${CSV_OUTPUT_PATH}
    generateOutput ${ACTIVITY_SUB_TASK_CODE} true "Please check Trivy SBOM scan failed!!!"
fi
