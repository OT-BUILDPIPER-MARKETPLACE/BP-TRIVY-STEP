#!/bin/bash

source /opt/buildpiper/shell-functions/functions.sh
source /opt/buildpiper/shell-functions/mi-functions.sh
source /opt/buildpiper/shell-functions/log-functions.sh
source /opt/buildpiper/shell-functions/str-functions.sh
source /opt/buildpiper/shell-functions/file-functions.sh
source /opt/buildpiper/shell-functions/aws-functions.sh
source /opt/buildpiper/shell-functions/getDataFile.sh
source ./login.sh

if [ "$DEBUG" = true ]; then
  set -x
fi


logInfoMessage "============================"
logInfoMessage "Start Trivy Image scanning"
logInfoMessage "============================"

export application=$APPLICATION_NAME
export environment=$(getProjectEnv)
export service=$(getServiceName)
export organization=$ORGANIZATION
export source_key=$SOURCE_KEY
export report_file_path=$REPORT_FILE_PATH


cd ${WORKSPACE}/${CODEBASE_DIR}

if [ -d "reports" ]; then
    true
else
    mkdir reports 
fi

sleep $SLEEP_DURATION

STATUS=0
if [ -z "$IMAGE_NAME" ] || [ -z "$IMAGE_TAG" ]; then
    logInfoMessage "Image name/tag is not provided in env variable $IMAGE_NAME checking it in BP data"
    IMAGE_NAME=$(getImageName)
    IMAGE_TAG=$(getImageTag)
    IMAGE_REGION=$(echo "$IMAGE_NAME" | awk -F'.' '{print $(NF-2)}')

    logInfoMessage "Image Region -> ${IMAGE_REGION}"
    logInfoMessage "Image Name -> ${IMAGE_NAME}"
    logInfoMessage "Image Tag -> ${IMAGE_TAG}"
fi

if docker image inspect "${IMAGE_NAME}:${IMAGE_TAG}" >/dev/null 2>&1; then
    logInfoMessage "Image found locally: ${IMAGE_NAME}:${IMAGE_TAG}"
else
    logWarningMessage "Image not found locally. Pulling ${IMAGE_NAME}:${IMAGE_TAG}"
    logInfoMessage "Logging into configured registries"
    login_all_registries
    docker pull "${IMAGE_NAME}:${IMAGE_TAG}"
    logInfoMessage "Image successful pull ${IMAGE_NAME}:${IMAGE_TAG}"
    if [[ $? -ne 0 ]]; then
        logErrorMessage "Failed to pull image: ${IMAGE_NAME}:${IMAGE_TAG}"
        exit 1
    fi
fi

if [ -z "$IMAGE_NAME" ] || [ -z "$IMAGE_TAG" ]; then
    logErrorMessage "Image name/tag is not available in BP data as well. Please check!"
    STATUS=1
    else
        logInfoMessage "I'll scan image ${IMAGE_NAME}:${IMAGE_TAG} for only ${SCAN_SEVERITY} severities"
        logInfoMessage "Executing Trivy scan command..."

        if [[ "${REPORT_TYPE}" == "json" || "${REPORT_TYPE}" == "both" ]]; then
            
                JSON_REPORT=reports/trivy-img-results.json
                logInfoMessage "Generating JSON report: ${JSON_REPORT}"
                logInfoMessage "Executing trivy image -q --severity ${SCAN_SEVERITY} --format json -o ${JSON_REPORT} ${IMAGE_NAME}:${IMAGE_TAG}"

                trivy image -q --severity ${SCAN_SEVERITY} --format json -o "${JSON_REPORT}" "${IMAGE_NAME}:${IMAGE_TAG}"
                logInfoMessage "Generating JSON report at ${JSON_REPORT}"

            elif [[ "${REPORT_TYPE}" == "html"  || "${REPORT_TYPE}" == "both" ]]; then

                logInfoMessage "Executing trivy image -q --severity ${SCAN_SEVERITY} ${IMAGE_NAME}:${IMAGE_TAG}"

                trivy image -q --severity ${SCAN_SEVERITY} ${IMAGE_NAME}:${IMAGE_TAG}

                logInfoMessage "trivy image -q --severity ${SCAN_SEVERITY} --exit-code 1 ${FORMAT_ARG} ${OUTPUT_ARG} ${IMAGE_NAME}:${IMAGE_TAG}"

                trivy image -q --severity ${SCAN_SEVERITY} --exit-code 1 ${FORMAT_ARG} ${OUTPUT_ARG} ${IMAGE_NAME}:${IMAGE_TAG}


                STATUS=$?

                logWarningMessage "=============================================================="
                logInfoMessage  "CSV report is not generated when HTML report type is selected."
                logWarningMessage "=============================================================="

            else
            logErrorMessage "Invalid REPORT_TYPE provided. Supported: json, html"
        fi
fi


if [[ "${REPORT_TYPE}" == "json" || "${REPORT_TYPE}" == "both" ]]; then

    if [ -s "${JSON_REPORT}" ]; then
            CRITICAL=$(jq '([.Results[]? .Vulnerabilities[]? | select(.Severity=="CRITICAL")] | length)' "${JSON_REPORT}" 2>/dev/null || echo 0)
            HIGH=$(jq '([.Results[]? .Vulnerabilities[]? | select(.Severity=="HIGH")] | length)' "${JSON_REPORT}" 2>/dev/null || echo 0)
            MEDIUM=$(jq '([.Results[]? .Vulnerabilities[]? | select(.Severity=="MEDIUM")] | length)' "${JSON_REPORT}" 2>/dev/null || echo 0)
            LOW=$(jq '([.Results[]? .Vulnerabilities[]? | select(.Severity=="LOW")] | length)' "${JSON_REPORT}" 2>/dev/null || echo 0)
        else
         CRITICAL=0; HIGH=0; MEDIUM=0; LOW=0
    fi
    logInfoMessage "Image vulnerabilities -> CRITICAL=${CRITICAL}, HIGH=${HIGH}, MEDIUM=${MEDIUM}, LOW=${LOW}"

    HORIZONTAL_CSV="reports/trivy_image.csv"

    echo "Library,CVE_ID,Severity,InstalledVersion,FixedVersion,Title" > "${HORIZONTAL_CSV}"

    if [ -s "${JSON_REPORT}" ]; then
        jq -r '
        .Results[]? 
        | select(.Vulnerabilities != null)
        | .Vulnerabilities[]?
        | [
            (.PkgName // "N/A"),
            (.VulnerabilityID // "N/A"),
            (.Severity // "N/A"),
            (.InstalledVersion // "N/A"),
            (.FixedVersion // "N/A"),
            (.Title // "N/A")
            ] | @csv
        ' "${JSON_REPORT}" >> "${HORIZONTAL_CSV}" || true
        
            logInfoMessage "Generated horizontal CVE CSV: ${HORIZONTAL_CSV}"
        else
            logWarningMessage "No JSON report available; horizontal CSV created empty."
    fi

fi


if [ -n "${GLOBAL_TASK_ID}" ]; then
    cp -rf reports/* "/bp/execution_dir/${GLOBAL_TASK_ID}/"
    logInfoMessage "Copied reports to /bp/execution_dir/${GLOBAL_TASK_ID}/"
else
    logWarningMessage "GLOBAL_TASK_ID not set; skipping UI copy"
fi


if [[ -n "${MI_SERVER:-}" ]]; then
    logInfoMessage "MI_SERVER is set to ${MI_SERVER}. Starting MI data send process..."


    logInfoMessage "Executing trivy image -q --severity ${SCAN_SEVERITY} --exit-code 1 --format template --template '{{- $critical := 0 }}{{- $high := 0 }}{{- range . }}{{- range .Vulnerabilities }}{{- if  eq .Severity "CRITICAL" }}{{- $critical = add $critical 1 }}{{- end }}{{- if  eq .Severity "HIGH" }}{{- $high = add $high 1 }}{{- end }}{{- end }}{{- end }}Critical: {{ $critical }}, High: {{ $high }}' ${OUTPUT_ARG} ${IMAGE_NAME}:${IMAGE_TAG}"

    trivy image -q --severity ${SCAN_SEVERITY} --exit-code 1 --format template --template '{{- $critical := 0 }}{{- $high := 0 }}{{- range . }}{{- range .Vulnerabilities }}{{- if  eq .Severity "CRITICAL" }}{{- $critical = add $critical 1 }}{{- end }}{{- if  eq .Severity "HIGH" }}{{- $high = add $high 1 }}{{- end }}{{- end }}{{- end }}Critical: {{ $critical }}, High: {{ $high }}' ${OUTPUT_ARG} ${IMAGE_NAME}:${IMAGE_TAG}

    awk 'BEGIN { FS="[:,]"; OFS="," }
    {
        for (i = 1; i <= NF; i += 2) {
            gsub(/ /, "", $i); # Remove spaces from keys
            header = (header ? header OFS : "") $i;
            value = (value ? value OFS : "") $(i+1);
        }
        print header > "reports/trivy_mi.csv";
        print value >> "reports/trivy_mi.csv";
    }' reports/trivy-img-results.json
    
    STATUS=$?

    logInfoMessage "Displaying Original Report: reports/trivy_mi.csv"
    echo "================================================================================"
    python3 /opt/buildpiper/shell-functions/print_table.py reports/trivy_mi.csv
    echo "================================================================================"

    export base64EncodedResponse=$(encodeFileContent reports/trivy_mi.csv)

    # Sending MI data
    export metrics=("trivy_critical" "trivy_high")
    MI_SEND_STATUS=0

    for metric in "${metrics[@]}"; do
        export source_key="${metric}"
        export report_file_path=$REPORT_FILE_PATH

        generateMIDataJson /opt/buildpiper/data/mi.template trivy.mi

        logInfoMessage "Sending ${metric} data to MI server..."
        logWarningMessage "Loading encoded data trivy.mi..."
        cat trivy.mi

        if ! sendMIData trivy.mi "${MI_SERVER}"; then
            logErrorMessage "Failed to push data for ${metric} to MI server"
            MI_SEND_STATUS=1
        else
            logInfoMessage "Successfully sent data for ${metric}"
        fi
    done

    if [ "$MI_SEND_STATUS" -eq 0 ]; then
        logInfoMessage "Trivy scan succeeded, and all metrics were sent to the MI server successfully!"
    else
        logErrorMessage "Some metrics failed to send. Please check the MI server or JSON format."
    fi
else
    logWarningMessage "MI_SERVER variable not set. Skipping MI data send block."
fi

if [ $STATUS -eq 0 ]; then
    logInfoMessage "Congratulations! Trivy scan succeeded!"
    generateOutput ${ACTIVITY_SUB_TASK_CODE} true "Congratulations! Trivy scan succeeded!"
elif [ "$VALIDATION_FAILURE_ACTION" == "FAILURE" ]; then
    logErrorMessage "Trivy scan failed!"
    generateOutput ${ACTIVITY_SUB_TASK_CODE} false "Trivy scan failed!"
    exit 1
else
    logWarningMessage "Trivy scan failed!"
    generateOutput ${ACTIVITY_SUB_TASK_CODE} true "Trivy scan failed!"
fi
