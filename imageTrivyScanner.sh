#!/bin/bash

source /opt/buildpiper/shell-functions/functions.sh
source /opt/buildpiper/shell-functions/mi-functions.sh
source /opt/buildpiper/shell-functions/log-functions.sh
source /opt/buildpiper/shell-functions/str-functions.sh
source /opt/buildpiper/shell-functions/file-functions.sh
source /opt/buildpiper/shell-functions/aws-functions.sh
#source /opt/buildpiper/shell-functions/getDataFile.sh

export application=$APPLICATION_NAME
export environment=$(getProjectEnv)
export service=$(getServiceName)
export organization=$ORGANIZATION
export source_key=$SOURCE_KEY
export report_file_path=$REPORT_FILE_PATH

cd ${WORKSPACE}/${CODEBASE_DIR}

mkdir -p reports

STATUS=0
# if [ -z "$IMAGE_NAME" ] || [ -z "$IMAGE_TAG" ]; then
#     logInfoMessage "Image name/tag is not provided in env variable $IMAGE_NAME checking it in BP data"
#     IMAGE_NAME=$(getImageName)
#     IMAGE_TAG=$(getImageTag)
#     logInfoMessage "Image Name -> ${IMAGE_NAME}"
#     logInfoMessage "Image Tag -> ${IMAGE_TAG}"
# fi
if [ -z "$IMAGE_NAME" ] || [ -z "$IMAGE_TAG" ]; then
    logErrorMessage "IMAGE_NAME or IMAGE_TAG is not provided. Please set both environment variables."
    STATUS=1
else
    logInfoMessage "Using Image Name -> ${IMAGE_NAME}"
    logInfoMessage "Using Image Tag  -> ${IMAGE_TAG}"
fi

if [ -z "$IMAGE_NAME" ] || [ -z "$IMAGE_TAG" ]; then
    logErrorMessage "Image name/tag is not available in BP data as well. Please check!"
    STATUS=1
else
    logInfoMessage "I'll scan image ${IMAGE_NAME}:${IMAGE_TAG} for only ${SCAN_SEVERITY} severities"
    sleep $SLEEP_DURATION
    logInfoMessage "Executing Trivy scan command..."
    
    mkdir -p reports

    # Running Trivy scan and generating reports
    logInfoMessage "Executing trivy image -q --severity ${SCAN_SEVERITY} ${IMAGE_NAME}:${IMAGE_TAG}"

    trivy image -q --severity ${SCAN_SEVERITY} ${IMAGE_NAME}:${IMAGE_TAG}

    logInfoMessage "trivy image -q --severity ${SCAN_SEVERITY} --exit-code 1 ${FORMAT_ARG} ${OUTPUT_ARG} ${IMAGE_NAME}:${IMAGE_TAG}"
    mkdir -p reports
    trivy image -q --severity ${SCAN_SEVERITY} --exit-code 1 ${FORMAT_ARG} ${OUTPUT_ARG} ${IMAGE_NAME}:${IMAGE_TAG}

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
    }' reports/trivy-results.json

    STATUS=$?

    logInfoMessage "Trivy scan completed successfully!"

    logInfoMessage "Updating reports in /bp/execution_dir/${GLOBAL_TASK_ID}......."
    cp -rf reports/* /bp/execution_dir/${GLOBAL_TASK_ID}/

    logInfoMessage "Displaying Original Report: reports/trivy_mi.csv"
    echo "================================================================================"
    python3 /opt/buildpiper/shell-functions/print_table.py reports/trivy_mi.csv
    echo "================================================================================"

    export base64EncodedResponse=`encodeFileContent reports/trivy_mi.csv`

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

        if ! sendMIData trivy.mi ${MI_SERVER_ADDRESS}; then
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
