FROM aquasec/trivy:0.32.1

RUN apk add --no-cache --upgrade bash
RUN apk add jq

COPY build.sh .
COPY imageTrivyScanner.sh .
COPY filesystemTrivyScanner.sh .
COPY template2CSV.sh .
RUN ls
ADD BP-BASE-SHELL-STEPS /opt/buildpiper/shell-functions/
ADD BP-BASE-SHELL-STEPS/data /opt/buildpiper/data
RUN chmod +x build.sh

ENV APPLICATION_NAME ""
ENV ORGANIZATION ""
ENV SOURCE_KEY ""
ENV REPORT_FILE_PATH ""

ENV MI_SERVER_ADDRESS ""
ENV ACTIVITY_SUB_TASK_CODE BP-TRIVY-TASK
ENV SLEEP_DURATION 5s
ENV VALIDATION_FAILURE_ACTION WARNING
ENV SCANNER "IMAGE"
ENV SCAN_SEVERITY "HIGH,CRITICAL"
ENV FORMAT_ARG "-f json"
ENV OUTPUT_ARG "-o reports/trivy-results.json"

ENTRYPOINT [ "./build.sh" ]
