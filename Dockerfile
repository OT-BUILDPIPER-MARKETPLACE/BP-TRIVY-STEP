FROM aquasec/trivy:0.32.1

RUN apk add --no-cache --upgrade bash
RUN apk add jq

COPY build.sh .
COPY imageTrivyScanner.sh .
COPY filesystemTrivyScanner.sh .
COPY template2CSV.sh .
COPY BP-BASE-SHELL-STEPS/functions.sh .
COPY BP-BASE-SHELL-STEPS/log-functions.sh .
COPY BP-BASE-SHELL-STEPS/mi-functions.sh .
COPY BP-BASE-SHELL-STEPS/file-functions.sh .
ADD BP-BASE-SHELL-STEPS/data /opt/buildpiper/data

ENV ACTIVITY_SUB_TASK_CODE BP-TRIVY-TASK
ENV SLEEP_DURATION 5s
ENV VALIDATION_FAILURE_ACTION WARNING
ENV SCANNER "IMAGE"
ENV SCAN_SEVERITY "HIGH,CRITICAL"
ENV FORMAT_ARG "-f json"
ENV OUTPUT_ARG "-o reports/trivy-results.json"

ENTRYPOINT [ "./build.sh" ]
