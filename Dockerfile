FROM aquasec/trivy:0.48.3

RUN apk add --no-cache --upgrade bash
RUN apk add jq

COPY build.sh .
COPY imageTrivyScanner.sh .
COPY filesystemTrivyScanner.sh .
COPY repoTrivyScanner.sh .

COPY BP-BASE-SHELL-STEPS/functions.sh .
COPY BP-BASE-SHELL-STEPS/log-functions.sh .

ENV IMAGE_NAME registry.buildpiper.in/trivy-scan
ENV IMAGE_TAG 1.2
ENV ACTIVITY_SUB_TASK_CODE BP-TRIVY-TASK
ENV SLEEP_DURATION 5s
ENV VALIDATION_FAILURE_ACTION WARNING
ENV SCANNER "REPO"
ENV SCAN_TYPE "license"
ENV SCAN_SEVERITY "HIGH,CRITICAL"
ENV FORMAT_ARG "json"
ENV OUTPUT_ARG "trivy-report.json"
ENTRYPOINT [ "./build.sh" ]
