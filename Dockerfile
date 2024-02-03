FROM aquasec/trivy:0.48.3

RUN apk add --no-cache --upgrade bash
RUN apk add jq

COPY build.sh .
COPY imageTrivyScanner.sh .
COPY filesystemTrivyScanner.sh .
COPY repoTrivyScanner.sh .

COPY functions.sh .
COPY log-functions.sh .

ENV ACTIVITY_SUB_TASK_CODE BP-TRIVY-TASK
ENV SLEEP_DURATION 5s
ENV VALIDATION_FAILURE_ACTION WARNING
ENV SCANNER "REPO"
ENV SCAN_TYPE "license"
ENV SCAN_SEVERITY "HIGH,CRITICAL"
ENV FORMAT_ARG "--format json"
ENV OUTPUT_ARG "trivy-report.json"
ENTRYPOINT [ "./build.sh" ]
