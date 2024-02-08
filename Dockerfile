FROM aquasec/trivy:0.48.3

RUN apk add --no-cache --upgrade bash
RUN apk add jq

COPY filesystemTrivyScanner.sh .
COPY imageTrivyScanner.sh .
COPY build.sh .
ADD BP-BASE-SHELL-STEPS /opt/buildpiper/shell-functions/

ENV ACTIVITY_SUB_TASK_CODE BP-TRIVY-TASK
ENV SLEEP_DURATION 5s
ENV VALIDATION_FAILURE_ACTION WARNING
ENV SCANNER ""
ENV IMAGE_NAME ""
ENV IMAGE_TAG ""

ENV SCAN_TYPE ""
ENV SCAN_SEVERITY "HIGH,CRITICAL"
ENV FORMAT_ARG "table"
ENV OUTPUT_ARG "trivy-report.json"
ENTRYPOINT [ "./build.sh" ]
