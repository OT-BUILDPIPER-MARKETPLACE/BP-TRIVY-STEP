FROM aquasec/trivy:0.32.1

RUN apk add --no-cache --upgrade bash
RUN apk add jq

COPY build.sh .
COPY imageTrivyScanner.sh .
COPY filesystemTrivyScanner.sh .
ADD BP-BASE-SHELL-STEPS /opt/buildpiper/shell-functions/

ENV ACTIVITY_SUB_TASK_CODE BP-TRIVY-TASK
ENV SLEEP_DURATION 5s
ENV VALIDATION_FAILURE_ACTION WARNING
ENV SCANNER "IMAGE"
ENV SCAN_SEVERITY "HIGH,CRITICAL"
ENV FORMAT_ARG "--format template --template @/contrib/html.tpl"
ENV OUTPUT_ARG "-o trivy-report.html"

ENTRYPOINT [ "./build.sh" ]