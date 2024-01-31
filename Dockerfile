FROM aquasec/trivy:0.48.1

RUN apk add --no-cache --upgrade bash
RUN apk add jq

COPY build.sh .
COPY imageTrivyScanner.sh .
COPY filesystemTrivyScanner.sh .
COPY VulnerabilitiesTrivyScanner.sh .
COPY licensesTrivyScanner.sh .
COPY secretTrivyScanner.sh .
COPY BP-BASE-SHELL-STEPS .

ENV ACTIVITY_SUB_TASK_CODE BP-TRIVY-TASK
ENV SLEEP_DURATION 5s
ENV VALIDATION_FAILURE_ACTION WARNING
ENV SCANNER "IMAGE"
ENV SCAN_SEVERITY "HIGH,CRITICAL"
ENV FORMAT_ARG "--format template --template @/contrib/html.tpl"
ENV OUTPUT_ARG "-o trivy-report.html"
ENV FORMAT_ARGONE "--format table"
ENTRYPOINT [ "./build.sh" ]

