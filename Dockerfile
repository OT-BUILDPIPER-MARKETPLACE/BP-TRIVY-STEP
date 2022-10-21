FROM aquasec/trivy:0.32.1

RUN apk add --no-cache --upgrade bash
RUN apk add jq

COPY build.sh .
COPY BP-BASE-SHELL-STEPS/functions.sh .

ENV ACTIVITY_SUB_TASK_CODE BP-TRIVY-TASK
ENV SLEEP_DURATION 5s
ENV VALIDATION_FAILURE_ACTION WARNING
ENV SCANNER "image"

ENTRYPOINT [ "./build.sh" ]