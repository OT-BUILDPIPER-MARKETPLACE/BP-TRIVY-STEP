FROM aquasec/trivy:0.55.2

# Install dependencies
RUN apk --no-cache add \
    bash jq gettext libintl curl python3 py3-pip py3-virtualenv

# Create a virtual environment and install Python packages inside it
RUN python3 -m venv /opt/venv && \
    /opt/venv/bin/pip install --no-cache-dir tabulate

# Set environment variables to use the virtual environment
ENV PATH="/opt/venv/bin:$PATH"

WORKDIR /src
COPY build.sh .
COPY imageTrivyScanner.sh .
COPY filesystemTrivyScanner.sh .
COPY template2CSV.sh .
ADD BP-BASE-SHELL-STEPS /opt/buildpiper/shell-functions/
ADD BP-BASE-SHELL-STEPS/data /opt/buildpiper/data

ENV APPLICATION_NAME ""
ENV ORGANIZATION ""
ENV SOURCE_KEY ""
ENV REPORT_FILE_PATH null
ENV MI_SERVER_ADDRESS ""
ENV ACTIVITY_SUB_TASK_CODE BP-TRIVY-TASK
ENV SLEEP_DURATION 5s
ENV VALIDATION_FAILURE_ACTION WARNING
ENV SCANNER "IMAGE"
ENV SCAN_SEVERITY "HIGH,CRITICAL"
ENV FORMAT_ARG "-f json"
ENV OUTPUT_ARG "-o reports/trivy-results.json"

ENTRYPOINT [ "./build.sh" ]
