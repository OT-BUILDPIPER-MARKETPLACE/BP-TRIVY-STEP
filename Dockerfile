FROM aquasec/trivy:0.55.2

RUN addgroup -g 65522 buildpiper && \
    adduser -u 65522 -G buildpiper -D -h /home/buildpiper buildpiper && \
    chown -R buildpiper:buildpiper /home/buildpiper

RUN mkdir -p \
    /src/reports \
    /bp/data \
    /bp/execution_dir \
    /opt/buildpiper/shell-functions \
    /opt/buildpiper/data \
    /bp/workspace \
    /usr/local/bin \
    /var/lib/apt/lists \
    /etc/timezone \
    /opt/python_versions \
    /opt/jdk \
    /opt/maven \
    /app/venv && \
    chown -R buildpiper:buildpiper /src /bp /opt /usr /tmp /app

# Install dependencies
RUN apk --no-cache add \
    bash jq gettext libintl curl python3 py3-pip py3-virtualenv

# Create a virtual environment and install Python packages inside it
RUN python3 -m venv /opt/venv && \
    /opt/venv/bin/pip install --no-cache-dir tabulate
# Install dependencies
RUN apk --no-cache add \
    bash jq gettext libintl curl python3 py3-pip py3-virtualenv util-linux
# Set environment variables to use the virtual environment
ENV PATH="/opt/venv/bin:$PATH"

WORKDIR /src
COPY --chown=buildpiper:buildpiper build.sh .
COPY --chown=buildpiper:buildpiper imageTrivyScanner.sh .
COPY --chown=buildpiper:buildpiper filesystemTrivyScanner.sh .
COPY --chown=buildpiper:buildpiper template2CSV.sh .
COPY --chown=buildpiper:buildpiper BP-BASE-SHELL-STEPS /opt/buildpiper/shell-functions/
COPY --chown=buildpiper:buildpiper BP-BASE-SHELL-STEPS/data /opt/buildpiper/data
COPY --chown=buildpiper:buildpiper BP-BASE-SHELL-STEPS/mi-functions.sh /opt/buildpiper/shell-functions/mi-functions.sh

USER buildpiper

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
ENV OUTPUT_ARG "${SCANNER}_trivy-results.json"

ENTRYPOINT [ "./build.sh" ]