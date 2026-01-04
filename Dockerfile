FROM aquasec/trivy:0.55.2

WORKDIR /home/buildpiper


RUN apk --no-cache add \
    bash jq gettext libintl curl python3 py3-pip py3-virtualenv docker-cli && \
    addgroup -g 65522 buildpiper && \
    adduser -D -h /home/buildpiper -u 65522 -G buildpiper buildpiper && \
    mkdir -p /home/buildpiper && \
    chown -R buildpiper:buildpiper /home/buildpiper

RUN apk --no-cache add aws-cli
# Create a virtual environment and install Python packages inside it
RUN python3 -m venv /opt/venv && \
    /opt/venv/bin/pip install --no-cache-dir tabulate

# Set environment variables to use the virtual environment
ENV PATH="/opt/venv/bin:$PATH"

# Create necessary directories and assign permissions early
RUN mkdir -p \
    /src/reports \
    /bp/data \
    /bp/execution_dir \
    /opt/buildpiper/shell-functions \
    /opt/buildpiper/data \
    /bp/workspace && \
    chown -R buildpiper:buildpiper /src /bp /opt

# Copy files with correct ownership
COPY --chown=buildpiper:buildpiper build.sh /home/buildpiper/build.sh
COPY --chown=buildpiper:buildpiper BP-BASE-SHELL-STEPS /opt/buildpiper/shell-functions/
COPY --chown=buildpiper:buildpiper BP-BASE-SHELL-STEPS/data /opt/buildpiper/data/

# Make the build script executable
RUN chmod +x /home/buildpiper/build.sh

COPY build.sh .
COPY imageTrivyScanner.sh .
COPY filesystemTrivyScanner.sh .
COPY template2CSV.sh .
COPY sbom-image-generate.sh .
COPY trivy-sbom-scan.sh .
COPY sbom-fs-generate.sh .
COPY loging.sh .
ADD BP-BASE-SHELL-STEPS /opt/buildpiper/shell-functions/
ADD BP-BASE-SHELL-STEPS/data /opt/buildpiper/data

# Application and organization info
ENV APPLICATION_NAME="" \
    ORGANIZATION="" \
    SOURCE_KEY="" \
    REPORT_FILE_PATH="null" \
    MI_SERVER_ADDRESS=""

# Task and execution configuration
ENV ACTIVITY_SUB_TASK_CODE="BP-TRIVY-TASK" \
    SLEEP_DURATION="5s" \
    VALIDATION_FAILURE_ACTION="WARNING"

ENV SCANNER="IMAGE" \                         
    SCAN_SEVERITY="HIGH,CRITICAL" \
    FORMAT_ARG="--format template --template @/contrib/html.tpl" \
    OUTPUT_ARG="-o reports/trivy-img-results.html"

ENV OUTPUT_FS_ARG="-o reports/trivy-fs-results.html" \
    SBOM_FS_REPORT_NAME="sbom.fs.cdx.json"

ENV SBOM_REPORT_NAME="sbom.img.cdx.json" \
    SBOM_FORMAT_ARG="cyclonedx"

ENV SBOM_SCAN_FORMAT="json" \
    SBOM_SCAN_REPORT_NAME="sbom_scan_report.json" \
    OUTPUT_CSV="sbom_scan_report.csv" \
    TRIVY_CACHE_DIR="/home/buildpiper/.cache/trivy"


RUN chown -R buildpiper:buildpiper /bp/workspace && \
    mkdir -p /home/buildpiper/reports && \
    chown -R buildpiper:buildpiper /home/buildpiper

# Switch to non-root user
USER buildpiper

ENTRYPOINT [ "./build.sh" ]




    
