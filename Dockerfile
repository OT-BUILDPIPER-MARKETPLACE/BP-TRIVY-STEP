FROM aquasec/trivy:0.55.2

WORKDIR /home/buildpiper


RUN apk --no-cache add \
    bash jq gettext libintl curl python3 py3-tabulate py3-cryptography docker-cli aws-cli && \
    addgroup -g 65522 buildpiper && \
    adduser -D -h /home/buildpiper -u 65522 -G buildpiper buildpiper && \
    mkdir -p /home/buildpiper && \
    chown -R buildpiper:buildpiper /home/buildpiper
ENV DOCKER_CONFIG=/tmp/.docker
RUN mkdir -p /tmp/.docker && chmod 700 /tmp/.docker

# Create necessary directories and assign permissions early
RUN mkdir -p \
    /src/reports \
    /bp/data \
    /bp/execution_dir \
    /opt/buildpiper/shell-functions \
    /opt/buildpiper/data \
    /bp/workspace && \
    chown -R buildpiper:buildpiper /src /bp /opt /home/buildpiper/ /tmp/.docker

# Copy files with correct ownership
COPY --chown=buildpiper:buildpiper build.sh /home/buildpiper/build.sh
COPY --chown=buildpiper:buildpiper login.sh /home/buildpiper/login.sh
COPY --chown=buildpiper:buildpiper imageTrivyScanner.sh /home/buildpiper/imageTrivyScanner.sh
COPY --chown=buildpiper:buildpiper filesystemTrivyScanner.sh /home/buildpiper/filesystemTrivyScanner.sh
COPY --chown=buildpiper:buildpiper template2CSV.sh /home/buildpiper/template2CSV.sh
COPY --chown=buildpiper:buildpiper sbom-image-generate.sh /home/buildpiper/sbom-image-generate.sh
COPY --chown=buildpiper:buildpiper trivy-sbom-scan.sh /home/buildpiper/trivy-sbom-scan.sh
COPY --chown=buildpiper:buildpiper sbom-fs-generate.sh /home/buildpiper/sbom-fs-generate.sh
COPY --chown=buildpiper:buildpiper BP-BASE-SHELL-STEPS /opt/buildpiper/shell-functions/

# Make the build script executable
RUN chmod +x /home/buildpiper/*.sh

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