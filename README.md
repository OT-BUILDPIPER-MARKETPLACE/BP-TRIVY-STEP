# BP-TRIVY-STEP
A BP step to orchestrate trivy execution

## Setup
* Clone the code available at [BP-TRIVY-STEP](https://github.com/OT-BUILDPIPER-MARKETPLACE/BP-TRIVY-STEP)
* Build the docker image
```
git submodule init
git submodule update
docker build -t ot/trivy:0.1 .
```
## Testing
This section will give you a walkthrough of how you can use this image to do various types of testing
Some of the global environment variables that control the behaviour of scanning
* SCAN_SEVERITY | Default - HIGH,CRITICAL | For possible values check documentation
* FORMAT_ARG | Default - table | For possible values check documentation
* OUTPUT_ARG | Default - trivy-report.json | Give any path as per your preference
* SCANNER    | IMAGE,FILESYSTEM
* SCAN_TYPE  vuln,license,secret

### Docker Image Scan

Docker image scan will scan a docker image, this BP step can be used independently and with BuildPiper as well
If you want to use it independently you have to take care of below things

* You have to set IMAGE_NAME env variable
* You have to set IMAGE_TAG env variable
* You have to set SCAN_TYPE env variable
* You have to set SCANNER env variable
* You have to mount /var/run/docker.sock
* You have to set WORKSPACE env variable
* You have to set CODEBASE_DIR env variable

```
# Successful Scan
docker run -it --rm -v /var/run/docker.sock:/var/run/docker.sock -v $PWD:/src -e SCANNER=IMAGE -e SCAN_TYPE=vuln -e WORKSPACE=/ -e CODEBASE_DIR=src -e IMAGE_NAME="ot/trivy" -e IMAGE_TAG=latest ot/trivy:0.1
```

### Filesystem Scan
Filesystem scan will scan a filesystem, this BP step can be used independently and with BuildPiper as well
If you want to use it independently you have to take care of below things
* You have to set SCAN_TYPE env variable
* You have to set SCANNER env variable
* You have to mount /var/run/docker.sock
* You have to set WORKSPACE env variable
* You have to set CODEBASE_DIR env variable

```
# Successful Scan
docker run -it --rm -v /var/run/docker.sock:/var/run/docker.sock -v $PWD:/src -e SCANNER=FILESYSTEM -e SCAN_TYPE=secret -e WORKSPACE=/ -e CODEBASE_DIR=src ot/trivy:0.1
```
## Reference 
* [Docs](https://aquasecurity.github.io/trivy/v0.32/docs/)
* [Blog](https://www.prplbx.com/resources/blog/docker-part2/)
* [Image Scanning](https://aquasecurity.github.io/trivy/v0.32/docs/vulnerability/scanning/image/)
* [Filesystem Scanning](https://aquasecurity.github.io/trivy/v0.32/docs/vulnerability/scanning/filesystem/)
* [Format](https://aquasecurity.github.io/trivy/v0.27.1/docs/vulnerability/examples/report/)
