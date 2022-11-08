# BP-TRIVY-STEP
A BP step to orchestrate trivy execution

## Important Note
Since git submodule doesn't support the concept of tags, we have to follow this unorhtodox approach
So as and when a new tag of BP-BASE-SHELL-STEPS is released we have to perform below operation to update submodule
```
cd BP-BASE-SHELL-STEPS
git checkout v0.2
cd ..
git add BP-BASE-SHELL-STEPS
git commit -m "moved submodule to v0.2"
git push
```

## Setup
* Clone the code available at [BP-TRIVY-STEP](https://github.com/OT-BUILDPIPER-MARKETPLACE/BP-TRIVY-STEP)
* Build the docker image
```
git submodule init
git submodule update
docker build -t ot/trivy:0.2 .
```
## Testing
This section will give you a walkthrough of how you can use this image to do various types of testing
Some of the global environment variables that control the behaviour of scanning
* SCAN_SEVERITY | Default - HIGH,CRITICAL | For possible values check documentation
* FORMAT_ARG | Default - html | For possible values check documentation
* OUTPUT_ARG | Default - trivy-report.html | Give any path as per your preference


### Docker Image Scan

Docker image scan will scan a docker image, this BP step can be used independently and with BuildPiper as well
If you want to use it independently you have to take care of below things
    * You have to set IMAGE_NAME env variable
    * You have to set IMAGE_TAG env variable
    * You have to mount /var/run/docker.sock
    * You have to set WORKSPACE env variable
    * You have to set CODEBASE_DIR env variable

* Do local testing via image only

```
# Failed Scan
docker run -it --rm -v /var/run/docker.sock:/var/run/docker.sock -v $PWD:/src -e WORKSPACE=/ -e CODEBASE_DIR=src -e IMAGE_NAME="ot/trivy" -e IMAGE_TAG=0.1 ot/trivy:0.2
```

```
# Successful Scan
docker run -it --rm -v /var/run/docker.sock:/var/run/docker.sock -v $PWD:/src -e WORKSPACE=/ -e CODEBASE_DIR=src -e IMAGE_NAME="ot/trivy" -e IMAGE_TAG=0.1 -e SCAN_SEVERITY="CRITICAL" ot/trivy:0.2
```

### Filesystem Scan
Filesystem scan will scan a filesystem, this BP step can be used independently and with BuildPiper as well

```
# Successful Scan
docker run -it --rm -v $PWD:/src -e WORKSPACE=/ -e CODEBASE_DIR=src -e SCANNER=FILESYSTEM ot/trivy:0.2
```

* Debugging
```
docker run -it --rm -v /var/run/docker.sock:/var/run/docker.sock -v $PWD:/src -e WORKSPACE=/ -e CODEBASE_DIR=src -e IMAGE_NAME="ot/trivy" -e IMAGE_TAG=0.1 --entrypoint bash ot/trivy:0.2
```
## Reference 
* [Docs](https://aquasecurity.github.io/trivy/v0.32/docs/)
* [Blog](https://www.prplbx.com/resources/blog/docker-part2/)
* [Image Scanning](https://aquasecurity.github.io/trivy/v0.32/docs/vulnerability/scanning/image/)
* [Filesystem Scanning](https://aquasecurity.github.io/trivy/v0.32/docs/vulnerability/scanning/filesystem/)
* [Format](https://aquasecurity.github.io/trivy/v0.27.1/docs/vulnerability/examples/report/)