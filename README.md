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


### Docker Image

* Do local testing via image only
** Failed Scan
```
docker run -it --rm -v /var/run/docker.sock:/var/run/docker.sock -e IMAGE_NAME="ot/trivy" -e IMAGE_TAG=0.1 ot/trivy:0.1
```
** Successful Scan
```
docker run -it --rm -v /var/run/docker.sock:/var/run/docker.sock -e IMAGE_NAME="ot/trivy" -e IMAGE_TAG=0.1 -e SCAN_SEVERITY="CRITICAL" ot/trivy:0.1
```
* Debugging
```
docker run -it --rm -v /var/run/docker.sock:/var/run/docker.sock -e IMAGE_NAME="ot/trivy" -e IMAGE_TAG=0.1 --entrypoint bash ot/trivy:0.1
```
## Reference 
* [Docs](https://aquasecurity.github.io/trivy/v0.32/docs/)
* [Blog](https://www.prplbx.com/resources/blog/docker-part2/)
* [Image Scanning](https://aquasecurity.github.io/trivy/v0.32/docs/vulnerability/scanning/image/)