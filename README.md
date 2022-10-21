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

## Reference 
* https://aquasecurity.github.io/trivy/v0.32/docs/
* https://www.prplbx.com/resources/blog/docker-part2/