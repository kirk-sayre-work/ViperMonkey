# Overview

This dockerfile takes the base ubuntu docker image and layers on
software necessary to run ViperMonkey. 

Note for running docker commands: the following commands use sudo, but
you can also add your user to the docker group to avoid this.

## Using This Dockerfile

### Step 1 - build the docker image
Build it!  './build_docker_image.sh'

NOTE: It is expected to take 5+ minutes to build.

### Step 2 - push to Docker Hub

Log into your Docker hub account.

```
sudo docker login
```

Push the container to Docker Hub.

```
sudo docker push kirksayre/vipermonkey_pypy3:latest
```

