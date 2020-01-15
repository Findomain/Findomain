How to execute a findomain into a docker

1.- Build and Tag Image
docker build -f Dockerfile . -t findomain

2.- RUN Image 
docker run -it --rm findomain /bin/bash

3.- Once inside execute
./findomain-linux