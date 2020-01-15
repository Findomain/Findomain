# How to execute a findomain in a docker container

1. Build and tag the image.

``$ docker build -f Dockerfile . -t findomain``

2. Run the image.

``$ docker run -it --rm findomain /bin/bash``

3. Execute

``$ findomain``
