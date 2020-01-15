FROM ubuntu:19.04
RUN  apt-get update \
  && apt-get install -y wget \
  && rm -rf /var/lib/apt/lists/*
RUN wget -O /usr/bin/findomain https://github.com/Edu4rdSHL/findomain/releases/latest/download/findomain-linux
RUN chmod +x /usr/bin/findomain
RUN  apt-get remove --autoremove -y wget
