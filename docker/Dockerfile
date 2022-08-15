# docker run -it findomain -t example.com
FROM alpine:latest
LABEL maintainers="wfnintr@null.net,edu4rdshl@protonmail.com"
WORKDIR /opt/findomain
RUN apk --no-cache add unzip curl --quiet
RUN curl -sLO https://github.com/Edu4rdSHL/findomain/releases/latest/download/findomain-linux.zip && \
	unzip findomain-linux.zip && rm findomain-linux.zip && mv findomain /usr/bin/&& chmod +x /usr/bin/findomain
RUN apk del unzip curl --quiet
ENTRYPOINT ["findomain"]
