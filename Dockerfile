FROM golang:1.17
VOLUME /sources
RUN mkdir -p /sources
RUN apt-get update
RUN apt-get -y install python2.7
