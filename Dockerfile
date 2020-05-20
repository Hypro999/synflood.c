FROM ubuntu:18.04

RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get install build-essential libpcap-dev -y \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

WORKDIR ~/synflood
COPY ./ ./

RUN make

ENTRYPOINT ["./run.sh"]

