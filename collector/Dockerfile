FROM ubuntu:22.04

RUN apt-get update -qq && apt-get install -y -qq \
    strace \
    curl wget git \
    python3 python3-pip \
    nmap netcat-openbsd \
    openssh-client \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /archprobe
COPY run_workload.sh /archprobe/
RUN chmod +x /archprobe/run_workload.sh

ENTRYPOINT ["/archprobe/run_workload.sh"]
