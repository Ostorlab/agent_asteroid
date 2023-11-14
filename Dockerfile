FROM ubuntu:latest as base

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y software-properties-common \
    && add-apt-repository ppa:deadsnakes/ppa \
    && apt-get remove -y python*

RUN apt-get install -y build-essential \
    python3.11 \
    python3.11-dev \
    python3-pip \
    wireguard \
    iproute2

RUN python3.11 -m pip install --upgrade pip
COPY requirement.txt /requirement.txt
RUN python3.11 -m pip install -r /requirement.txt
RUN mkdir -p /app/agent
ENV PYTHONPATH=/app
COPY agent /app/agent
COPY ostorlab.yaml /app/agent/ostorlab.yaml
WORKDIR /app
CMD ["python3.11", "/app/agent/asteroid.py"]
