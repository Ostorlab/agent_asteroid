FROM python:3.14-slim as base

RUN apt-get update && apt-get install -y \
    default-jdk \
    libpq-dev \
    libffi-dev \
    --no-install-recommends \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

ENV JAVA_HOME=/usr/lib/jvm/java-11-openjdk-amd64
ENV CLASSPATH=/app/agent/Resources/hsqldb.jar:$CLASSPATH
ENV PYTHONPATH=/app

FROM base as builder

RUN apt-get update && apt-get install -y \
    g++ \
    make \
    cmake \
    pkg-config \
    libc6-dev \
    --no-install-recommends

RUN pip install --no-cache-dir uv

WORKDIR /install
COPY requirement.txt .
RUN uv pip install --prefix=/install -r requirement.txt --system

FROM base

COPY --from=builder /install /usr/local

RUN mkdir -p /app/agent
COPY agent /app/agent
COPY ostorlab.yaml /app/agent/ostorlab.yaml

WORKDIR /app
CMD ["python3", "/app/agent/asteroid_agent.py"]