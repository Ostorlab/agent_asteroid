FROM python:3.11-slim as base
FROM base as builder
RUN mkdir /install
WORKDIR /install
COPY requirement.txt /requirement.txt
RUN pip install --prefix=/install -r /requirement.txt
FROM base
COPY --from=builder /install /usr/local
RUN mkdir -p /app/agent
ENV PYTHONPATH=/app
COPY agent /app/agent
COPY ostorlab.yaml /app/agent/ostorlab.yaml
WORKDIR /app
CMD ["python3", "/app/agent/asteroid_agent.py"]
