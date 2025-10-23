FROM python:3.13-slim

WORKDIR /app

RUN apt-get update \
    && apt-get install --no-install-recommends -y curl ca-certificates iproute2 nmap sudo \
    && rm -rf /var/lib/apt/lists/*

COPY ./ .

RUN pip install --no-cache-dir fastapi uvicorn

EXPOSE 8001/tcp

ENTRYPOINT ["python", "run.py"]
