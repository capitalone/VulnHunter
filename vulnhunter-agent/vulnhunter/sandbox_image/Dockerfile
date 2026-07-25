FROM python:3.12-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends bash build-essential ca-certificates curl git jq \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 scanner

COPY runner.py /usr/local/bin/vulnhunter-sandbox-runner
RUN chmod 0555 /usr/local/bin/vulnhunter-sandbox-runner

USER 10001:10001
WORKDIR /work
ENTRYPOINT ["python", "/usr/local/bin/vulnhunter-sandbox-runner"]
