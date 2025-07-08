FROM python:3.11-slim

LABEL maintainer="stefan@pejcic.rs"
LABEL org.opencontainers.image.title="🐍 EndleSSH Honeypot"
LABEL org.opencontainers.image.description="An SSH tarpit that slows down brute-force bots by feeding them random SSH banners very slowly."
LABEL org.opencontainers.image.version="1.0.0"
LABEL org.opencontainers.image.authors="stefan@pejcic.rs"
LABEL org.opencontainers.image.licenses="MIT"

RUN adduser --disabled-password endlessh
USER endlessh

WORKDIR /home/endlessh

COPY endlessh.py config.yaml banners.txt ./

RUN pip install pyyaml

EXPOSE 2222

CMD ["python", "endlessh.py"]
