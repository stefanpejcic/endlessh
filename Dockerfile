FROM python:3.11-slim

LABEL maintainer="stefan@pejcic.rs"
LABEL org.opencontainers.image.title="🐍 Endlessh Honeypot"
LABEL org.opencontainers.image.description="An SSH tarpit that slows down brute-force bots by feeding them random SSH banners very slowly."
LABEL org.opencontainers.image.version="1.0.0"
LABEL org.opencontainers.image.authors="Stefan Pejcic <stefan@pejcic.rs>"
LABEL org.opencontainers.image.licenses="MIT"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /home/endlessh/

COPY endlessh.py ./

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt


EXPOSE 2222

CMD ["python", "endlessh.py"]
