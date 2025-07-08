FROM python:3.11-slim

WORKDIR /app

# Install dependencies
RUN pip install pyyaml

# Copy files
COPY endlessh.py .
COPY config.yaml .
COPY banners.txt .

# Expose port
EXPOSE 2222

CMD ["python", "endlessh.py"]
