FROM python:3.11-slim

RUN adduser --disabled-password endlessh
USER endlessh

WORKDIR /home/endlessh

COPY endlessh.py config.yaml banners.txt ./

RUN pip install pyyaml

EXPOSE 2222

CMD ["python", "endlessh.py"]
