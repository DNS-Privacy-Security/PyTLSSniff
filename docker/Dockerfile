FROM python:3.8

WORKDIR /usr/src/app

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y tshark \
 && rm -rf /var/lib/apt/lists/*
ENV DEBIAN_FRONTEND=

COPY pytlssniff pytlssniff
COPY requirements.txt ./

RUN pip install --no-cache-dir -r requirements.txt \
 && rm -rf ~/.cache/*

ENTRYPOINT [ "python", "-u", "-m", "pytlssniff" ]
