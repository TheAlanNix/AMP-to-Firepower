FROM python:3.7-alpine

RUN apk add --no-cache openssl perl perl-io-socket-ssl perl-yaml-xs

ENV PERL_USE_UNSAFE_INC=1

WORKDIR /app

COPY requirements.txt /app

RUN pip install --no-cache-dir -r requirements.txt

COPY HostInputSDK /app/HostInputSDK
COPY amp_client.py /app

COPY amp_to_firepower.py /app

ENTRYPOINT ["python", "-u", "amp_to_firepower.py", "-d"]
