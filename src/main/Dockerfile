FROM alpine:3.15.0

# Install python and pip
ENV PYTHONUNBUFFERED=1
RUN apk add --update --no-cache python3 && ln -sf python3 /usr/bin/python
RUN python3 -m ensurepip
RUN pip3 install --no-cache --upgrade pip setuptools

# Pre-requisites for cryptography package
RUN apk add --no-cache gcc musl-dev libffi-dev openssl-dev python3-dev

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

RUN apk del gcc musl-dev libffi-dev openssl-dev python3-dev

COPY . .

CMD kopf run /app/secure_secrets.py
