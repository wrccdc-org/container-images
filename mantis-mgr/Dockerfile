FROM python:3-alpine

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    WORKDIR=/app
WORKDIR /app
RUN apk add --no-cache \
        gcc \
        musl-dev \
        libffi-dev \
        openldap-dev \
        openssl-dev \
        python3-dev \
        mariadb-connector-c-dev
COPY mantis-mgr.py /app/
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt
RUN apk del gcc musl-dev libffi-dev python3-dev
ENTRYPOINT ["python", "mantis-mgr.py"]

