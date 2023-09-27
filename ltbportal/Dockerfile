FROM docker.io/ltbproject/self-service-password:1.5.3
COPY ./*.crt //usr/local/share/ca-certificates/
COPY ./*.crt /etc/ca-certificates/
COPY WRCCDC.png /var/www/html/images/
RUN update-ca-certificates --verbose

