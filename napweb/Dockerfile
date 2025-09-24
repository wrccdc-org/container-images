
FROM alpine:latest
ENV PHP_VERSION=php82
RUN apk update && \
    apk add --no-cache \
    nginx supervisor msmtp \
    ${PHP_VERSION} \
    ${PHP_VERSION}-fpm \
    ${PHP_VERSION}-opcache \
    ${PHP_VERSION}-zip \
    ${PHP_VERSION}-intl \
    ${PHP_VERSION}-sockets \
    ${PHP_VERSION}-xsl \
    ${PHP_VERSION}-bz2 \
    ${PHP_VERSION}-exif \
    ${PHP_VERSION}-gd \
    ${PHP_VERSION}-ldap \
    ${PHP_VERSION}-mysqli \
    ${PHP_VERSION}-pdo_mysql \
    ${PHP_VERSION}-pdo_pgsql \
    ${PHP_VERSION}-pdo_sqlite \
    ${PHP_VERSION}-gettext \
    ${PHP_VERSION}-mbstring \    
    ${PHP_VERSION}-imap \
    rm -rf /var/cache/apk/*
RUN mkdir -p /var/log/php /docker-entrypoint.d \
    && touch /var/log/msmtp.log \
    && chmod 600 /var/log/msmtp.log \ 
    && mkdir -p /run/php
COPY default.conf /etc/nginx/conf.d/default.conf
COPY supervisord.conf /etc/supervisord.conf

WORKDIR /var/www/html
EXPOSE 8080

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf"]


