FROM ghcr.io/roadrunner-server/roadrunner:2025 AS roadrunner
FROM alpine:latest
ENV PHP_VERSION=php82
RUN apk update && \
    apk add --no-cache \
    msmtp \
    ${PHP_VERSION} \
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
    && \
    rm -rf /var/cache/apk/*
RUN wget https://frankenphp.dev/install.sh \
    && chmod +x install.sh && ./install.sh \
    && mv frankenphp /usr/local/bin/ \
    && mkdir -p /app /etc/roadrunner /var/log/php /docker-entrypoint.d \
    && touch /var/log/msmtp.log \
    && chmod 600 /var/log/msmtp.log \
    && rm ./install.sh
COPY --from=roadrunner /usr/bin/rr /usr/local/bin/rr
COPY docker/entrypoint.sh /docker-entrypoint.d/
EXPOSE 8080/tcp
WORKDIR /app
RUN chmod +x /docker-entrypoint.d/entrypoint.sh
ENTRYPOINT ["/bin/sh", "/docker-entrypoint.d/entrypoint.sh"]
CMD ["frankenphp", "php-server", "--listen", "0.0.0.0:8080", "--watch"]