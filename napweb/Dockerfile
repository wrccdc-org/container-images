
FROM alpine:latest
ENV PHP_VERSION=php82
COPY setupphp.sh /setupphp.sh
RUN apk update && \
    apk add --no-interactive --no-cache \
    curl nginx supervisor msmtp \
    && chmod +x /setupphp.sh \
	&& /setupphp.sh curl \
    fpm \
    opcache \
    zip \
    intl \
    sockets \
    xsl \
    bz2 \
    exif \
    gd \
    ldap \
    mysqli \
    pdo_mysql \
    pdo_pgsql \
    pdo_sqlite \
    gettext \
    mbstring \    
    imap \
    && rm -rf /var/cache/apk/* \
    && sed -i '/APKINDEX/d;/^rm$/d' /etc/apk/world \
    && rm /setupphp.sh
RUN mkdir -p /var/log/php /docker-entrypoint.d \
    && touch /var/log/msmtp.log \
    && chmod 600 /var/log/msmtp.log \ 
    && mkdir -p /run/php \
    && mkdir -p /var/log/supervisord /var/run/
COPY nginx.conf /etc/nginx/nginx.conf
COPY default.conf /etc/nginx/conf.d/default.conf
COPY supervisord.conf /etc/supervisord.conf

WORKDIR /var/www/html
EXPOSE 8080

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf"]


