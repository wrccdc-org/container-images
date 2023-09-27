#
# Dockerfile for mantisbt
#

FROM php:7.4-apache
MAINTAINER kev <noreply@easypi.pro>

ENV MANTIS_VER 2.25.7

RUN a2enmod rewrite

RUN set -xe \
    && apt-get update \
    && apt-get install -y libfreetype6-dev libpng-dev libjpeg-dev libpq-dev libxml2-dev libonig-dev libldap2-dev \
    && docker-php-ext-install gd mbstring mysqli pgsql soap \
    && docker-php-ext-configure ldap --with-libdir=lib/x86_64-linux-gnu/ \
    && docker-php-ext-install ldap \
    && rm -rf /var/lib/apt/lists/*

RUN a2enmod rewrite

ENV MANTIS_URL https://sourceforge.net/projects/mantisbt/files/mantis-stable/${MANTIS_VER}/mantisbt-${MANTIS_VER}.tar.gz
ENV MANTIS_FILE mantisbt.tar.gz

RUN set -xe \
    && curl -fSL ${MANTIS_URL} -o ${MANTIS_FILE} \
    && tar -xz --strip-components=1 -f ${MANTIS_FILE} \
    && rm ${MANTIS_FILE} \
    && chown -R www-data:www-data . \
    && mv /var/www/html/admin /var/www/ \
    && ln -sf /usr/share/zoneinfo/America/Los_Angeles /etc/localtime \
    && echo 'date.timezone = "America/Los_Angeles"' > /usr/local/etc/php/php.ini

COPY wrccdc.png /var/www/html/images/
COPY *.crt /usr/local/share/ca-certificates/
RUN cp /var/www/html/images/wrccdc.png /var/www/html/images/mantis_logo.png \
    && cp /var/www/html/images/wrccdc.png mantis_logo_notext.png \
    && ls -1 /usr/local/share/ca-certificates/ \
    && update-ca-certificates --verbose

#COPY config_inc.php /var/www/html/config/
