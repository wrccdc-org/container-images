#
# Dockerfile for mantisbt
#

FROM php:8.2-apache
MAINTAINER wrccdc

ENV MANTIS_VER 2.27.1


ENV MANTIS_URL https://sourceforge.net/projects/mantisbt/files/mantis-stable/${MANTIS_VER}/mantisbt-${MANTIS_VER}.tar.gz
ENV OIDC_PLUGIN_URL https://github.com/FSD-Christian-ADM/MantisOIDC/archive/refs/heads/master.tar.gz

RUN set -xe \
    && apt-get update \
    && apt-get install -y libfreetype6-dev libpng-dev libjpeg-dev libpq-dev libxml2-dev libonig-dev libldap2-dev composer \
    && docker-php-ext-install gd mbstring mysqli pgsql soap \
    && docker-php-ext-configure ldap --with-libdir=lib/x86_64-linux-gnu/ \
    && docker-php-ext-install ldap \
    && rm -rf /var/lib/apt/lists/*

RUN a2enmod rewrite

ENV MANTIS_FILE mantisbt.tar.gz
ENV OIDC_PLUGIN_FILE MantisOIDC.tar.gz

RUN set -xe \
    && curl -fSL ${MANTIS_URL} -o ${MANTIS_FILE} \
    && curl -fsL ${OIDC_PLUGIN_URL} -o ${OIDC_PLUGIN_FILE} \
    && tar -xz --strip-components=1 -f ${MANTIS_FILE} \
    && mkdir ./plugins/MantisOIDC/ \
    && tar -xz -C ./plugins/MantisOIDC/ --strip-components=1 -f ${OIDC_PLUGIN_FILE} \
    && rm ${MANTIS_FILE} ${OIDC_PLUGIN_FILE} \
    && chown -R www-data:www-data . \
    && mv /var/www/html/admin /var/www/ \
    && ln -sf /usr/share/zoneinfo/America/Los_Angeles /etc/localtime \
    && echo 'date.timezone = "America/Los_Angeles"' > /usr/local/etc/php/php.ini \
    && cd plugins/MantisOIDC/pages/assets/lib/OpenID-Connect-PHP/ \
    && composer install || echo composer failed

COPY wrccdc.png /var/www/html/images/logo.png
RUN cp /var/www/html/images/logo.png /var/www/html/images/mantis_logo.png \
    && cp /var/www/html/images/logo.png mantis_logo_notext.png

#COPY config_inc.php /var/www/html/config/
