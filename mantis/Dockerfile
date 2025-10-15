#
# Dockerfile for mantisbt
#

FROM php:8.2-apache
LABEL maintainer="wrccdc"

ENV MANTIS_VER=2.27.1
ENV MANTIS_URL=https://sourceforge.net/projects/mantisbt/files/mantis-stable/${MANTIS_VER}/mantisbt-${MANTIS_VER}.tar.gz
ENV OIDC_PLUGIN_URL=https://github.com/initOS/MantisOIDC/archive/refs/heads/scopes-and-user-mapping.tar.gz

# Install dependencies and Composer
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        libfreetype6-dev libpng-dev libjpeg-dev libpq-dev libxml2-dev libonig-dev libldap2-dev curl unzip git; \
    docker-php-ext-configure gd --with-freetype --with-jpeg; \
    docker-php-ext-install gd mbstring mysqli pgsql soap ldap \
    # Install Composer globally
    && curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer; \
    \
    rm -rf /var/lib/apt/lists/*

RUN a2enmod rewrite

ENV MANTIS_FILE=mantisbt.tar.gz
ENV OIDC_PLUGIN_FILE=MantisOIDC.tar.gz

WORKDIR /var/www/html

RUN set -eux; \
    curl -fSL "${MANTIS_URL}" -o "${MANTIS_FILE}"; \
    curl -fsSL "${OIDC_PLUGIN_URL}" -o "${OIDC_PLUGIN_FILE}"; \
    tar -xzf "${MANTIS_FILE}" --strip-components=1; \
    mkdir -p ./plugins/MantisOIDC; \
    tar -xzf "${OIDC_PLUGIN_FILE}" -C ./plugins/MantisOIDC --strip-components=1; \
    rm "${MANTIS_FILE}" "${OIDC_PLUGIN_FILE}"; \
    chown -R www-data:www-data .; \
    mv /var/www/html/admin /var/www/; \
    ln -sf /usr/share/zoneinfo/America/Los_Angeles /etc/localtime; \
    echo 'date.timezone = "America/Los_Angeles"' > /usr/local/etc/php/conf.d/timezone.ini; \
    cd plugins/MantisOIDC/pages/assets/lib/OpenID-Connect-PHP; \
    composer install || echo "composer failed"

COPY wrccdc.png /var/www/html/images/logo.png
RUN cp /var/www/html/images/logo.png /var/www/html/images/mantis_logo.png \
    && cp /var/www/html/images/logo.png /var/www/html/images/mantis_logo_notext.png
    
