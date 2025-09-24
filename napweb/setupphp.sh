#!/bin/sh -x
set -e
PHP_VERSION=${PHP_VERSION:-php82}
VER_NUM=$(echo "$PHP_VERSION"|sed -e 's/php//g')
echo "Creating symlinks..."

# Symlink php binary
ln -svf /usr/sbin/php-fpm${VER_NUM} /usr/sbin/php || echo "Failure on php symlink"
ln -svf /usr/sbin/php-fpm${VER_NUM} /usr/sbin/php-fpm || echo "Failure on php-fpm symlink"
ln -svf /etc/${PHP_VERSION} /etc/php || echo "Failure on symlink of /etc/php"

if [ "$#" -lt 1 ]; then
    echo "Usage: $0 extension1 [extension2 ...]"
    exit 1
fi

EXTENSIONS="$@"

echo "Installing PHP and extensions..."
apk add --no-cache $PHP_VERSION $(for ext in $EXTENSIONS; do echo "${PHP_VERSION}-$ext"; done)

PHP_INI=$("$PHP_VERSION" --ini | grep "Loaded Configuration" | awk -F': ' '{print $2}' | xargs)
echo "Using php.ini at '$PHP_INI'"

#for ext in $EXTENSIONS; do
#    [ "$ext" = "fpm" ] && continue
#    if grep -q "^\s*;*extension=.*$ext" "$PHP_INI"; then
#        sed -i "s|^\s*;*\(extension=.*$ext\)|\1|" "$PHP_INI"
#    fi
#done

sed -i "s|^\s*error_reporting\s*=.*|error_reporting = E_ALL|" "$PHP_INI"
sed -i "s|^\s*display_errors\s*=.*|display_errors = On|" "$PHP_INI"

echo "PHP extensions installed and enabled successfully!"
/usr/sbin/php -v