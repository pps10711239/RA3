# Usamos Ubuntu 24.04 como base
FROM ubuntu:24.04

# Instalamos las herramientas básicas y agregamos el repositorio de PHP actualizado
RUN apt update && apt install -y software-properties-common && \
    add-apt-repository ppa:ondrej/php -y && \
    apt update

# Instalamos Apache, PHP 8.2 y ModSecurity
RUN apt install -y apache2 php8.2 libapache2-mod-php8.2 libapache2-mod-security2 modsecurity-crs nano

# Habilitamos los módulos necesarios en Apache
RUN a2enmod headers ssl security2 php8.2

# Configuramos ModSecurity para bloquear ataques
RUN cp /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf && \
    sed -i 's/SecRuleEngine DetectionOnly/SecRuleEngine On/' /etc/modsecurity/modsecurity.conf

# Copiamos archivos de configuración de Apache
COPY default.conf /etc/apache2/sites-available/000-default.conf
COPY default-ssl.conf /etc/apache2/sites-available/default-ssl.conf
COPY modsecurity.conf /etc/modsecurity/modsecurity.conf

# Copiamos el archivo PHP en el DocumentRoot
COPY post.php /var/www/html/post.php

# Habilitamos SSL en Apache
RUN a2ensite default-ssl

# Exponemos los puertos HTTP y HTTPS
EXPOSE 80 443

# Iniciamos Apache en primer plano
CMD ["apachectl", "-D", "FOREGROUND"]
