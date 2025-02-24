# Usamos Ubuntu 24.04 como base
FROM ubuntu:24.04

# Instalamos Apache y OpenSSL
RUN apt update && apt install -y apache2 openssl

# Habilitamos los módulos necesarios
RUN a2enmod headers ssl

# Creamos la carpeta para los certificados
RUN mkdir /etc/apache2/ssl

# Generamos un certificado autofirmado
RUN openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/apache2/ssl/apache-selfsigned.key \
    -out /etc/apache2/ssl/apache-selfsigned.crt \
    -subj "/C=ES/ST=Valencia/L=Valencia/O=Seguridad/OU=IT/CN=localhost"

# Copiamos los archivos de configuración de Apache
COPY default.conf /etc/apache2/sites-available/000-default.conf
COPY default-ssl.conf /etc/apache2/sites-available/default-ssl.conf

# Habilitamos el sitio SSL
RUN a2ensite default-ssl

# Exponemos los puertos HTTP y HTTPS
EXPOSE 80 443

# Iniciamos Apache
CMD ["apachectl", "-D", "FOREGROUND"]
