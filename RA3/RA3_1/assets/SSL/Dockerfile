# Usa la imagen base de PR4 (apache-hardening-dos)
FROM pps10711239/pr4:latest

# Instala OpenSSL (si no está instalado)
RUN apt update && apt install -y openssl

# Crea el directorio para los certificados SSL
RUN mkdir -p /etc/apache2/ssl

# Genera un certificado autofirmado válido por 1 año
RUN openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout /etc/apache2/ssl/apache-selfsigned.key \
  -out /etc/apache2/ssl/apache-selfsigned.crt \
  -subj "/C=ES/ST=Valencia/L=Valencia/O=Seguridad/OU=IT/CN=localhost"

# Copia la configuración SSL en Apache
COPY default-ssl.conf /etc/apache2/sites-available/default-ssl.conf

# Habilita el módulo SSL y el sitio SSL
RUN a2enmod ssl && a2ensite default-ssl

# Reinicia Apache para aplicar cambios
CMD ["apachectl", "-D", "FOREGROUND"]
