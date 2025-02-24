# Usamos Ubuntu 24.04 como base
FROM ubuntu:24.04

# Instalamos dependencias necesarias
RUN apt update && apt install -y \
    apache2 \
    php \
    libapache2-mod-php \
    libapache2-mod-security2 \
    modsecurity-crs \
    git \
    nano

# Habilitamos los módulos necesarios en Apache
RUN a2enmod headers ssl security2

# Configuramos ModSecurity
RUN cp /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf && \
    sed -i 's/SecRuleEngine DetectionOnly/SecRuleEngine On/' /etc/modsecurity/modsecurity.conf

# Eliminamos el archivo de configuración problemático y lo recreamos con las reglas correctas
RUN rm -f /etc/apache2/mods-enabled/security2.conf
COPY security2.conf /etc/apache2/mods-enabled/security2.conf

# Clonamos las reglas OWASP CRS
RUN git clone https://github.com/SpiderLabs/owasp-modsecurity-crs.git /tmp/owasp-crs && \
    mv /tmp/owasp-crs/crs-setup.conf.example /etc/modsecurity/crs-setup.conf && \
    mv /tmp/owasp-crs/rules/ /etc/modsecurity/ && \
    mkdir -p /etc/modsecurity/rules && \
    cp /etc/modsecurity/rules/*.* /etc/modsecurity/rules/

# Configuramos Apache para usar ModSecurity
RUN echo "ServerName localhost" >> /etc/apache2/apache2.conf

# Añadimos una regla personalizada para pruebas
RUN echo 'SecRule ARGS:testparam "@contains test" "id:123456,deny,status:403,msg:'"'"'Bloqueado por ModSecurity'"'"'"' >> /etc/apache2/sites-available/000-default.conf

# Exponemos los puertos
EXPOSE 80 443

# Iniciamos Apache en primer plano
CMD ["apachectl", "-D", "FOREGROUND"]
