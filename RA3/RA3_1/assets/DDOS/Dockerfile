# Usa la imagen base de Ubuntu
FROM ubuntu:latest

# Mantenedor de la imagen
LABEL maintainer="pps10711239"

# Actualizar el sistema e instalar Apache con módulos de seguridad
RUN apt update && apt install -y \
    apache2 \
    libapache2-mod-security2 \
    libapache2-mod-evasive \
    git \
    curl \
    nano \
    iptables \
    && apt clean

# Habilitar módulos en Apache
RUN a2enmod headers security2 evasive rewrite ssl

# Configurar Content Security Policy (CSP)
RUN echo 'Header set Content-Security-Policy "default-src '\''self'\''; img-src *; media-src media1.com media2.com; script-src userscripts.example.com"' \
    >> /etc/apache2/conf-available/security.conf && \
    a2enconf security

# Configurar ModSecurity con OWASP CRS
RUN git clone https://github.com/coreruleset/coreruleset.git /etc/modsecurity-crs && \
    cp /etc/modsecurity-crs/crs-setup.conf.example /etc/modsecurity-crs/crs-setup.conf && \
    sed -i 's/SecRuleEngine DetectionOnly/SecRuleEngine On/' /etc/modsecurity/modsecurity.conf && \
    echo 'IncludeOptional /etc/modsecurity-crs/crs-setup.conf' >> /etc/apache2/mods-enabled/security2.conf && \
    echo 'IncludeOptional /etc/modsecurity-crs/rules/*.conf' >> /etc/apache2/mods-enabled/security2.conf

# Configurar ModEvasive
RUN mkdir -p /var/log/mod_evasive && \
    chmod 777 /var/log/mod_evasive && \
    echo '<IfModule mod_evasive20.c>' > /etc/apache2/mods-available/evasive.conf && \
    echo '    DOSHashTableSize 3097' >> /etc/apache2/mods-available/evasive.conf && \
    echo '    DOSPageCount 5' >>
