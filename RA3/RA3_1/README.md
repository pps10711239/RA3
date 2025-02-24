# RA3_1

## Introduction

La presente documentación cubre la configuración de seguridad para Apache dentro de un contenedor Docker, implementando distintas prácticas de hardening para reforzar la seguridad del servidor en un entorno de producción segura. La seguridad en la puesta en producción es un aspecto crítico para garantizar la integridad, disponibilidad y confidencialidad de los servicios web. En este contexto, se aplicarán configuraciones avanzadas para mitigar riesgos como ataques de ejecución remota de código (RCE), Cross-Site Scripting (XSS), inyección SQL (SQLi), ataques de denegación de servicio (DDoS) y otras amenazas documentadas en el OWASP Top 10.

Para ello, se implementarán estrategias de seguridad en capas que incluyen políticas de seguridad de contenido (CSP), encabezados de seguridad estrictos (HSTS), firewalls de aplicaciones web (WAF) y módulos específicos de Apache como `mod_security` y `mod_evasive`. Además, se aplicarán restricciones en la configuración de Apache para evitar fugas de información y reforzar la resistencia ante ataques dirigidos al servidor web.

---

## Tasks

* [Práctica 1: CSP](#practica-1-csp)
* [Práctica 2: Web Application Firewall](#practica-2-web-application-firewall)
* [Práctica 3: OWASP](#practica-3-owasp)
* [Práctica 4: Evitar ataques DDOS](#practica-4-evitar-ataques-ddos)

---

## Práctica 1: CSP

### Introducción

Content Security Policy (CSP) es una capa de seguridad adicional que previene ataques como Cross Site Scripting (XSS) y ataques de inyección de datos. Se logra restringiendo los orígenes de contenido que puede cargar el navegador.

![CSP](URL_IMG_CSP)

Ejemplo de configuración en Apache:

```apache
Header set Content-Security-Policy "default-src 'self'; img-src *; media-src media1.com media2.com; script-src userscripts.example.com"
```

---

## Práctica 2: Web Application Firewall

### Introducción

Un Web Application Firewall (WAF) filtra, supervisa y bloquea el tráfico HTTP entre una aplicación web y el usuario. Protege contra inyección SQL, XSS y CSRF.

![WAF](URL_IMG_WAF)

Ejemplo de instalación de ModSecurity en Apache:

```sh
sudo apt install libapache2-mod-security2
sudo cp /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf
sudo systemctl restart apache2
```

---

## Práctica 3: OWASP

### Introducción

OWASP proporciona reglas de seguridad para ModSecurity, protegiendo contra ataques comunes.

![OWASP](URL_IMG_OWASP)

Instalación de las reglas OWASP:

```sh
git clone https://github.com/SpiderLabs/owasp-modsecurity-crs.git
sudo mv owasp-modsecurity-crs/rules/ /etc/modsecurity/
```

Verificar configuración en `/etc/apache2/mods-enabled/security2.conf`:

```apache
Include /etc/modsecurity/rules/*.conf
```

---

## Práctica 4: Evitar ataques DDOS

### Introducción

El módulo `mod_evasive` en Apache permite mitigar ataques de denegación de servicio (DoS).

![DDoS](URL_IMG_DDOS)

Instalación y configuración de `mod_evasive`:

```sh
sudo apt install libapache2-mod-evasive
sudo nano /etc/apache2/mods-available/evasive.conf
```

Ejemplo de configuración:

```apache
DOSHashTableSize 2048
DOSPageCount 10
DOSSiteCount 50
DOSBlockingPeriod 600
```

Reiniciar Apache:

```sh
sudo systemctl restart apache2
```

Prueba con `ab` para simular un ataque DoS:

```sh
ab -n 1000 -c 100 http://localhost/
```

---

## Contribución
Si deseas mejorar esta configuración o agregar nuevas medidas de seguridad, ¡no dudes en hacer un fork del repositorio y enviar un pull request!

---

## Autor
Este proyecto fue realizado por [Tu Nombre], aplicando medidas de hardening en Apache dentro de un contenedor Docker.

