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

## Práctica 1: Content Security Policy (CSP)

### Introducción

Content Security Policy (CSP) es una política de seguridad que restringe el origen de los recursos que un navegador puede cargar en una página web. Ayuda a prevenir ataques como Cross-Site Scripting (XSS) e inyecciones de contenido malicioso.

### Configuración de CSP en Apache

Para implementar CSP en Apache, se configura la directiva en el archivo de configuración del sitio seguro (`default-ssl.conf`):

```apache
Header set Content-Security-Policy "default-src 'self'; img-src *; media-src media1.com media2.com; script-src userscripts.example.com"
```

Esta configuración establece:
- `default-src 'self'`: El contenido solo puede cargarse desde el mismo origen.
- `img-src *`: Permite cargar imágenes desde cualquier origen.
- `media-src media1.com media2.com`: Los archivos de medios solo pueden provenir de `media1.com` y `media2.com`.
- `script-src userscripts.example.com`: Solo se permite ejecutar scripts desde `userscripts.example.com`.

### Implementación en Docker

El `Dockerfile` con esta configuración se encuentra en la carpeta `assets/CSP` dentro del repositorio. No es necesario incluirlo aquí, pero puedes acceder a él en el repositorio para más detalles.

Además, la imagen generada con esta configuración está disponible en Docker Hub en el siguiente enlace: 

**[apache-hardening en Docker Hub](https://hub.docker.com/r/pps10711239/apache-hardening)**

### Verificación de CSP

Para verificar que CSP está aplicado correctamente, se puede ejecutar el siguiente comando:

```sh
curl -I https://localhost --insecure
```

La salida esperada incluirá la cabecera `Content-Security-Policy`:

```
Content-Security-Policy: default-src 'self'; img-src *; media-src media1.com media2.com; script-src userscripts.example.com
```
## Práctica 2: Web Application Firewall (WAF)

### Introducción

Un Web Application Firewall (WAF) es un sistema de seguridad que supervisa, filtra y bloquea el tráfico HTTP para proteger aplicaciones web de ataques como inyección SQL (SQLi), Cross-Site Scripting (XSS) y falsificación de peticiones entre sitios (CSRF). En esta práctica, se ha configurado Apache con **ModSecurity**, un firewall de aplicaciones web de código abierto ampliamente utilizado.

### Configuración de WAF en Apache

Para implementar WAF en Apache, se han seguido estos pasos:
1. Instalación del módulo ModSecurity y las reglas de OWASP Core Rule Set (CRS).
2. Configuración de ModSecurity para bloquear ataques en lugar de solo detectarlos.
3. Implementación de un archivo PHP (`post.php`) en el DocumentRoot para probar reglas de seguridad.

### Implementación en Docker

El `Dockerfile` con esta configuración se encuentra en la carpeta `assets/WAF` dentro del repositorio. Allí también están los archivos de configuración y capturas de pantalla del proceso. 

La imagen Docker generada con esta configuración está disponible en:

**[apache-hardening-waf en Docker Hub](https://hub.docker.com/r/pps10711239/apache-hardening-waf)**

### Verificación del WAF

Para comprobar que ModSecurity está funcionando correctamente, se puede realizar una prueba enviando una solicitud maliciosa. Si el firewall está bien configurado, responderá con un código **403 Forbidden** bloqueando el intento de ataque.

Ejemplo de prueba con `curl`:

```sh
curl -X POST http://localhost/post.php -d "<script>alert('XSS')</script>"
```

Salida esperada:

```
HTTP/1.1 403 Forbidden
```

Este comportamiento indica que el firewall ha detectado e impedido la ejecución de un ataque XSS.

---

## Práctica 3: OWASP

### Introducción

Para reforzar la seguridad de Apache contra los ataques más comunes de aplicaciones web, se ha implementado **ModSecurity** con el conjunto de reglas de **OWASP Core Rule Set (CRS)**. Este conjunto de reglas protege contra inyección SQL, XSS, ejecución remota de código y otros ataques listados en el **OWASP Top 10**.

### Configuración de OWASP CRS en Apache

1. Se instala ModSecurity y el OWASP CRS.
2. Se habilita el motor de reglas de ModSecurity (`SecRuleEngine On`).
3. Se clonan las reglas OWASP desde el repositorio oficial y se configuran en Apache.
4. Se añade una regla personalizada para bloquear peticiones sospechosas.

### Implementación en Docker

El `Dockerfile` con esta configuración se encuentra en la carpeta `assets/OWASP` dentro del repositorio. Allí también se encuentran los archivos `security2.conf` y `setup_modsecurity`, además de capturas de pantalla que evidencian el proceso de configuración y pruebas.

La imagen Docker generada con esta configuración está disponible en:

**[apache-hardening-owasp en Docker Hub](https://hub.docker.com/r/pps10711239/apache-hardening-owasp)**

### Verificación de OWASP CRS

Para comprobar que el WAF con reglas OWASP está funcionando correctamente, se puede probar con una petición que simule un ataque SQLi o XSS.

Ejemplo de prueba con `curl` para simular una inyección SQL:

```sh
curl -X GET "http://localhost/index.html?id=' OR '1'='1' --"
```

Salida esperada:

```
HTTP/1.1 403 Forbidden
```

Este resultado indica que el firewall ha detectado la inyección SQL y ha bloqueado la solicitud.



---


Con esta configuración, se mejora la seguridad del servidor Apache al restringir las fuentes desde donde se pueden cargar los recursos, mitigando así ataques XSS y de inyección de código.

---

## Autor
Este proyecto fue realizado por **Adrián López Olaria**, aplicando medidas de hardening en Apache dentro de un contenedor Docker.
