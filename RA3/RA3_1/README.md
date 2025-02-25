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

Con esta configuración, se mejora la seguridad del servidor Apache al restringir las fuentes desde donde se pueden cargar los recursos, mitigando así ataques XSS y de inyección de código.

---

## Contribución
Si deseas mejorar esta configuración o agregar nuevas medidas de seguridad, ¡no dudes en hacer un fork del repositorio y enviar un pull request!

---

## Autor
Este proyecto fue realizado por [Tu Nombre], aplicando medidas de hardening en Apache dentro de un contenedor Docker.
