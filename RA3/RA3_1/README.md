# RA3_1

## Introduction

La presente documentación cubre la configuración de seguridad para Apache dentro de un contenedor Docker, implementando distintas prácticas de hardening para reforzar la seguridad del servidor en un entorno de producción segura. La seguridad en la puesta en producción es un aspecto crítico para garantizar la integridad, disponibilidad y confidencialidad de los servicios web. En este contexto, se aplicarán configuraciones avanzadas para mitigar riesgos como ataques de ejecución remota de código (RCE), Cross-Site Scripting (XSS), inyección SQL (SQLi), ataques de denegación de servicio (DDoS) y otras amenazas documentadas en el OWASP Top 10.

Para ello, se implementarán estrategias de seguridad en capas que incluyen políticas de seguridad de contenido (CSP), encabezados de seguridad estrictos (HSTS), firewalls de aplicaciones web (WAF) y módulos específicos de Apache como `mod_security` y `mod_evasive`. Además, se aplicarán restricciones en la configuración de Apache para evitar fugas de información y reforzar la resistencia ante ataques dirigidos al servidor web.

---

## Tasks

1. [Introducción](#introducción)
2. [Práctica 1: Content Security Policy (CSP)](#practica-1-content-security-policy-csp)
3. [Práctica 2: Web Application Firewall (WAF)](#practica-2-web-application-firewall-waf)
4. [Práctica 3: OWASP](#practica-3-owasp)
5. [Práctica 4: Evitar ataques DoS](#practica-4-evitar-ataques-dos)
6. [Práctica 5: Instalación de Certificado SSL en Docker](#practica-5-instalacion-de-certificado-ssl-en-docker)
7. [Autor](#autor)

---

## 📌 Práctica 1: Content Security Policy (CSP)

### **Introducción**
Content Security Policy (CSP) es un mecanismo de seguridad que permite definir reglas estrictas sobre qué contenido puede ser cargado en una página web. Esto ayuda a mitigar ataques como **Cross-Site Scripting (XSS)** e inyección de contenido malicioso, protegiendo la integridad del sitio y la información del usuario.  

En esta práctica, se ha implementado CSP en Apache dentro de un contenedor Docker para reforzar la seguridad en la entrega de contenido web.

---

### **📌 Configuración de CSP en Apache**
Para aplicar **CSP** en Apache, se ha configurado la directiva en el archivo de configuración del sitio seguro (`default-ssl.conf`):

```apache
Header set Content-Security-Policy "default-src 'self'; img-src *; media-src media1.com media2.com; script-src userscripts.example.com"
```

📌 **Explicación de la configuración:**  
- **`default-src 'self'`** → Solo permite cargar contenido desde el mismo dominio (evita scripts externos).  
- **`img-src *`** → Permite la carga de imágenes desde cualquier origen.  
- **`media-src media1.com media2.com`** → Los archivos de medios solo pueden provenir de `media1.com` y `media2.com`.  
- **`script-src userscripts.example.com`** → Solo permite ejecutar scripts desde `userscripts.example.com`.  

---

### **📌 Implementación en Docker**
Para hacer esta configuración **persistente y fácilmente replicable**, se ha definido en un `Dockerfile` ubicado en:  
📂 `assets/CSP/Dockerfile`  

Este Dockerfile incluye la configuración de **Apache con CSP habilitado** y la generación de un certificado SSL autofirmado para asegurar la comunicación HTTPS.

📌 **La imagen resultante con esta configuración está disponible en Docker Hub:**  
👉 **[apache-hardening en Docker Hub](https://hub.docker.com/r/pps10711239/pr1)**  

---

### **📌 Generación de un certificado SSL autofirmado**
Para habilitar HTTPS en Apache y aplicar CSP de manera segura, se generó un certificado SSL autofirmado utilizando OpenSSL.  
Se ejecutó el siguiente comando dentro del contenedor:

```sh
mkdir /etc/apache2/ssl
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout /etc/apache2/ssl/apache-selfsigned.key \
  -out /etc/apache2/ssl/apache-selfsigned.crt \
  -subj "/C=ES/ST=Valencia/L=Valencia/O=Seguridad/OU=IT/CN=localhost"
```

📌 **Esto crea un certificado válido por 1 año** y lo almacena en `/etc/apache2/ssl/`.

---

### **📌 Modificación del VirtualHost para HTTPS**
En el archivo `/etc/apache2/sites-available/default-ssl.conf` se añadieron las siguientes líneas para configurar **SSL y CSP**:

```apache
SSLCertificateFile /etc/apache2/ssl/apache-selfsigned.crt
SSLCertificateKeyFile /etc/apache2/ssl/apache-selfsigned.key

Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
Header set Content-Security-Policy "default-src 'self'; img-src *; media-src media1.com media2.com; script-src userscripts.example.com"
```

📌 **Explicación:**  
✔ **SSL:** Se especifica el uso del certificado y la clave privada generados.  
✔ **HSTS (`Strict-Transport-Security`)**: Obliga a los navegadores a utilizar HTTPS en futuras conexiones.  
✔ **CSP:** Se aplica la política de seguridad establecida previamente.

---

### **📌 Verificación de CSP**
Para verificar que CSP se está aplicando correctamente, se utilizó **`curl`** con los siguientes comandos:

```sh
curl -I http://localhost
curl -I https://localhost --insecure
```

📌 **Salida esperada:**  
```
HTTP/1.1 200 OK
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
Content-Security-Policy: default-src 'self'; img-src *; media-src media1.com media2.com; script-src userscripts.example.com
```

Esto confirma que **CSP está activo y funcionando correctamente** tanto en HTTP como en HTTPS.

---

### **📌 Evidencias (Capturas de pantalla)**
Para documentar el proceso, se han incluido capturas de pantalla de cada paso:

📌 **📷 Captura 1: Creación de la imagen Docker con CSP configurado**  
![Captura 1](assets/CSP/Captura1.png)

📌 **📷 Captura 2: Generación del certificado SSL con OpenSSL**  
![Captura 2](assets/CSP/Captura2.png)

📌 **📷 Captura 3: Configuración del archivo `default-ssl.conf`**  
![Captura 3](assets/CSP/Captura3.png)

---

## **📌 Práctica 2: Web Application Firewall (WAF)**

### **Introducción**
Un **Web Application Firewall (WAF)** es una solución de seguridad que supervisa, filtra y bloquea el tráfico HTTP para proteger aplicaciones web de **ataques como inyección SQL (SQLi), Cross-Site Scripting (XSS) y falsificación de peticiones entre sitios (CSRF)**.  

Para esta práctica, se ha configurado Apache con **ModSecurity**, un firewall de aplicaciones web de código abierto ampliamente utilizado, junto con el **OWASP Core Rule Set (CRS)** para reforzar la seguridad del servidor.

---

### **📌 Configuración de WAF en Apache**
Para implementar WAF en Apache, se siguieron los siguientes pasos:

1️⃣ **Se instaló el módulo `mod_security` y se habilitó**:
   ```sh
   a2enmod security2
   ```
   **Salida esperada**:
   ```
   Module security2 already enabled
   ```

2️⃣ **Se activó el OWASP CRS** en la configuración de ModSecurity.  

3️⃣ **Se implementó un archivo PHP (`post.php`) en el DocumentRoot** para probar la efectividad de las reglas de seguridad:

   ```php
   <?php
   if ($_SERVER["REQUEST_METHOD"] == "POST") {
       echo "Entrada recibida: " . htmlspecialchars($_POST["data"]);
   }
   ?>
   <form method="post">
       <input type="text" name="data">
       <button type="submit">Enviar</button>
   </form>
   ```

---

### **📌 Implementación en Docker**
Para hacer que esta configuración **sea persistente y replicable**, se ha definido en un **Dockerfile**, ubicado en:  
📂 `assets/WAF/Dockerfile`  

Este Dockerfile incluye la instalación de Apache, la activación de **ModSecurity** y la configuración de las reglas de seguridad.

📌 **La imagen resultante con esta configuración está disponible en Docker Hub:**  
👉 **[apache-hardening-waf en Docker Hub](https://hub.docker.com/r/pps10711239/pr2)**  

---

### **📌 Prueba de funcionamiento**
Para comprobar que **ModSecurity está bloqueando correctamente peticiones sospechosas**, se realizó una prueba enviando un **ataque XSS** mediante un `POST` con `curl`:

```sh
curl -X POST http://localhost/post.php -d "<script>alert('XSS')</script>"
```

📌 **Salida esperada:**
```
HTTP/1.1 403 Forbidden
```
Esto confirma que **ModSecurity ha detectado el intento de inyección de código y lo ha bloqueado**.

📌 **También se verificó desde el navegador**, donde se intentó enviar una solicitud al archivo `post.php`, lo que resultó en un **error 403 Forbidden**, indicando que el acceso fue denegado.

---

### **📌 Logs y Evidencia de Bloqueo**
Para confirmar que **ModSecurity estaba registrando y bloqueando los intentos de ataque**, se revisaron los logs de Apache:

```sh
tail -f /var/log/apache2/error.log | grep ModSecurity
```

📌 **Salida esperada en los logs:**
```
[ModSecurity] Warning. Matched "Operator `Contains' ...
[ModSecurity] Access denied with code 403 ...
```
Esto muestra que el firewall ha identificado y bloqueado el intento de ataque.

---

### **📌 Evidencias (Capturas de pantalla)**
Se incluyen capturas de pantalla que documentan cada paso del proceso:

📌 **📷 Captura 1: Activación del módulo `security2` en Apache**  
![Captura 1](assets/WAF/Captura1.png)

📌 **📷 Captura 2: Código de `post.php` utilizado para probar el firewall**  
![Captura 2](assets/WAF/Captura2.png)

📌 **📷 Captura 3: Respuesta HTTP 403 Forbidden al intentar acceder a `post.php`**  
![Captura 3](assets/WAF/Captura3.png)

---


## **📌 Práctica 3: OWASP**

### **Introducción**
Para reforzar la seguridad de Apache contra los ataques más comunes a aplicaciones web, se ha implementado **ModSecurity** con el conjunto de reglas **OWASP Core Rule Set (CRS)**.  

Este conjunto de reglas protege contra vulnerabilidades como:  
✔ **Inyección SQL (SQLi)**  
✔ **Cross-Site Scripting (XSS)**  
✔ **Ejecución remota de código (RCE)**  
✔ **Path traversal y otros ataques del OWASP Top 10**  

---

### **📌 Configuración de OWASP CRS en Apache**
Para implementar OWASP CRS en Apache, se realizaron los siguientes pasos:

1️⃣ **Se instaló y activó el módulo `mod_security`**  
   ```sh
   a2enmod security2
   ```
   **Salida esperada:**
   ```
   Module security2 already enabled
   ```

2️⃣ **Se configuró el motor de reglas de ModSecurity para bloquear ataques**  
   Se verificó que `SecRuleEngine` estaba activado en la configuración de ModSecurity:  
   ```apache
   SecRuleEngine On
   ```

3️⃣ **Se añadió una regla personalizada para bloquear solicitudes sospechosas**  
   Se incluyó la siguiente regla en el archivo `/etc/apache2/sites-available/000-default.conf`:
   ```apache
   SecRule ARGS:testparam "@contains test" "id:123456,deny,status:403,msg:'Bloqueado por ModSecurity'"
   ```
   📌 **Esto significa que cualquier petición que incluya `testparam=test` será bloqueada con un error 403.**

---

### **📌 Implementación en Docker**
Para que esta configuración sea replicable, se creó un **Dockerfile** ubicado en:  
📂 `assets/OWASP/Dockerfile`

📌 **La imagen resultante con OWASP CRS activado está disponible en Docker Hub:**  
👉 **[apache-hardening-owasp en Docker Hub](https://hub.docker.com/r/pps10711239/pr3)**  

---

### **📌 Prueba de seguridad con OWASP CRS**
Para verificar que **ModSecurity está bloqueando ataques correctamente**, se realizaron pruebas con `curl`:

```sh
curl -I "http://localhost/index.html?testparam=test"
```
📌 **Salida esperada:**  
```
HTTP/1.1 403 Forbidden
```
✅ **Esto confirma que la regla personalizada de OWASP CRS está funcionando.**  

Se probaron otros intentos de ataque para validar la efectividad de ModSecurity:

```sh
curl -I "http://localhost/index.html?exec=/bin/bash"
curl -I "http://localhost/index.html?exec=../../"
```
📌 **Todas las solicitudes fueron bloqueadas con error 403, indicando que OWASP CRS detectó intentos de ataque.**  

---

### **📌 Evidencias (Capturas de pantalla)**
Se documentaron las pruebas realizadas con las siguientes imágenes:

📌 **📷 Captura 1: Ejecución de `curl` con pruebas de ataque bloqueadas**  
![Captura 1](assets/OWASP/Captura1.png)

📌 **📷 Captura 2: Verificación del módulo `mod_security` en Apache**  
![Captura 2](assets/OWASP/Captura2.png)

📌 **📷 Captura 3: Configuración de la regla personalizada en `000-default.conf`**  
![Captura 3](assets/OWASP/Captura3.png)

---

### **📌 Práctica 4: Evitar ataques DoS**

### **Introducción**
Un ataque de **Denegación de Servicio (DoS)** tiene como objetivo sobrecargar un servidor web enviando una gran cantidad de peticiones en un corto período de tiempo, lo que puede hacer que el servicio se vuelva lento o deje de responder.  

Para mitigar estos ataques, Apache nos proporciona el módulo **`mod_evasive`**, el cual:
✔️ **Escanea continuamente las conexiones entrantes.**  
✔️ **Bloquea direcciones IP cuando se alcanza un umbral definido.**  
✔️ **Evita que el servidor colapse ante un tráfico excesivo.**  

---

### **📌 Configuración de `mod_evasive` en Apache**
Para implementar la protección contra DoS en Apache, se siguieron los siguientes pasos:

1️⃣ **Se instaló el módulo `mod_evasive`** en el contenedor.  
2️⃣ **Se configuraron los umbrales de bloqueo** en el archivo `/etc/apache2/mods-enabled/evasive.conf`:  

```apache
<IfModule mod_evasive20.c>
    DOSHashTableSize 3097
    DOSPageCount 5
    DOSSiteCount 50
    DOSPageInterval 1
    DOSSiteInterval 1
    DOSBlockingPeriod 10
    DOSEmailNotify admin@example.com
    DOSSystemCommand "sudo iptables -A INPUT -s %s -j DROP"
    DOSLogDir "/var/log/mod_evasive"
</IfModule>
```

📌 **Explicación de la configuración:**
- `DOSPageCount 5` → Si un usuario realiza más de **5 peticiones** a una misma página en **1 segundo**, será bloqueado.  
- `DOSSiteCount 50` → Si el servidor recibe más de **50 peticiones** en total en **1 segundo**, se activará la protección.  
- `DOSBlockingPeriod 10` → La IP bloqueada **no podrá acceder durante 10 segundos**.  
- `DOSSystemCommand "iptables -A INPUT -s %s -j DROP"` → **Bloquea la IP automáticamente** en el firewall.  
- `DOSLogDir "/var/log/mod_evasive"` → **Guarda registros** de las IPs bloqueadas.  

3️⃣ **Se creó el directorio de logs y se aseguraron los permisos:**
```sh
mkdir -p /var/log/mod_evasive
touch /var/log/mod_evasive/mod_evasive.log
chmod 777 /var/log/mod_evasive/mod_evasive.log
```

4️⃣ **Se reinició Apache para aplicar los cambios:**
```sh
service apache2 restart
```

---

### **📌 Implementación en Docker**
Para hacer esta configuración **permanente**, se creó un **Dockerfile** ubicado en la carpeta `assets/dos`. Este `Dockerfile` contiene la instalación y configuración de `mod_evasive` en un entorno seguro.

📌 **La imagen Docker resultante con esta configuración está disponible en:**
👉 **[apache-hardening-dos en Docker Hub](https://hub.docker.com/r/pps10711239/pr4)**  

---

### **📌 Prueba de resistencia con Apache Bench**
Para verificar que `mod_evasive` está bloqueando solicitudes masivas, se utilizó **Apache Bench (`ab`)**, una herramienta que permite simular múltiples peticiones al servidor.

🔹 **Se ejecutó el siguiente comando en la máquina host:**
```sh
ab -n 100 -c 10 http://localhost/
```
📌 **Explicación:**  
- `-n 100` → Se enviaron **100 solicitudes en total**.  
- `-c 10` → **10 peticiones concurrentes** en cada ronda.  

### **📌 Resultados obtenidos**
Como era de esperarse, el módulo **bloqueó muchas de las solicitudes**, lo que demuestra que está funcionando correctamente.  

📌 **Salida de Apache Bench:**
- **100 solicitudes en total**  
- **70 solicitudes bloqueadas**  
- **30 solicitudes exitosas**  

🚀 **Esto confirma que `mod_evasive` está funcionando correctamente y está mitigando los intentos de ataque.**  

---

### **📌 Logs de `mod_evasive` y Apache**
Para comprobar qué direcciones IP fueron bloqueadas, se revisaron los logs:

```sh
tail -f /var/log/apache2/error.log | grep evasive
```

📌 **Salida esperada en los logs de Apache:**
```
[Tue Feb 25 15:49:25.056477 2025] [evasive20:error] [pid 109] [client 172.17.0.1:53416] client denied by server configuration: /var/www/html/
[Tue Feb 25 15:49:25.057297 2025] [evasive20:error] [pid 108] [client 172.17.0.1:53420] client denied by server configuration: /var/www/html/
```

✅ **Aquí se puede ver que `mod_evasive` está bloqueando la IP `172.17.0.1` por exceder el umbral de peticiones.**

---

### **📌 Evidencias (Capturas de pantalla)**
A continuación, se presentan capturas de pantalla del proceso y los resultados obtenidos:

📌 **📷 Captura 1: Ejecución de Apache Bench (`ab`)**  
![Captura 1](assets/DDOS/Captura1.png)

📌 **📷 Captura 2: Configuración de `mod_evasive.conf`**  
![Captura 2](assets/DDOS/Captura2.png)

📌 **📷 Captura 3: Logs de Apache mostrando IPs bloqueadas**  
![Captura 3](assets/DDOS/Captura3.png)

---

📌 **La imagen final con `mod_evasive` configurado está disponible en Docker Hub:**  
👉 **[pps10711239/pr4](https://hub.docker.com/r/pps10711239/pr4)**  

---
## **📌 Práctica 5: Instalación de Certificado SSL en Docker**

### **Introducción**
En esta práctica se implementa un **certificado digital SSL/TLS** en un servidor Apache dentro de un **contenedor Docker**, asegurando que las comunicaciones entre clientes y el servidor sean **seguras y cifradas**.  

El uso de **HTTPS** evita ataques como **Man-in-the-Middle (MITM)** y protege la privacidad de los usuarios al cifrar los datos transmitidos entre el cliente y el servidor.  

---

### **📌 Generación del Certificado SSL en Apache**
Para habilitar **HTTPS** en Apache dentro del contenedor, se generó un **certificado autofirmado** con **OpenSSL**.  

El siguiente comando crea un certificado válido por **1 año** en la ruta `/etc/apache2/ssl/` dentro del contenedor:

```sh
mkdir -p /etc/apache2/ssl
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout /etc/apache2/ssl/apache-selfsigned.key \
  -out /etc/apache2/ssl/apache-selfsigned.crt \
  -subj "/C=ES/ST=Valencia/L=Valencia/O=Seguridad/OU=IT/CN=localhost"
```

📌 **Explicación:**  
- Se genera un certificado **X.509** autofirmado.  
- Se crea una **clave RSA de 2048 bits**.  
- El certificado es válido por **365 días**.  
- El `CN=localhost` indica que el certificado se usará para el dominio `localhost`.  

📷 **Captura 1: Información del Certificado SSL en el navegador**  
![Captura 1](assets/SSL/Captura1.png)

---

### **📌 Configuración de Apache para usar el Certificado**
Para que **Apache** use el certificado generado, se editó el archivo de configuración del sitio **`default-ssl.conf`**:

```apache
SSLCertificateFile /etc/apache2/ssl/apache-selfsigned.crt
SSLCertificateKeyFile /etc/apache2/ssl/apache-selfsigned.key

<VirtualHost *:443>
    ServerAdmin admin@example.com
    ServerName localhost
    DocumentRoot /var/www/html

    ErrorLog ${APACHE_LOG_DIR}/error.log
    CustomLog ${APACHE_LOG_DIR}/access.log combined

    SSLEngine on
</VirtualHost>
```

📌 **Explicación:**  
✔ **Se habilita SSL (`SSLEngine on`)** para el puerto **443**.  
✔ **Se configuran los archivos del certificado** (`.crt`) y la clave privada (`.key`).  
✔ **El sitio se servirá en `localhost` con HTTPS.**  

---

### **📌 Habilitación del Módulo SSL en Apache**
Para activar **SSL** en Apache dentro del contenedor, se ejecutaron los siguientes comandos:

```sh
a2enmod ssl
a2ensite default-ssl
service apache2 restart
```

📌 **Salida esperada:**
```
Module ssl already enabled
Site default-ssl already enabled
 * Restarting Apache httpd web server apache2
```

Esto confirma que **SSL está activado correctamente** y que **Apache está sirviendo contenido en HTTPS**.

---

### **📌 Implementación en Docker**
Para que esta configuración sea **persistente y replicable**, se creó un **Dockerfile**, ubicado en:  
📂 `assets/SSL/Dockerfile`

📌 **La imagen final con Apache y SSL configurado está disponible en Docker Hub:**  
👉 **[apache-hardening-ssl en Docker Hub](https://hub.docker.com/r/pps10711239/pr5)**  

---

### **📌 Verificación del Certificado SSL**
Se accedió a `https://localhost/` desde un navegador y se verificó el certificado.

📌 **Salida esperada:**  
✅ **El candado en la barra de direcciones indica que HTTPS está funcionando.**  
✅ **Al ver el certificado, se muestra la información correcta del emisor.**  

📷 **Captura 2: Página servida con HTTPS en el navegador**  
![Captura 2](assets/SSL/Captura2.png)

---

Con esta configuración, se mejora la seguridad del servidor Apache al restringir las fuentes desde donde se pueden cargar los recursos, mitigando así ataques XSS y de inyección de código.

---

## Autor
Este proyecto fue realizado por **Adrián López Olaria**, aplicando medidas de hardening en Apache dentro de un contenedor Docker.
