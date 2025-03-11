# RA3_1

# Damn Vulnerable Web Application (DVWA) con MySQL en Docker

Este proyecto levanta **DVWA** junto con **MySQL 5.7** en contenedores Docker para practicar pruebas de seguridad web.

## **Instalación y Puesta en Marcha**

1. **Descargar la imagen de MySQL** y ejecutarla con credenciales preconfiguradas:
   ```bash
   docker run -d --name dvwa-mysql \
     -e MYSQL_ROOT_PASSWORD=root \
     -e MYSQL_USER=dvwa \
     -e MYSQL_PASSWORD=p@ssw0rd \
     -e MYSQL_DATABASE=dvwa \
     mysql:5.7
   ```

2. **Levantar DVWA** y conectarlo al contenedor de MySQL:
   ```bash
   docker run -d --name dvwa --link dvwa-mysql:mysql -p 80:80 \
     -e DB_SERVER=mysql ghcr.io/digininja/dvwa:cc86a34
   ```

3. **Acceder a la aplicación** en el navegador:
   ```
   http://localhost/setup.php
   ```

4. **Configurar la base de datos** haciendo clic en **"Create / Reset Database"**.

5. **Iniciar sesión** con:
   - Usuario: `admin`
   - Contraseña: `password`

Ahora **DVWA** está listo para realizar pruebas de seguridad. 🛡️


