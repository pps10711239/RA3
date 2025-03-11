# Damn Vulnerable Web Application (DVWA) con MySQL en Docker

Este proyecto levanta **DVWA** junto con **MySQL 5.7** en contenedores Docker para practicar pruebas de seguridad web.

## **Instalación y Puesta en Marcha**

1. **Descargar las imágenes necesarias de Docker**:
   ```bash
   docker pull mysql:5.7
   docker pull ghcr.io/digininja/dvwa:cc86a34
   ```

2. **Ejecutar MySQL** con credenciales preconfiguradas:
   ```bash
   docker run -d --name dvwa-mysql \
     -e MYSQL_ROOT_PASSWORD=root \
     -e MYSQL_USER=dvwa \
     -e MYSQL_PASSWORD=p@ssw0rd \
     -e MYSQL_DATABASE=dvwa \
     mysql:5.7
   ```

3. **Levantar DVWA** y conectarlo al contenedor de MySQL:
   ```bash
   docker run -d --name dvwa --link dvwa-mysql:mysql -p 80:80 \
     -e DB_SERVER=mysql ghcr.io/digininja/dvwa:cc86a34
   ```

4. **Acceder a la aplicación** en el navegador:
   ```
   http://localhost/setup.php
   ```

5. **Configurar la base de datos** haciendo clic en **"Create / Reset Database"**.

6. **Iniciar sesión** con:
   - Usuario: `admin`
   - Contraseña: `password`

Ahora **DVWA** está listo para realizar pruebas de seguridad. 🛡️

### **Captura de la Configuración**
A continuación, se muestra una imagen con la configuración y ejecución de los contenedores:

![Configuración de DVWA en Docker](assets/Captura1.png)  

*Sustituye `ruta/a/la/imagen.png` por la ubicación real de la imagen en tu repositorio o sistema.*

