#!/bin/bash

# Activamos el motor de reglas de ModSecurity
echo "SecRuleEngine On" >> /etc/apache2/sites-available/000-default.conf

# Añadimos una regla personalizada para pruebas
echo 'SecRule ARGS:testparam "@contains test" "id:1234,deny,status:403,msg:'"'"'Cazado por Ciberseguridad'"'"'"' >> /etc/apache2/sites-available/000-default.conf
