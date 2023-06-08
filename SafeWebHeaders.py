#!/usr/bin/python3

# Autor: Thegame008
# Versión firmada: 2.0
# Fecha de firma: 2023-06-08

import sys
import time
import requests
from itertools import cycle
from termcolor import colored
from urllib3.exceptions import InsecureRequestWarning

# Desactivar las advertencias de solicitud no segura
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

# Obtener la URL de la línea de comandos
if len(sys.argv) < 2:
    print("Por favor, proporciona la URL al ejecutar el script.")
    print("python3 SafeWebHeaders.py https://ejemplo.com")
    sys.exit(1)

url = sys.argv[1]

# Mostrar mensaje de inicio del análisis
print(f"\nEjecutando análisis para la web: {colored(url, 'grey', attrs=['bold'])}\n")

# Simular progreso del análisis
progress_symbols = cycle(['-', '\\', '|', '/'])

# Obtener las cabeceras de la URL en segundo plano
headers = None
success_flag = False

def get_headers(url):
    global headers, success_flag
    try:
        response = requests.get(url, verify=False)
        headers = response.headers
        success_flag = True
    except requests.exceptions.RequestException:
        print("\nOcurrió un error al obtener las cabeceras de la URL. Asegúrate de proporcionar una URL válida y accesible.")
        sys.exit(1)

# Iniciar el proceso en segundo plano para obtener las cabeceras
import threading
thread = threading.Thread(target=get_headers, args=(url,))
thread.start()

# Mantener la barra de progreso girando mientras se obtienen las cabeceras
while thread.is_alive():
    progress_symbol = next(progress_symbols)

    print(f"\r{progress_symbol} Ejecutando análisis para la web: {colored(url, 'grey', attrs=['bold'])}", end='')
    sys.stdout.flush()
    time.sleep(0.2)  # Ajusta el tiempo de espera según sea necesario

thread.join()  # Esperar a que finalice el proceso en segundo plano

# Mostrar resultados
if success_flag:
    print(f"\r{colored('Resultados finalizados con éxito para la web:')} {colored(url, 'grey', attrs=['bold'])}")

# Verificar si se obtuvieron las cabeceras correctamente
if not success_flag:
    print("\nNo se obtuvo conectividad. Asegúrate de proporcionar una URL válida y accesible como argumento al ejecutar el script.")
    print("Verifica la URL y la conectividad de red para asegurarte de que la URL sea correcta y esté disponible.")
    sys.exit(1)

# Identificar cabeceras que revelan información innecesaria
info_headers = {
    "Server": "",
    "X-Powered-By": "",
    "X-AspNet-Version": ""
}

# Definir las cabeceras recomendadas por OWASP
owasp_headers = {
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
    "X-Frame-Options": "SAMEORIGIN",
    "X-XSS-Protection": "1; mode=block",
    "X-Content-Type-Options": "nosniff",
    "Content-Security-Policy": "default-src 'self'; base-uri 'self'; img-src 'self' data:; object-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'"
}

# Separar las cabeceras que están presentes y tienen la configuración correcta
correct_headers = {header: value for header, value in owasp_headers.items() if header in headers and headers[header] == value}

# Mostrar cabeceras correctamente implementadas
print(colored("\nCabeceras correctamente implementadas:", "green"))
if correct_headers:
    for header, value in correct_headers.items():
        print(colored("[+] ", "green") + f"{header}: {value}")
else:
    print("Durante la comprobación, no se encontraron cabeceras correctamente implementadas.")
    print("\rSería recomendable revisar la configuración y asegurarse de implementar las cabeceras de seguridad necesarias para proteger la aplicación.")

# Separar las cabeceras que están presentes, pero de manera incorrecta
incorrect_headers = {header: {"recommended_value": value, "current_value": headers[header]} for header, value in owasp_headers.items() if header in headers and headers[header] != value}

# Mostrar cabeceras con configuración incorrecta
print(colored("\nCabeceras con configuración incorrecta:", "yellow"))
if incorrect_headers:
    for header, values in incorrect_headers.items():
        recommended_value = values["recommended_value"]
        current_value = values["current_value"]
        print(colored("[!] ", "yellow") + f"{header}:")
        print(f"    - Valor recomendado por OWASP: {recommended_value}")
        print(f"    - Configuración actual en la URL: {current_value}")
else:
    missing_headers = {header: value for header, value in owasp_headers.items() if header not in headers}
    if missing_headers:
        print("Durante la comprobación, no se encontraron cabeceras con configuración incorrecta.")
        print("\rSin embargo, existen cabeceras de seguridad sin implementar, ¡y es crucial que las implementes de manera inmediata para asegurar tu aplicación!")
    else:
        print("Durante la comprobación, no se encontraron cabeceras con configuración incorrecta.")
        print("\rEsto demuestra un sólido enfoque en la seguridad de la aplicación.")

# Identificar cabeceras que no están implementadas
missing_headers = {header: value for header, value in owasp_headers.items() if header not in headers}

# Mostrar cabeceras que deberían estar implementadas pero no se ven implementadas
print(colored("\nCabeceras que deberían estar implementadas, pero no se ven implementadas:", "red"))
for header, value in owasp_headers.items():
    if header not in headers:
        print(colored("[-] ", "red") + f"{header}: {value}")
        if header == "Strict-Transport-Security":
            print("Riesgo: La ausencia de la cabecera Strict-Transport-Security permite ataques de tipo 'Man-in-the-Middle' y")
            print("        deja la comunicación vulnerable a interceptaciones y modificaciones.")
        elif header == "X-Frame-Options":
            print("Riesgo: La falta de la cabecera X-Frame-Options puede permitir ataques de Clickjacking,")
            print("        donde un atacante podría mostrar tu sitio web dentro de un marco oculto y realizar acciones en nombre del usuario.")
        elif header == "X-XSS-Protection":
            print("Riesgo: La falta de la cabecera X-XSS-Protection puede permitir ataques de Cross-Site Scripting (XSS),")
            print("        que podrían comprometer la seguridad de tu aplicación y sus usuarios.")
        elif header == "X-Content-Type-Options":
            print("Riesgo: La ausencia de la cabecera X-Content-Type-Options puede permitir ataques de tipo 'MIME sniffing',")
            print("        donde los navegadores intentan adivinar incorrectamente el tipo de contenido, lo que podría conducir a ataques de inyección.")
        elif header == "Content-Security-Policy":
            print("Riesgo: La falta de la cabecera Content-Security-Policy deja la aplicación vulnerable a ataques de inyección de código y otros ataques maliciosos.")
        print("Recomendación: Implementa las cabeceras faltantes para mejorar la seguridad de tu aplicación.")

# Identificar cabeceras que divulgan información
info_disclosure_headers = {}
for header, value in headers.items():
    if header in info_headers:
        info_disclosure_headers[header] = value

# Mostrar cabeceras que divulgan información
print(colored("\nDivulgación de información en cabecera:", "magenta"))
if len(info_disclosure_headers) > 0:
    for header, value in info_disclosure_headers.items():
        print(colored("[*] ", "magenta") + f"{header}: {value}")
        if value == "" or "XXX" in value:
            if value == "":
                print(colored("\tNota: Se realiza la consulta y se evidencia que esta cabecera tiene un valor vacío.", "magenta"))
            elif "XXX" in value:
                print(colored("\tNota: Se realiza la consulta y se evidencia que esta cabecera tiene un valor enmascarado tipo 'XXX'.", "magenta"))
else:
    print("Durante el análisis, no se han identificado cabeceras que puedan exponer información interna.")
    print("Esto refuerza la seguridad de la aplicación y minimiza el riesgo de divulgación de datos confidenciales.")

print()  # Línea en blanco al final
