import requests

# Pedir al usuario la URL a escanear
url = input("Introduce la URL a escanear: ")

# Obtener las cabeceras de la URL
response = requests.get(url)
headers = response.headers

# Definir las cabeceras recomendadas por OWASP
owasp_headers = {
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
    "X-Frame-Options": "SAMEORIGIN",
    "X-XSS-Protection": "1; mode=block",
    "X-Content-Type-Options": "nosniff",
    "Content-Security-Policy": "default-src 'self'; base-uri 'self'; img-src 'self' data:; object-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'"
}

# Separar las cabeceras que están presentes de manera correcta
correct_headers = {}
for header, value in owasp_headers.items():
    if header in headers and headers[header] == value:
        correct_headers[header] = value

print("Cabeceras correctamente implementadas:")
for header, value in correct_headers.items():
    print(f"- {header}: {value}")

# Separar las cabeceras que están presentes, pero de manera incorrecta
incorrect_headers = {}
for header, value in owasp_headers.items():
    if header in headers and headers[header] != value:
        incorrect_headers[header] = headers[header]

print("\nCabeceras con configuración incorrecta:")
for header, value in incorrect_headers.items():
    print(f"- {header}:")
    print(f"\t- Valor recomendado por OWASP: {owasp_headers[header]}")
    print(f"\t- Configuración actual en la URL: {value}")
    if header == "Strict-Transport-Security":
        print("\t- Riesgo: Vulnerabilidad a ataques de MITM")
    elif header == "X-XSS-Protection":
        print("\t- Riesgo: Vulnerabilidad a ataques de XSS")
    elif header == "Content-Security-Policy":
        print("\t- Riesgo: Vulnerabilidad a ataques de inyección de código")

# Separar las cabeceras que deberían estar implementadas, pero no se ven implementadas
missing_headers = {}
for header in owasp_headers.keys():
    if header not in headers:
        missing_headers[header] = owasp_headers[header]

print("\nCabeceras que deberían estar implementadas, pero no se ven implementadas:")
for header, value in missing_headers.items():
    print(f"- {header}: {value}")
    if header == "Referrer-Policy":
        print("\t- Riesgo: Posible divulgación de información confidencial")

# Identificar cabeceras que revelan información innecesaria
info_headers = {
    "Server": "",
    "X-Powered-By": "",
    "X-AspNet-Version": ""
}

# Mostrar las cabeceras que revelan información innecesaria y su valor
print("\nDivulgación de información en cabecera:")
for header, value in headers.items():
    if header in info_headers:
        print(f"- {header}: {value}")
