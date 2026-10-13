# config.py

# Presupuestos temporales en segundos (RFC / escaneo no invasivo)
DNS_TIMEOUT = 2.0
TCP_TIMEOUT = 1.5
HTTP_TIMEOUT = 3.0

# Modelo LLM unificado para síntesis ejecutiva y Structured Outputs
MODELO_GEMINI = "gemini-3.5-flash-lite"

# Selectores DKIM corporativos de alta frecuencia
DKIM_SELECTORS = [
    "google",
    "k1",
    "default",
    "s1",
    "s2",
    "selector1",
    "mail",
    "office365",
    "mandrill",
    "zoho"
]

# Puertos críticos a evaluar de forma pasiva
TARGET_PORTS = [22, 80, 135, 443, 445, 3389, 8080, 11434]
