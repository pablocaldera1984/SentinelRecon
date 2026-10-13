from typing import Dict, Any

def calculate_email_penalty(dns_data: Dict[str, Any]) -> float:
    """Calcula la penalización por higiene de correo y anti-spoofing (P_email: 0 a 100)."""
    penalty = 0.0
    
    # 1. SPF
    spf = dns_data.get("spf", {})
    spf_status = spf.get("status")
    if spf_status in ["NOT_CONFIGURED", "PERMISSIVE"]:
        penalty += 45.0
    elif spf_status in ["SOFTFAIL", "NEUTRAL"]:
        penalty += 20.0
    
    if spf.get("dns_lookup_count", 0) > 10:
        penalty += 25.0

    # 2. DMARC
    dmarc = dns_data.get("dmarc", {})
    dmarc_status = dmarc.get("status")
    dmarc_policy = dmarc.get("policy", "none")
    
    if dmarc_status == "NOT_CONFIGURED":
        penalty += 40.0
    elif dmarc_policy == "none":
        penalty += 25.0
    elif dmarc_policy == "quarantine":
        penalty += 10.0

    # 3. DKIM
    dkim = dns_data.get("dkim", {})
    if not dkim.get("has_dkim", False):
        penalty += 15.0

    return min(100.0, penalty)


def calculate_crypto_penalty(web_data: Dict[str, Any]) -> float:
    """Calcula la penalización por postura SSL/TLS y encabezados HTTP (P_crypto: 0 a 100)."""
    penalty = 0.0
    
    ssl_cert = web_data.get("ssl_certificate", {})
    if not ssl_cert.get("has_ssl", False):
        return 100.0  # Sin SSL en puerto 443 es crítico
    
    if ssl_cert.get("expired", False):
        penalty += 60.0
    elif ssl_cert.get("days_until_expiry") is not None and ssl_cert.get("days_until_expiry") < 15:
        penalty += 25.0

    headers = web_data.get("http_headers", {})
    if not headers.get("hsts", False):
        penalty += 20.0
    if not headers.get("csp", False):
        penalty += 15.0
    if not headers.get("x_frame_options"):
        penalty += 10.0

    return min(100.0, penalty)


def calculate_ports_penalty(port_data: Dict[str, Any]) -> float:
    """Calcula la penalización por exposición de interfaces de gestión crítica (P_puertos: 0 a 100)."""
    penalty = 0.0
    open_ports = [p.get("port") for p in port_data.get("open_ports", [])]
    
    critical_weights = {
        3389: 50.0,  # RDP expuesto
        445: 50.0,   # SMB expuesto
        135: 40.0,   # RPC expuesto
        11434: 40.0, # Shadow AI (Ollama sin auth)
        22: 25.0,    # SSH expuesto
        8080: 15.0   # Proxy/Admin web alternativo
    }

    for port, weight in critical_weights.items():
        if port in open_ports:
            penalty += weight

    return min(100.0, penalty)


def evaluate_security_posture(dns_data: Dict[str, Any], web_data: Dict[str, Any], port_data: Dict[str, Any]) -> Dict[str, Any]:
    """Calcula el Puntaje Consolidado (R_total) y Calificación S_posture."""
    p_email = calculate_email_penalty(dns_data)
    p_crypto = calculate_crypto_penalty(web_data)
    p_ports = calculate_ports_penalty(port_data)

    # Ponderación: 40% Puertos, 35% Configuración Correo, 25% Cripto/Web
    r_total = min(100.0, (0.40 * p_ports) + (0.35 * p_email) + (0.25 * p_crypto))
    s_posture = round(100.0 - r_total, 1)

    # Escala ejecutiva (A a F)
    if s_posture >= 90:
        grade = "A"
        risk_level = "BAJO"
    elif s_posture >= 80:
        grade = "B"
        risk_level = "MODERADO"
    elif s_posture >= 70:
        grade = "C"
        risk_level = "MEDIO"
    elif s_posture >= 60:
        grade = "D"
        risk_level = "ALTO"
    else:
        grade = "F"
        risk_level = "CRÍTICO"

    # Advertencias normativas para Chile
    regulatory_notes = []
    if p_ports >= 40.0:
        regulatory_notes.append(
            "Exposición de interfaces de gestión crítica. "
            "Bajo Ley 21.663, un incidente reportable a la ANCI exige notificación obligatoria en plazo de 3 horas."
        )
    if p_email >= 40.0:
        regulatory_notes.append(
            "Dominio desprotegido ante suplantación (Phishing/BEC), facilitando el compromiso inicial hacia puestos de trabajo."
        )

    return {
        "score_posture": s_posture,
        "grade": grade,
        "risk_level": risk_level,
        "penalties": {
            "ports_penalty": round(p_ports, 1),
            "email_penalty": round(p_email, 1),
            "crypto_penalty": round(p_crypto, 1)
        },
        "regulatory_context": regulatory_notes
    }
