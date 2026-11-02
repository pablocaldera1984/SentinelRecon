# core/scoring.py
import hashlib
import json
from typing import Dict, Any, Optional


def calculate_email_penalty(dns_data: Dict[str, Any]) -> float:
    """Calcula la penalización por higiene de correo, anti-spoofing, listas negras RBL y gobernanza DNS (P_email: 0 a 100)."""
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

    # 4. Gobernanza DNS Avanzada (CAA, MTA-STS & DNSSEC)
    gov = dns_data.get("governance", {})
    if gov:
        if not gov.get("caa_configured", False):
            penalty += 5.0
        if not gov.get("mta_sts_configured", False):
            penalty += 5.0
        if not gov.get("dnssec_enabled", False):
            penalty += 5.0

    # 5. Listas Negras Internacionales Anti-Spam (RBL / DNSBL)
    rbl = dns_data.get("rbl_blacklist", {})
    listed_count = rbl.get("listed_count", 0)
    if listed_count > 0:
        penalty += min(60.0, listed_count * 35.0)

    return min(100.0, penalty)


def calculate_crypto_penalty(web_data: Dict[str, Any]) -> float:
    """Calcula la penalización por postura SSL/TLS, PQC, encabezados HTTP, exposición de APIs y código web (P_crypto: 0 a 100)."""
    penalty = 0.0

    ssl_cert = web_data.get("ssl_certificate", {})
    if not ssl_cert.get("has_ssl", False):
        return 100.0

    if ssl_cert.get("expired", False):
        penalty += 60.0
    elif ssl_cert.get("days_until_expiry") is not None and ssl_cert.get("days_until_expiry") < 15:
        penalty += 25.0

    if ssl_cert.get("deprecated_tls", False):
        penalty += 35.0

    headers = web_data.get("http_headers", {})
    if not headers.get("hsts", False):
        penalty += 20.0
    if not headers.get("csp", False):
        penalty += 15.0
    if not headers.get("x_frame_options"):
        penalty += 10.0
    if headers.get("cors_wildcard", False):
        penalty += 10.0

    exposure = web_data.get("exposure_audit", {})
    if exposure.get("openapi_swagger_exposed", False):
        penalty += 15.0
    if exposure.get("sourcemaps_referenced", False):
        penalty += 10.0

    # 6. Auditoría de Estructura y Seguridad de Código Web (v2.2: PHP/CGI, JS, Respaldos, Secretos, Privacidad)
    code_audit = web_data.get("code_security_audit", {}) or headers.get("code_security_audit", {})
    if code_audit:
        if code_audit.get("exposed_backup_or_env_files"):
            penalty += 45.0
        if code_audit.get("exposed_frontend_secrets"):
            penalty += 40.0
        if code_audit.get("suspicious_hidden_iframes", False):
            penalty += 50.0
        if code_audit.get("cms_backdoors_exposed"):
            penalty += 20.0
        if code_audit.get("php_cgi_surface_exposed", False):
            penalty += 15.0
        if code_audit.get("outdated_js_libraries"):
            penalty += 15.0
        if code_audit.get("insecure_forms_detected", False):
            penalty += 15.0
        if code_audit.get("insecure_cookies_detected", False):
            penalty += 10.0
        if code_audit.get("privacy_ley21719", {}).get("compliance_warning", False):
            penalty += 10.0

    return min(100.0, penalty)


def calculate_ports_penalty(port_data: Dict[str, Any]) -> float:
    """Calcula la penalización por exposición de interfaces de gestión, bases de datos, Shadow AI y Shodan CVEs (P_puertos: 0 a 100)."""
    penalty = 0.0
    open_ports = [p.get("port") for p in port_data.get("open_ports", [])]

    critical_weights = {
        3389: 50.0,   # RDP expuesto (Windows)
        445: 50.0,    # SMB expuesto (Windows)
        135: 40.0,    # RPC expuesto (Windows)
        11434: 45.0,  # Shadow AI (Ollama sin auth)
        8000: 35.0,   # Shadow AI (vLLM / API LLM sin auth)
        6333: 40.0,   # Vector DB Qdrant (Shadow AI)
        6379: 45.0,   # Redis expuesto
        27017: 45.0,  # MongoDB expuesto
        3306: 35.0,   # MySQL expuesto
        5432: 35.0,   # PostgreSQL expuesto
        21: 25.0,     # FTP texto plano
        22: 25.0,     # SSH expuesto
        8080: 15.0    # Proxy/Admin web alternativo
    }

    for port, weight in critical_weights.items():
        if port in open_ports:
            penalty += weight

    # Penalización adicional si Shodan InternetDB reporta vulnerabilidades (CVEs) activas en la IP
    shodan_vulns = port_data.get("passive_internetdb_intel", {}).get("vulns", [])
    if shodan_vulns:
        penalty += min(45.0, len(shodan_vulns) * 10.0)

    return min(100.0, penalty)


def calculate_drps_extended_penalty(
    identity_data: Optional[Dict[str, Any]] = None,
    typosquatting_data: Optional[Dict[str, Any]] = None,
    shadow_dns_data: Optional[Dict[str, Any]] = None,
    kev_epss_data: Optional[Dict[str, Any]] = None,
    cloud_leak_data: Optional[Dict[str, Any]] = None
) -> Dict[str, float]:
    """
    Calcula las penalizaciones deterministas de los 5 motores DRPS/EASM avanzados.
    """
    p_identity = 0.0
    p_brand = 0.0
    p_shadow = 0.0
    p_kev = 0.0
    p_cloud = 0.0

    # 1. Infostealers (Hudson Rock)
    if identity_data:
        emp = identity_data.get("compromised_employees", 0)
        usr = identity_data.get("compromised_users", 0)
        if emp > 0:
            p_identity = min(100.0, 50.0 + (emp * 5.0))
        elif usr > 0:
            p_identity = min(60.0, 20.0 + (usr * 0.5))

    # 2. Typosquatting & BEC
    if typosquatting_data:
        mx_clones = typosquatting_data.get("mail_ready_clones_count", 0)
        web_clones = typosquatting_data.get("active_lookalikes_count", 0)
        visual_clones = typosquatting_data.get("visual_phishing_clones_count", 0)
        if visual_clones > 0:
            p_brand = 100.0
        elif mx_clones > 0:
            p_brand = min(100.0, 35.0 + (mx_clones * 15.0))
        elif web_clones > 0:
            p_brand = min(60.0, web_clones * 15.0)

    # 3. Shadow DNS, Subdomain Takeover & NIC Chile
    if shadow_dns_data:
        takeovers = shadow_dns_data.get("takeover_vulnerable_count", 0)
        days_exp = shadow_dns_data.get("domain_registration_rdap", {}).get("days_until_expiration")
        if takeovers > 0:
            p_shadow += min(100.0, takeovers * 60.0)
        if days_exp is not None and days_exp < 15:
            p_shadow += 40.0
        elif days_exp is not None and days_exp < 30:
            p_shadow += 15.0
        p_shadow = min(100.0, p_shadow)

    # 4. Priorizador CISA KEV + FIRST EPSS
    if kev_epss_data:
        p0_count = kev_epss_data.get("same_day_p0_incidents_count", 0)
        ransom_count = kev_epss_data.get("ransomware_active_vectors_count", 0)
        if p0_count > 0:
            p_kev = min(100.0, (p0_count * 35.0) + (ransom_count * 25.0))

    # 5. Cloud Storage Leaks (AWS/GCP/Azure/Firebase)
    if cloud_leak_data:
        open_buckets = cloud_leak_data.get("public_leaking_buckets_count", 0)
        if open_buckets > 0:
            p_cloud = min(100.0, open_buckets * 70.0)

    return {
        "identity_penalty": round(p_identity, 1),
        "brand_penalty": round(p_brand, 1),
        "shadow_dns_penalty": round(p_shadow, 1),
        "kev_epss_penalty": round(p_kev, 1),
        "cloud_leak_penalty": round(p_cloud, 1)
    }


def evaluate_security_posture(
    dns_data: Dict[str, Any],
    web_data: Dict[str, Any],
    port_data: Dict[str, Any],
    identity_data: Optional[Dict[str, Any]] = None,
    typosquatting_data: Optional[Dict[str, Any]] = None,
    shadow_dns_data: Optional[Dict[str, Any]] = None,
    kev_epss_data: Optional[Dict[str, Any]] = None,
    cloud_leak_data: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Calcula el Puntaje Consolidado (R_total) y Calificación S_posture integrando todos los pilares v2.2."""
    p_email = calculate_email_penalty(dns_data)
    p_crypto = calculate_crypto_penalty(web_data)
    p_ports = calculate_ports_penalty(port_data)

    ext = calculate_drps_extended_penalty(
        identity_data, typosquatting_data, shadow_dns_data, kev_epss_data, cloud_leak_data
    )

    r_base = (0.40 * p_ports) + (0.35 * p_email) + (0.25 * p_crypto)

    r_extended = (
        (0.35 * ext["identity_penalty"]) +
        (0.25 * ext["kev_epss_penalty"]) +
        (0.20 * ext["cloud_leak_penalty"]) +
        (0.10 * ext["shadow_dns_penalty"]) +
        (0.10 * ext["brand_penalty"])
    )

    r_total = min(100.0, (0.70 * r_base) + (0.30 * r_extended))
    s_posture = round(100.0 - r_total, 1)

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

    regulatory_notes = []
    if p_ports >= 40.0 or ext["kev_epss_penalty"] >= 35.0:
        regulatory_notes.append(
            "Exposición de servicios críticos con vulnerabilidades activas (CISA KEV / EPSS / Shodan). "
            "Bajo Ley 21.663 (Art. 8 y 9), exige gestión de parches documentada y protocolo de respuesta ante incidentes."
        )
    if p_email >= 40.0 or ext["brand_penalty"] >= 35.0:
        regulatory_notes.append(
            "Riesgo elevado de suplantación de correo corporativo y desvío de pagos (dominios similares con correo activo o falta de bloqueo DMARC)."
        )
    if dns_data.get("rbl_blacklist", {}).get("is_blacklisted", False):
        regulatory_notes.append(
            "Reputación de Correo Comprometida: La IP figura en listas negras internacionales de Spam (RBL), afectando la entrega de correos comerciales."
        )
    if ext["identity_penalty"] > 0:
        regulatory_notes.append(
            "Detección de credenciales o sesiones comprometidas por malware Infostealer en equipos externos/usuarios (Ley 21.663 Art. 8)."
        )
    if ext["cloud_leak_penalty"] > 0:
        regulatory_notes.append(
            "Almacenamiento Cloud público detectado: riesgo directo bajo Ley de Ciberseguridad (21.663) y Protección de Datos Personales (21.719)."
        )

    code_audit = web_data.get("code_security_audit", {}) or web_data.get("http_headers", {}).get("code_security_audit", {})
    if code_audit.get("php_cgi_surface_exposed") or code_audit.get("cms_backdoors_exposed") or code_audit.get("exposed_backup_or_env_files"):
        regulatory_notes.append(
            "Seguridad de Código Web: Se detectó exposición de superficie PHP/CMS o archivos de configuración públicos vulnerables a inyección de comandos."
        )
    if code_audit.get("privacy_ley21719", {}).get("compliance_warning", False):
        regulatory_notes.append(
            "Privacidad Web (Ley N° 21.719): El sitio utiliza rastreadores de terceros sin un aviso o política de privacidad explícita visible en portada."
        )

    sovereignty = dns_data.get("asn_sovereignty", {})
    if sovereignty.get("country_code") and not sovereignty.get("hosted_in_chile"):
        regulatory_notes.append(
            f"Jurisdicción de Alojamiento: Infraestructura web alojada fuera de Chile ({sovereignty.get('country')} - {sovereignty.get('isp_org')}). "
            "Exige resguardar cláusulas de transferencia internacional de datos bajo la Ley N° 21.719."
        )

    global_fingerprints = {
        "score": s_posture,
        "grade": grade,
        "rbl_listed": dns_data.get("rbl_blacklist", {}).get("listed_count", 0),
        "code_env_exposed": len(code_audit.get("exposed_backup_or_env_files", [])),
        "code_backdoors": len(code_audit.get("cms_backdoors_exposed", [])),
        "id_fp": (identity_data or {}).get("drift_fingerprint", ""),
        "typo_fp": (typosquatting_data or {}).get("drift_fingerprint", ""),
        "shadow_fp": (shadow_dns_data or {}).get("drift_fingerprint", ""),
        "kev_fp": (kev_epss_data or {}).get("drift_fingerprint", ""),
        "cloud_fp": (cloud_leak_data or {}).get("drift_fingerprint", "")
    }
    global_drift_hash = hashlib.sha256(
        json.dumps(global_fingerprints, sort_keys=True).encode("utf-8")
    ).hexdigest()

    return {
        "score_posture": s_posture,
        "grade": grade,
        "risk_level": risk_level,
        "penalties": {
            "ports_penalty": round(p_ports, 1),
            "email_penalty": round(p_email, 1),
            "crypto_penalty": round(p_crypto, 1),
            **ext
        },
        "regulatory_context": regulatory_notes,
        "global_drift_hash": global_drift_hash
    }