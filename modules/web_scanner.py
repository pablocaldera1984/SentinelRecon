# modules/web_scanner.py
import ssl
import socket
import datetime
import asyncio
import re
import httpx
import mmh3
import base64
from typing import Dict, Any
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from config import HTTP_TIMEOUT


def get_ssl_certificate_info(domain: str, port: int = 443) -> Dict[str, Any]:
    """Extrae el certificado X.509, versión de protocolo TLS, suite de cifrado y postura Post-Cuántica (PQC)."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    result = {
        "has_ssl": False,
        "expired": False,
        "days_until_expiry": None,
        "issuer": None,
        "subject": None,
        "sans": [],
        "tls_version": None,
        "cipher_suite": None,
        "cipher_bits": None,
        "deprecated_tls": False,
        "pqc_ready_transport": False,
        "error": None
    }

    try:
        with socket.create_connection((domain, port), timeout=3.0) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                result["tls_version"] = ssock.version()
                cipher_info = ssock.cipher()
                if cipher_info:
                    result["cipher_suite"] = cipher_info[0]
                    result["cipher_bits"] = cipher_info[2]

                if result["tls_version"] in ["TLSv1", "TLSv1.1", "SSLv3"]:
                    result["deprecated_tls"] = True

                # Preparación base para algoritmos híbridos / TLS 1.3 moderno
                if result["tls_version"] == "TLSv1.3":
                    result["pqc_ready_transport"] = True

                der_cert = ssock.getpeercert(binary_form=True)
                if not der_cert:
                    return result
                
                result["has_ssl"] = True
                cert = x509.load_der_x509_certificate(der_cert, default_backend())
                
                expiry_date = cert.not_valid_after_utc.replace(tzinfo=None)
                remaining_days = (expiry_date - datetime.datetime.utcnow()).days
                result["days_until_expiry"] = remaining_days
                result["expired"] = remaining_days < 0

                try:
                    result["subject"] = cert.subject.rfc4514_string()
                    result["issuer"] = cert.issuer.rfc4514_string()
                except Exception:
                    pass

                try:
                    san_ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                    result["sans"] = san_ext.value.get_values_for_type(x509.DNSName)
                except Exception:
                    pass

    except Exception as e:
        result["error"] = str(e)

    return result


async def audit_web_exposure_and_governance(client: httpx.AsyncClient, domain: str, home_html: str) -> Dict[str, Any]:
    """
    Audita de forma pasiva y defensiva metadatos de gobernanza (security.txt),
    documentación de API pública (Swagger/OpenAPI) y referencias a SourceMaps en el frontend.
    """
    exposure = {
        "has_security_txt": False,
        "openapi_swagger_exposed": False,
        "Exposed_endpoints": [],
        "sourcemaps_referenced": False,
        "frontend_tech_hints": []
    }

    # 1. Detectar referencias a SourceMaps o frameworks en el HTML principal
    if home_html:
        if ".js.map" in home_html or "sourceMappingURL" in home_html:
            exposure["sourcemaps_referenced"] = True
        if "_next/static" in home_html:
            exposure["frontend_tech_hints"].append("Next.js")
        if "wp-content" in home_html:
            exposure["frontend_tech_hints"].append("WordPress")
        if "firebase" in home_html.lower():
            exposure["frontend_tech_hints"].append("Firebase SDK")

    # 2. Sondeo ligero de rutas estándar con validación estricta de contenido (anti-falsos positivos SPA)
    probes = [
        ("/.well-known/security.txt", "SECURITY_TXT", "Contact:"),
        ("/swagger.json", "SWAGGER_API", '"swagger"'),
        ("/openapi.json", "OPENAPI_SPEC", '"openapi"'),
        ("/graphql", "GRAPHQL_ENDPOINT", "query")
    ]

    async def check_path(path: str, label: str, expected_token: str):
        try:
            r = await client.get(f"https://{domain}{path}", timeout=2.0)
            if r.status_code == 200 and expected_token.lower() in r.text[:1000].lower():
                if label == "SECURITY_TXT":
                    exposure["has_security_txt"] = True
                else:
                    exposure["openapi_swagger_exposed"] = True
                    exposure["Exposed_endpoints"].append(path)
        except Exception:
            pass

    await asyncio.gather(*(check_path(p, lbl, tok) for p, lbl, tok in probes))
    return exposure


async def get_http_security_posture(domain: str) -> Dict[str, Any]:
    """Analiza encabezados de seguridad HTTP, CORS, cookies, Favicon Hash y exposición de API/metadatos."""
    result = {
        "status_code": None,
        "host_ip": None,
        "server": None,
        "hsts": False,
        "csp": False,
        "x_frame_options": None,
        "x_content_type_options": None,
        "referrer_policy": None,
        "permissions_policy": None,
        "cors_wildcard": False,
        "favicon_mmh3": None,
        "exposure_audit": {},
        "error": None
    }

    try:
        result["host_ip"] = socket.gethostbyname(domain)
    except Exception:
        pass

    url = f"https://{domain}"
    favicon_url = f"https://{domain}/favicon.ico"

    headers_ua = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"
    }

    async with httpx.AsyncClient(verify=False, timeout=HTTP_TIMEOUT, headers=headers_ua, follow_redirects=True) as client:
        home_html = ""
        try:
            resp = await client.get(url)
            result["status_code"] = resp.status_code
            home_html = resp.text[:15000] if resp.text else ""
            headers = {k.lower(): v for k, v in resp.headers.items()}
            result["server"] = headers.get("server")
            result["hsts"] = "strict-transport-security" in headers
            result["csp"] = "content-security-policy" in headers
            result["x_frame_options"] = headers.get("x-frame-options")
            result["x_content_type_options"] = headers.get("x-content-type-options")
            result["referrer_policy"] = headers.get("referrer-policy")
            result["permissions_policy"] = headers.get("permissions-policy")
            result["cors_wildcard"] = headers.get("access-control-allow-origin") == "*"
        except Exception as e:
            result["error"] = str(e)

        # Ejecutar Favicon Hash y Auditoría de Exposición en paralelo
        async def fetch_favicon():
            try:
                fav_resp = await client.get(favicon_url, timeout=2.0)
                if fav_resp.status_code == 200 and fav_resp.content:
                    b64_fav = base64.encodebytes(fav_resp.content)
                    result["favicon_mmh3"] = mmh3.hash(b64_fav)
            except Exception:
                pass

        async def run_exposure():
            result["exposure_audit"] = await audit_web_exposure_and_governance(client, domain, home_html)

        await asyncio.gather(fetch_favicon(), run_exposure())

    return result


async def scan_web_crypto(domain: str) -> Dict[str, Any]:
    """Orquesta en paralelo la inspección TLS profunda y HTTP/Exposición."""
    loop = asyncio.get_running_loop()
    cert_task = loop.run_in_executor(None, get_ssl_certificate_info, domain)
    http_task = get_http_security_posture(domain)

    cert_data, http_data = await asyncio.gather(cert_task, http_task)

    return {
        "host_ip": http_data.get("host_ip"),
        "ssl_certificate": cert_data,
        "http_headers": http_data,
        "exposure_audit": http_data.get("exposure_audit", {})
    }