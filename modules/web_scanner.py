import ssl
import socket
import datetime
import asyncio
import httpx
import mmh3
import base64
from typing import Dict, Any
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from config import HTTP_TIMEOUT

def get_ssl_certificate_info(domain: str, port: int = 443) -> Dict[str, Any]:
    """Extrae y parsea el certificado X.509 binario de forma pasiva vía SNI."""
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
        "error": None
    }

    try:
        with socket.create_connection((domain, port), timeout=3.0) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                der_cert = ssock.getpeercert(binary_form=True)
                if not der_cert:
                    return result
                
                result["has_ssl"] = True
                cert = x509.load_der_x509_certificate(der_cert, default_backend())
                
                # Fechas de expiración usando UTC
                expiry_date = cert.not_valid_after_utc.replace(tzinfo=None)
                remaining_days = (expiry_date - datetime.datetime.utcnow()).days
                result["days_until_expiry"] = remaining_days
                result["expired"] = remaining_days < 0

                # Extracción de emisor y sujeto
                try:
                    result["subject"] = cert.subject.rfc4514_string()
                    result["issuer"] = cert.issuer.rfc4514_string()
                except Exception:
                    pass

                # Subject Alternative Names (SANs)
                try:
                    san_ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                    result["sans"] = san_ext.value.get_values_for_type(x509.DNSName)
                except Exception:
                    pass

    except Exception as e:
        result["error"] = str(e)

    return result

async def get_http_security_posture(domain: str) -> Dict[str, Any]:
    """Analiza encabezados de seguridad HTTP y calcula el favicon MurmurHash3."""
    result = {
        "status_code": None,
        "server": None,
        "hsts": False,
        "csp": False,
        "x_frame_options": None,
        "x_content_type_options": None,
        "favicon_mmh3": None,
        "error": None
    }

    url = f"https://{domain}"
    favicon_url = f"https://{domain}/favicon.ico"

    headers_ua = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"
    }

    async with httpx.AsyncClient(verify=False, timeout=HTTP_TIMEOUT, headers=headers_ua, follow_redirects=True) as client:
        try:
            resp = await client.get(url)
            result["status_code"] = resp.status_code
            headers = {k.lower(): v for k, v in resp.headers.items()}
            result["server"] = headers.get("server")
            result["hsts"] = "strict-transport-security" in headers
            result["csp"] = "content-security-policy" in headers
            result["x_frame_options"] = headers.get("x-frame-options")
            result["x_content_type_options"] = headers.get("x-content-type-options")
        except Exception as e:
            result["error"] = str(e)

        try:
            fav_resp = await client.get(favicon_url)
            if fav_resp.status_code == 200 and fav_resp.content:
                b64_fav = base64.encodebytes(fav_resp.content)
                result["favicon_mmh3"] = mmh3.hash(b64_fav)
        except Exception:
            pass

    return result

async def scan_web_crypto(domain: str) -> Dict[str, Any]:
    """Orquesta en paralelo la inspección TLS y HTTP."""
    loop = asyncio.get_running_loop()
    cert_task = loop.run_in_executor(None, get_ssl_certificate_info, domain)
    http_task = get_http_security_posture(domain)

    cert_data, http_data = await asyncio.gather(cert_task, http_task)

    return {
        "ssl_certificate": cert_data,
        "http_headers": http_data
    }
