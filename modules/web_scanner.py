# modules/web_scanner.py
import ssl
import socket
import datetime
import asyncio
import re
import httpx
import mmh3
import base64
from typing import Dict, Any, List
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


async def audit_web_code_and_surface(
    client: httpx.AsyncClient,
    domain: str,
    home_html: str,
    resp_headers: Dict[str, str],
    set_cookie_list: List[str]
) -> Dict[str, Any]:
    """
    Inspecciona pasivamente el código HTML/JS entregado por el sitio web y rutas críticas:
    1. Exposición PHP / CGI / Superficie php2shell (X-Powered-By, phpinfo, xmlrpc.php, wp-json users).
    2. Librerías JavaScript vulnerables/obsoletas (jQuery, Bootstrap, etc.) y ausencia de SRI.
    3. Archivos de configuración o respaldo olvidados (.env, .git/config, wp-config.php.bak).
    4. Secretos expuestos en frontend, formularios inseguros y cookies sin HttpOnly/Secure.
    5. Inyección de iframes ocultos (Web Defacement) y rastreadores de privacidad (Ley 21.719).
    """
    code_audit = {
        "x_powered_by": resp_headers.get("x-powered-by"),
        "cms_generator": None,
        "php_cgi_surface_exposed": False,
        "php_exposure_details": [],
        "cms_backdoors_exposed": [],
        "exposed_backup_or_env_files": [],
        "outdated_js_libraries": [],
        "external_scripts_without_sri_count": 0,
        "exposed_frontend_secrets": [],
        "insecure_forms_detected": False,
        "insecure_cookies_detected": False,
        "suspicious_hidden_iframes": False,
        "privacy_ley21719": {
            "third_party_trackers": [],
            "has_privacy_or_cookie_notice": False,
            "compliance_warning": False
        }
    }

    # 1. Evaluar cabeceras X-Powered-By y Server en busca de PHP / CGI expuesto
    x_pow = (resp_headers.get("x-powered-by") or "").lower()
    srv = (resp_headers.get("server") or "").lower()
    if "php" in x_pow or "php" in srv:
        code_audit["php_cgi_surface_exposed"] = True
        code_audit["php_exposure_details"].append(
            f"Divulgación activa de intérprete en cabecera ({resp_headers.get('x-powered-by') or resp_headers.get('server')})"
        )

    # 2. Evaluar banderas de seguridad en Cookies de sesión (HttpOnly / Secure)
    for cookie_str in set_cookie_list:
        c_low = cookie_str.lower()
        if "httponly" not in c_low or "secure" not in c_low:
            code_audit["insecure_cookies_detected"] = True

    if home_html:
        html_low = home_html.lower()

        # Meta Generator (WordPress, Joomla, Drupal, Laravel, etc.)
        gen_match = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', home_html, re.I)
        if gen_match:
            code_audit["cms_generator"] = gen_match.group(1).strip()

        # Detectar referencias a rutas .php directas en el DOM
        if ".php" in html_low and not code_audit["php_cgi_surface_exposed"]:
            code_audit["php_exposure_details"].append("Rutas de ejecución .php detectadas en el código público")

        # 3. Escáner de librerías JS antiguas (ej. jQuery 1.x / 2.x, Bootstrap 3.x) y falta de SRI
        script_tags = re.findall(r'<script[^>]+src=["\']([^"\']+)["\'][^>]*>', home_html, re.I)
        for src in script_tags:
            src_low = src.lower()
            jq_match = re.search(r'jquery[.-](\d+\.\d+(?:\.\d+)?)', src_low)
            if jq_match:
                ver = jq_match.group(1)
                if ver.startswith("1.") or ver.startswith("2.") or ver.startswith("3.0") or ver.startswith("3.1") or ver.startswith("3.2") or ver.startswith("3.3") or ver.startswith("3.4"):
                    code_audit["outdated_js_libraries"].append(f"jQuery v{ver} (Vulnerable a XSS)")
            bs_match = re.search(r'bootstrap[.-](\d+\.\d+(?:\.\d+)?)', src_low)
            if bs_match:
                ver = bs_match.group(1)
                if ver.startswith("2.") or ver.startswith("3."):
                    code_audit["outdated_js_libraries"].append(f"Bootstrap v{ver} (Obsoleto)")

        # Contar scripts externos CDN sin sello criptográfico Subresource Integrity (integrity="sha...")
        full_script_tags = re.findall(r'<script[^>]+src=["\']https?://[^"\']+["\'][^>]*>', home_html, re.I)
        for tag in full_script_tags:
            if domain.lower() not in tag.lower() and "integrity=" not in tag.lower():
                code_audit["external_scripts_without_sri_count"] += 1

        # 4. Cazador de claves API o secretos olvidados en el código HTML/JS público
        secret_patterns = [
            (r'AIza[0-9A-Za-z\-_]{35}', "Google Cloud / Maps API Key expuesta en HTML"),
            (r'AKIA[0-9A-Z]{16}', "AWS Access Key ID expuesta en HTML"),
            (r'(?:sk_live|rk_live)_[0-9a-zA-Z]{24,}', "Llave de producción Stripe expuesta"),
            (r'eyJ[A-Za-z0-9_-]{20,}\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}', "Token JWT harcodeado en código público")
        ]
        for pat, desc in secret_patterns:
            if re.search(pat, home_html):
                code_audit["exposed_frontend_secrets"].append(desc)

        # 5. Revisión de formularios inseguros (action hacia http:// o sin protección evidente)
        if re.search(r'<form[^>]+action=["\']http://', home_html, re.I):
            code_audit["insecure_forms_detected"] = True

        # 6. Detección de iframes ocultos (síntoma clásico de inyección Webshell / php2shell)
        if re.search(r'<iframe[^>]+(?:display\s*:\s*none|visibility\s*:\s*hidden|width=["\']?0|height=["\']?0)', home_html, re.I):
            code_audit["suspicious_hidden_iframes"] = True

        # 7. Inspector de Privacidad Web Ley N° 21.719 (Rastreadores vs Aviso de Privacidad)
        trackers_map = {
            "connect.facebook.net": "Meta Pixel (Facebook)",
            "fbevents.js": "Meta Pixel (Facebook)",
            "googletagmanager.com": "Google Tag Manager",
            "google-analytics.com": "Google Analytics",
            "gtag/js": "Google Analytics 4",
            "analytics.tiktok.com": "TikTok Pixel",
            "static.hotjar.com": "Hotjar Session Recording",
            "clarity.ms": "Microsoft Clarity"
        }
        detected_trackers = set()
        for indicator, name in trackers_map.items():
            if indicator in html_low:
                detected_trackers.add(name)
        code_audit["privacy_ley21719"]["third_party_trackers"] = list(detected_trackers)

        privacy_keywords = ["política de privacidad", "politica de privacidad", "privacy policy", "uso de cookies", "protección de datos", "ley 21.719", "ley 19.628"]
        if any(kw in html_low for kw in privacy_keywords):
            code_audit["privacy_ley21719"]["has_privacy_or_cookie_notice"] = True

        if detected_trackers and not code_audit["privacy_ley21719"]["has_privacy_or_cookie_notice"]:
            code_audit["privacy_ley21719"]["compliance_warning"] = True

    # 8. Sondeo concurrente ultra-rápido de puertas traseras PHP/CMS y archivos críticos olvidados
    sensitive_probes = [
        ("/.env", "ENV_FILE", ["db_password", "app_key", "aws_", "mail_host", "secret"]),
        ("/.git/config", "GIT_REPO", ["[core]", "repositoryformatversion"]),
        ("/phpinfo.php", "PHPINFO", ["php version", "zend engine", "php.ini"]),
        ("/xmlrpc.php", "WP_XMLRPC", ["xml-rpc server accepts post requests only", "methodresponse"]),
        ("/wp-json/wp/v2/users", "WP_USER_ENUM", ['"slug":', '"id":']),
        ("/wp-config.php.bak", "WP_CONFIG_BAK", ["db_name", "db_user", "db_password"])
    ]

    async def probe_sensitive_path(path: str, ptype: str, tokens: List[str]):
        try:
            r = await client.get(f"https://{domain}{path}", timeout=2.0)
            body_sample = (r.text[:1500] if r.text else "").lower()
            # Xmlrpc suele responder 405 Method Not Allowed o 200 OK con el mensaje exacto
            if ptype == "WP_XMLRPC" and r.status_code in [200, 405] and any(t in body_sample for t in tokens):
                code_audit["php_cgi_surface_exposed"] = True
                code_audit["cms_backdoors_exposed"].append("/xmlrpc.php (Puerta abierta para fuerza bruta y abuso PHP)")
            elif r.status_code == 200 and any(t in body_sample for t in tokens):
                if ptype in ["ENV_FILE", "GIT_REPO", "WP_CONFIG_BAK"]:
                    code_audit["exposed_backup_or_env_files"].append(path)
                elif ptype == "PHPINFO":
                    code_audit["php_cgi_surface_exposed"] = True
                    code_audit["php_exposure_details"].append("/phpinfo.php público (Exposición total de variables del servidor)")
                elif ptype == "WP_USER_ENUM":
                    code_audit["cms_backdoors_exposed"].append("/wp-json/wp/v2/users (Lista de usuarios administradores expuesta)")
        except Exception:
            pass

    await asyncio.gather(*(probe_sensitive_path(p, pt, tk) for p, pt, tk in sensitive_probes))
    return code_audit


async def get_http_security_posture(domain: str) -> Dict[str, Any]:
    """Analiza encabezados de seguridad HTTP, CORS, cookies, Favicon Hash, exposición de API y seguridad de código web."""
    result = {
        "status_code": None,
        "host_ip": None,
        "server": None,
        "x_powered_by": None,
        "hsts": False,
        "csp": False,
        "x_frame_options": None,
        "x_content_type_options": None,
        "referrer_policy": None,
        "permissions_policy": None,
        "cors_wildcard": False,
        "favicon_mmh3": None,
        "exposure_audit": {},
        "code_security_audit": {},
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
        resp_headers = {}
        set_cookie_list = []
        try:
            resp = await client.get(url)
            result["status_code"] = resp.status_code
            home_html = resp.text[:35000] if resp.text else ""
            resp_headers = {k.lower(): v for k, v in resp.headers.items()}
            set_cookie_list = resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else []
            result["server"] = resp_headers.get("server")
            result["x_powered_by"] = resp_headers.get("x-powered-by")
            result["hsts"] = "strict-transport-security" in resp_headers
            result["csp"] = "content-security-policy" in resp_headers
            result["x_frame_options"] = resp_headers.get("x-frame-options")
            result["x_content_type_options"] = resp_headers.get("x-content-type-options")
            result["referrer_policy"] = resp_headers.get("referrer-policy")
            result["permissions_policy"] = resp_headers.get("permissions-policy")
            result["cors_wildcard"] = resp_headers.get("access-control-allow-origin") == "*"
        except Exception as e:
            result["error"] = str(e)

        # Ejecutar Favicon Hash, Auditoría de Exposición y Auditoría de Código Web en paralelo
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

        async def run_code_audit():
            result["code_security_audit"] = await audit_web_code_and_surface(
                client, domain, home_html, resp_headers, set_cookie_list
            )

        await asyncio.gather(fetch_favicon(), run_exposure(), run_code_audit())

    return result


async def scan_web_crypto(domain: str) -> Dict[str, Any]:
    """Orquesta en paralelo la inspección TLS profunda, HTTP/Exposición y Auditoría de Código Web."""
    loop = asyncio.get_running_loop()
    cert_task = loop.run_in_executor(None, get_ssl_certificate_info, domain)
    http_task = get_http_security_posture(domain)

    cert_data, http_data = await asyncio.gather(cert_task, http_task)

    return {
        "host_ip": http_data.get("host_ip"),
        "ssl_certificate": cert_data,
        "http_headers": http_data,
        "exposure_audit": http_data.get("exposure_audit", {}),
        "code_security_audit": http_data.get("code_security_audit", {})
    }