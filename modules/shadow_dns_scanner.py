# modules/shadow_dns_scanner.py
import asyncio
import hashlib
import html
import json
import re
import socket
from datetime import datetime, timezone
import httpx
import dns.asyncresolver
from typing import Dict, Any, List, Set, Tuple

TAKEOVER_FINGERPRINTS = {
    "github.io": {"service": "GitHub Pages", "body_match": "There isn't a GitHub Pages site here"},
    "amazonaws.com": {"service": "AWS S3 / CloudFront", "body_match": "NoSuchBucket"},
    "azurewebsites.net": {"service": "Microsoft Azure App Service", "body_match": "404 Web Site not found"},
    "cloudapp.net": {"service": "Microsoft Azure CloudApp", "body_match": "404"},
    "trafficmanager.net": {"service": "Azure Traffic Manager", "body_match": "404"},
    "herokuapp.com": {"service": "Heroku", "body_match": "No such app"},
    "myshopify.com": {"service": "Shopify", "body_match": "Sorry, this shop is currently unavailable"},
    "wpengine.com": {"service": "WP Engine", "body_match": "The site you were looking for couldn't be found"},
    "fastly.net": {"service": "Fastly CDN", "body_match": "Fastly error: unknown domain"},
    "pantheonsite.io": {"service": "Pantheon", "body_match": "404 error unknown site"},
    "zendesk.com": {"service": "Zendesk", "body_match": "Help Center Closed"},
    "vercel.app": {"service": "Vercel", "body_match": "DEPLOYMENT_NOT_FOUND"}
}

COMMON_SHADOW_SUBS = [
    "www", "mail", "webmail", "vpn", "remote", "portal", "admin", "intranet",
    "api", "dev", "test", "staging", "beta", "app", "cloud", "autodiscover",
    "cpanel", "webdisk", "ns1", "ns2", "smtp", "pop", "imap", "erp", "pagos",
    "clientes", "proveedores", "postulaciones", "personas", "empresas", "tienda",
    "pagosweb", "facturacion", "soporte", "ayuda", "capacitacion", "aula", "campus"
]

# Prefijos de infraestructura pura (correo/DNS) que no se contabilizan como "páginas web anexas de negocio"
NON_WEB_INFRA_PREFIXES = {
    "ns1", "ns2", "ns3", "ns4", " dns", "dns1", "dns2",
    "smtp", "pop", "pop3", "imap", "mx", "mx1", "mx2", "autodiscover", "autoconfig"
}

# Clasificador de subdominios de alto riesgo (Ambientes olvidados de ex-proveedores o paneles administrativos)
HIGH_RISK_SUBDOMAIN_PREFIXES = {
    "dev": "Ambiente de Desarrollo / Pruebas de Programadores (dev)",
    "test": "Ambiente de Pruebas Olvidado (test)",
    "staging": "Servidor Pre-Producción / Agencia Externa (staging)",
    "beta": "Versión Beta sin Blindaje (beta)",
    "cpanel": "Panel de Control Maestro del Hosting (cpanel)",
    "webmail": "Acceso Directo a Casillas de Correo por Navegador (webmail)",
    "admin": "Consola de Administración Expuesta (admin)",
    "intranet": "Portal Interno Corporativo Expuesto a Internet (intranet)",
    "vpn": "Concentrador de Red Privada Expuesto (vpn)",
    "remote": "Acceso Remoto de Terceros (remote)",
    "erp": "Sistema de Gestión / Facturación Expuesto (erp)",
    "webdisk": "Disco Remoto de Archivos del Servidor (webdisk)",
    "portal": "Portal Corporativo / Acceso Secundario (portal)",
    "clientes": "Portal de Clientes Expuesto (clientes)",
    "proveedores": "Portal de Proveedores Expuesto (proveedores)",
    "postulaciones": "Portal de Postulaciones / Campaña (postulaciones)",
    "facturacion": "Sistema de Facturación / Pagos (facturacion)"
}


async def _fetch_ct_subdomains(domain: str, timeout: float = 7.0) -> Tuple[List[str], List[str]]:
    """
    Combina Certificate Transparency (crt.sh) y HackerTarget Passive DNS (prioridad 1: hallazgos reales)
    con subdominios corporativos frecuentes (prioridad 2: diccionario activo).
    Retorna (osint_discovered, dictionary_candidates).
    """
    osint_subs: Set[str] = set()
    dict_subs: Set[str] = {f"{prefix}.{domain}" for prefix in COMMON_SHADOW_SUBS}

    headers = {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) SentinelRecon/2.3",
        "Accept": "application/json, text/plain, */*"
    }

    async with httpx.AsyncClient(timeout=timeout, headers=headers, follow_redirects=True) as client:
        try:
            ht_resp = await client.get(f"https://api.hackertarget.com/hostsearch/?q={domain}")
            if ht_resp.status_code == 200 and "error" not in ht_resp.text.lower():
                for line in ht_resp.text.splitlines():
                    parts = line.split(",")
                    if parts:
                        sub = parts[0].strip().lower()
                        if sub.endswith(f".{domain}") or sub == domain:
                            osint_subs.add(sub)
        except Exception:
            pass

        try:
            crt_resp = await client.get("https://crt.sh/", params={"q": domain, "output": "json"})
            if crt_resp.status_code == 200:
                for item in crt_resp.json():
                    name_val = item.get("name_value", "")
                    for line in name_val.splitlines():
                        sub = line.strip().lower()
                        if sub.startswith("*."):
                            sub = sub[2:]
                        if (sub == domain or sub.endswith(f".{domain}")) and "@" not in sub:
                            osint_subs.add(sub)
        except Exception:
            pass

    return sorted(list(osint_subs)), sorted(list(dict_subs - osint_subs))


async def _probe_live_web_page(subdomain: str, domain: str) -> Dict[str, Any]:
    """
    Verifica si un subdominio con IP activa tiene una página o portal web abierto (HTTP/HTTPS),
    extrayendo su título (<title>), estado HTTP, tecnología y si presenta un login o panel.
    """
    web_info = {
        "web_active": False,
        "url": None,
        "http_status": None,
        "page_title": None,
        "server_tech": None,
        "has_login_form": False,
        "is_main_site": subdomain in (domain, f"www.{domain}")
    }

    # Omitir sondeo HTTP en subdominios puramente de infraestructura DNS o transporte de correo
    if subdomain.endswith(f".{domain}"):
        prefix = subdomain[:-len(f".{domain}")].split(".")[0]
        if prefix in NON_WEB_INFRA_PREFIXES:
            return web_info

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 SentinelRecon/2.3",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    }

    async with httpx.AsyncClient(timeout=2.5, verify=False, follow_redirects=True, max_redirects=3, headers=headers) as client:
        for scheme in ("https", "http"):
            try:
                resp = await client.get(f"{scheme}://{subdomain}")
                # Consideramos sitio web activo si responde un estado válido de aplicación web
                if resp.status_code in (200, 201, 202, 204, 301, 302, 307, 308, 401, 403):
                    web_info["web_active"] = True
                    web_info["url"] = str(resp.url)
                    web_info["http_status"] = resp.status_code

                    srv = resp.headers.get("server", "")
                    powered = resp.headers.get("x-powered-by", "")
                    tech_parts = [p.strip() for p in (srv, powered) if p.strip()]
                    if tech_parts:
                        web_info["server_tech"] = " | ".join(tech_parts)[:60]

                    body_sample = resp.text[:15000] if resp.text else ""
                    title_match = re.search(r"<title[^>]*>(.*?)</title>", body_sample, re.IGNORECASE | re.DOTALL)
                    if title_match:
                        raw_title = html.unescape(title_match.group(1))
                        clean_title = re.sub(r"\s+", " ", raw_title).strip()
                        if clean_title:
                            web_info["page_title"] = clean_title[:80]

                    if re.search(r'type=["\']password["\']|wp-login|cpanel|webmail|iniciar sesi[oó]n|login', body_sample, re.IGNORECASE):
                        web_info["has_login_form"] = True

                    break
            except Exception:
                continue

    return web_info


async def _check_subdomain_status(
    subdomain: str,
    domain: str,
    resolver: dns.asyncresolver.Resolver,
    sem: asyncio.Semaphore
) -> Dict[str, Any]:
    """
    Resuelve IP y CNAME de cada subdominio, verifica riesgo de Subdomain Takeover
    y sondea si mantiene una página web abierta.
    """
    async with sem:
        cname_target = None
        ips: List[str] = []
        is_alive = False
        takeover_risk = False
        vulnerable_service = None
        takeover_reason = None
        loop = asyncio.get_running_loop()

        try:
            ans_cname = await resolver.resolve(subdomain, "CNAME")
            for r in ans_cname:
                cname_target = str(r.target).rstrip(".").lower()
        except Exception:
            pass

        try:
            addr_info = await asyncio.wait_for(
                loop.getaddrinfo(subdomain, None, family=socket.AF_INET),
                timeout=2.0
            )
            ips = sorted(list({item[4][0] for item in addr_info if item[4]}))
            is_alive = len(ips) > 0
        except Exception:
            if cname_target:
                for provider_domain, fp in TAKEOVER_FINGERPRINTS.items():
                    if provider_domain in cname_target:
                        takeover_risk = True
                        vulnerable_service = fp["service"]
                        takeover_reason = f"CNAME huérfano ({cname_target}) sin resolución IP activa (NXDOMAIN)"
                        break

        if cname_target and is_alive and not takeover_risk:
            for provider_domain, fp in TAKEOVER_FINGERPRINTS.items():
                if provider_domain in cname_target:
                    try:
                        async with httpx.AsyncClient(timeout=2.5, verify=False) as client:
                            http_resp = await client.get(f"http://{subdomain}")
                            if fp["body_match"].lower() in http_resp.text.lower():
                                takeover_risk = True
                                vulnerable_service = fp["service"]
                                takeover_reason = f"Respuesta HTTP coincide con recurso no reclamado en {fp['service']}"
                    except Exception:
                        pass
                    break

        web_info = {
            "web_active": False,
            "url": None,
            "http_status": None,
            "page_title": None,
            "server_tech": None,
            "has_login_form": False,
            "is_main_site": subdomain in (domain, f"www.{domain}")
        }
        if is_alive:
            web_info = await _probe_live_web_page(subdomain, domain)

        return {
            "subdomain": subdomain,
            "is_alive": is_alive,
            "ips": ips[:3],
            "cname": cname_target,
            "takeover_vulnerable": takeover_risk,
            "vulnerable_cloud_service": vulnerable_service,
            "takeover_detail": takeover_reason,
            "web_active": web_info["web_active"],
            "web_url": web_info["url"],
            "http_status": web_info["http_status"],
            "page_title": web_info["page_title"],
            "server_tech": web_info["server_tech"],
            "has_login_form": web_info["has_login_form"],
            "is_main_site": web_info["is_main_site"]
        }


async def _query_nic_cl_whois_socket(domain: str, timeout: float = 4.0) -> Dict[str, Any]:
    """
    Consulta directamente el socket TCP WHOIS (puerto 43) de whois.nic.cl
    para extraer Fecha de Expiración y Nameservers en dominios chilenos (.cl).
    """
    info = {"expiration_date": None, "nameservers": []}
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection("whois.nic.cl", 43),
            timeout=timeout
        )
        writer.write(f"{domain}\r\n".encode("utf-8"))
        await writer.drain()
        raw_bytes = await asyncio.wait_for(reader.read(8192), timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

        text = raw_bytes.decode("utf-8", errors="ignore")
        ns_set = set()
        for line in text.splitlines():
            line_clean = line.strip()
            if line_clean.lower().startswith("expiration date:"):
                val = line_clean.split(":", 1)[1].strip()
                match_date = re.search(r"(\d{4}-\d{2}-\d{2})", val)
                if match_date:
                    info["expiration_date"] = match_date.group(1)
            elif line_clean.lower().startswith("name server:"):
                ns_val = line_clean.split(":", 1)[1].strip().split()[0].lower().rstrip(".")
                if ns_val:
                    ns_set.add(ns_val)
        info["nameservers"] = sorted(list(ns_set))
    except Exception:
        pass
    return info


async def _check_rdap_expiration(domain: str, resolver: dns.asyncresolver.Resolver, timeout: float = 5.0) -> Dict[str, Any]:
    """
    Consulta RDAP + Fallback directo a Socket WHOIS de NIC Chile y DNS NS
    para garantizar siempre la fecha de expiración y los Nameservers.
    """
    rdap_info = {
        "registry": "NIC Chile (WHOIS/RDAP)" if domain.endswith(".cl") else "Global RDAP",
        "expiration_date": None,
        "days_until_expiration": None,
        "nameservers": [],
        "registrar_status": "unknown"
    }

    try:
        ans_ns = await resolver.resolve(domain, "NS")
        rdap_info["nameservers"] = sorted([str(r.target).rstrip(".").lower() for r in ans_ns])
        if rdap_info["nameservers"]:
            rdap_info["registrar_status"] = "active"
    except Exception:
        pass

    if domain.endswith(".cl"):
        nic_data = await _query_nic_cl_whois_socket(domain, timeout=timeout)
        if nic_data["expiration_date"]:
            rdap_info["expiration_date"] = nic_data["expiration_date"]
            try:
                exp_dt = datetime.strptime(nic_data["expiration_date"], "%Y-%m-%d").replace(tzinfo=timezone.utc)
                rdap_info["days_until_expiration"] = (exp_dt - datetime.now(timezone.utc)).days
            except Exception:
                pass
        if not rdap_info["nameservers"] and nic_data["nameservers"]:
            rdap_info["nameservers"] = nic_data["nameservers"]
            rdap_info["registrar_status"] = "active"

    if not rdap_info["expiration_date"]:
        url = f"https://rdap.org/domain/{domain}"
        headers = {"Accept": "application/rdap+json, application/json"}
        try:
            async with httpx.AsyncClient(timeout=timeout, headers=headers, follow_redirects=True) as client:
                resp = await client.get(url)
                if resp.status_code == 200:
                    data = resp.json()
                    for ev in data.get("events", []):
                        if ev.get("eventAction") == "expiration":
                            exp_str = ev.get("eventDate", "")
                            rdap_info["expiration_date"] = exp_str[:10]
                            try:
                                exp_dt = datetime.fromisoformat(exp_str.replace("Z", "+00:00"))
                                rdap_info["days_until_expiration"] = (exp_dt - datetime.now(timezone.utc)).days
                            except Exception:
                                pass
                            break
                    rdap_info["registrar_status"] = "active"
        except Exception:
            pass

    return rdap_info


async def scan_shadow_dns_and_takeover(domain: str, max_subdomains: int = 55) -> Dict[str, Any]:
    """
    Módulo 2: Sentinel Shadow & Dangling DNS Guard + Buscador de Páginas Web Abiertas y Portales Olvidados.
    """
    clean_domain = domain.strip().lower()

    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = 2.0
    resolver.lifetime = 2.0

    (osint_subs, dict_subs), rdap_data = await asyncio.gather(
        _fetch_ct_subdomains(clean_domain),
        _check_rdap_expiration(clean_domain, resolver)
    )

    # Priorizar dominio raíz + hallazgos reales en CT/PassiveDNS y luego completar con diccionario
    priority_list: List[str] = [clean_domain, f"www.{clean_domain}"]
    for s in osint_subs:
        if s not in priority_list:
            priority_list.append(s)
    for s in dict_subs:
        if s not in priority_list:
            priority_list.append(s)

    subs_to_check = priority_list[:max_subdomains]

    sem = asyncio.Semaphore(15)
    tasks = [_check_subdomain_status(sub, clean_domain, resolver, sem) for sub in subs_to_check]
    sub_results = await asyncio.gather(*tasks)

    active_subdomains = [s for s in sub_results if s["is_alive"] or s["cname"]]
    dangling_takeovers = [s for s in sub_results if s["takeover_vulnerable"]]

    # Clasificar páginas web activas (principales vs. páginas/portales anexos abiertos)
    active_web_sites = []
    additional_open_web_pages = []
    seen_main_site = False

    for s in active_subdomains:
        if s.get("web_active"):
            sub_name = s["subdomain"]
            role_label = "Sitio Web Principal" if s.get("is_main_site") else "Página / Portal Web Anexo"
            if sub_name.endswith(f".{clean_domain}"):
                prefix = sub_name[:-len(f".{clean_domain}")].split(".")[0]
                if prefix in HIGH_RISK_SUBDOMAIN_PREFIXES:
                    role_label = HIGH_RISK_SUBDOMAIN_PREFIXES[prefix]

            site_entry = {
                "subdomain": sub_name,
                "url": s.get("web_url") or f"https://{sub_name}",
                "page_title": s.get("page_title") or "Sitio Web Activo (Sin título HTML)",
                "http_status": s.get("http_status"),
                "server_tech": s.get("server_tech"),
                "has_login_form": s.get("has_login_form", False),
                "role": role_label,
                "ips": s["ips"],
                "is_main_site": s.get("is_main_site", False)
            }

            if s.get("is_main_site"):
                # Consolidar empresa.cl y www.empresa.cl como 1 solo sitio principal para no duplicar el conteo al cliente
                if not seen_main_site:
                    seen_main_site = True
                    active_web_sites.append(site_entry)
            else:
                active_web_sites.append(site_entry)
                additional_open_web_pages.append(site_entry)

    # Detectar subdominios administrativos, paneles o páginas anexas olvidadas
    exposed_admin_or_dev_portals = []
    for s in active_subdomains:
        sub_name = s["subdomain"]
        if sub_name.endswith(f".{clean_domain}"):
            prefix = sub_name[:-len(f".{clean_domain}")].split(".")[0]
            if prefix in HIGH_RISK_SUBDOMAIN_PREFIXES:
                exposed_admin_or_dev_portals.append({
                    "subdomain": sub_name,
                    "role": HIGH_RISK_SUBDOMAIN_PREFIXES[prefix],
                    "ips": s["ips"],
                    "web_active": s.get("web_active", False),
                    "page_title": s.get("page_title")
                })
            elif s.get("web_active") and not s.get("is_main_site"):
                # Si es un subdominio personalizado (ej. becas2022.empresa.cl) con web abierta, incluirlo también
                exposed_admin_or_dev_portals.append({
                    "subdomain": sub_name,
                    "role": f"Página Web Anexa Abierta ({s.get('page_title') or sub_name})",
                    "ips": s["ips"],
                    "web_active": True,
                    "page_title": s.get("page_title")
                })

    status = "clean"
    days_exp = rdap_data.get("days_until_expiration")
    if len(dangling_takeovers) > 0 or (days_exp is not None and days_exp < 15):
        status = "critical"
    elif (
        len(active_subdomains) > 15
        or len(exposed_admin_or_dev_portals) > 0
        or len(additional_open_web_pages) > 0
        or (days_exp is not None and days_exp < 45)
    ):
        status = "warning"

    drift_payload = {
        "active_subs": [s["subdomain"] for s in active_subdomains],
        "active_web_pages": [w["subdomain"] for w in active_web_sites],
        "takeovers": [s["subdomain"] for s in dangling_takeovers],
        "admin_portals": [p["subdomain"] for p in exposed_admin_or_dev_portals],
        "nameservers": rdap_data["nameservers"]
    }
    drift_hash = hashlib.sha256(
        json.dumps(drift_payload, sort_keys=True).encode("utf-8")
    ).hexdigest()

    return {
        "module": "shadow_dangling_dns_guard",
        "domain": clean_domain,
        "status": status,
        "total_candidates_evaluated": len(subs_to_check),
        "active_subdomains_count": len(active_subdomains),
        "active_web_sites_count": len(active_web_sites),
        "active_web_sites": active_web_sites[:20],
        "additional_open_web_pages_count": len(additional_open_web_pages),
        "additional_open_web_pages": additional_open_web_pages[:15],
        "takeover_vulnerable_count": len(dangling_takeovers),
        "dangling_takeovers": dangling_takeovers,
        "exposed_admin_or_dev_portals": exposed_admin_or_dev_portals,
        "exposed_admin_portals_count": len(exposed_admin_or_dev_portals),
        "active_shadow_subdomains": active_subdomains[:20],
        "domain_registration_rdap": rdap_data,
        "anci_art8_inventory_ready": True,
        "drift_fingerprint": drift_hash
    }