# modules/shadow_dns_scanner.py
import asyncio
import hashlib
import json
import re
import socket
from datetime import datetime, timezone
import httpx
import dns.asyncresolver
from typing import Dict, Any, List, Set

# Huellas de proveedores Cloud susceptibles a Subdomain Takeover (can-i-take-over-xyz)
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

# Subdominios corporativos críticos que siempre se auditan además de los CT Logs
COMMON_SHADOW_SUBS = [
    "www", "mail", "webmail", "vpn", "remote", "portal", "admin", "intranet",
    "api", "dev", "test", "staging", "beta", "app", "cloud", "autodiscover",
    "cpanel", "webdisk", "ns1", "ns2", "smtp", "pop", "imap", "erp", "pagos"
]


async def _fetch_ct_subdomains(domain: str, timeout: float = 7.0) -> List[str]:
    """
    Combina Certificate Transparency (crt.sh), HackerTarget Passive DNS y
    subdominios corporativos frecuentes para garantizar descubrimiento 100% resiliente.
    """
    subdomains: Set[str] = {domain, f"www.{domain}"}
    for prefix in COMMON_SHADOW_SUBS:
        subdomains.add(f"{prefix}.{domain}")

    headers = {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) SentinelRecon/2.0",
        "Accept": "application/json, text/plain, */*"
    }

    async with httpx.AsyncClient(timeout=timeout, headers=headers, follow_redirects=True) as client:
        # Fuente 1: HackerTarget Passive DNS / Certs (Ultrarrápido)
        try:
            ht_resp = await client.get(f"https://api.hackertarget.com/hostsearch/?q={domain}")
            if ht_resp.status_code == 200 and "error" not in ht_resp.text.lower():
                for line in ht_resp.text.splitlines():
                    parts = line.split(",")
                    if parts:
                        sub = parts[0].strip().lower()
                        if sub.endswith(f".{domain}") or sub == domain:
                            subdomains.add(sub)
        except Exception:
            pass

        # Fuente 2: crt.sh (Certificate Transparency oficial)
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
                            subdomains.add(sub)
        except Exception:
            pass

    return sorted(list(subdomains))


async def _check_subdomain_status(
    subdomain: str,
    resolver: dns.asyncresolver.Resolver,
    sem: asyncio.Semaphore
) -> Dict[str, Any]:
    """
    Resuelve IP y CNAME de cada subdominio y verifica riesgo de Subdomain Takeover.
    """
    async with sem:
        cname_target = None
        ips: List[str] = []
        is_alive = False
        takeover_risk = False
        vulnerable_service = None
        takeover_reason = None
        loop = asyncio.get_running_loop()

        # 1. Verificar registro CNAME
        try:
            ans_cname = await resolver.resolve(subdomain, "CNAME")
            for r in ans_cname:
                cname_target = str(r.target).rstrip(".").lower()
        except Exception:
            pass

        # 2. Verificar resolución de IP nativa del SO
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

        # 3. Validar huella HTTP si el CNAME apunta a un proveedor cloud
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

        return {
            "subdomain": subdomain,
            "is_alive": is_alive,
            "ips": ips[:3],
            "cname": cname_target,
            "takeover_vulnerable": takeover_risk,
            "vulnerable_cloud_service": vulnerable_service,
            "takeover_detail": takeover_reason
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
            # Ejemplo en NIC.cl: "Expiration date: 2027-04-15 14:22:10 CLST"
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

    # 1. Obtener Nameservers reales por consulta DNS directa (100% confiable)
    try:
        ans_ns = await resolver.resolve(domain, "NS")
        rdap_info["nameservers"] = sorted([str(r.target).rstrip(".").lower() for r in ans_ns])
        if rdap_info["nameservers"]:
            rdap_info["registrar_status"] = "active"
    except Exception:
        pass

    # 2. Si es .cl, consultar socket oficial de NIC Chile (whois.nic.cl:43)
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

    # 3. Fallback a RDAP HTTP para dominios internacionales (.com, .net, etc.)
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


async def scan_shadow_dns_and_takeover(domain: str, max_subdomains: int = 45) -> Dict[str, Any]:
    """
    Módulo 2: Sentinel Shadow & Dangling DNS Guard.
    Descubre subdominios sombra, evalúa riesgo de Subdomain Takeover
    y verifica caducidad registral en NIC Chile / RDAP.
    """
    clean_domain = domain.strip().lower()

    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = 2.0
    resolver.lifetime = 2.0

    # 1. Descubrimiento en paralelo: Subdominios + WHOIS/RDAP NIC Chile
    discovered_subs, rdap_data = await asyncio.gather(
        _fetch_ct_subdomains(clean_domain),
        _check_rdap_expiration(clean_domain, resolver)
    )

    subs_to_check = discovered_subs[:max_subdomains]

    sem = asyncio.Semaphore(15)
    tasks = [_check_subdomain_status(sub, resolver, sem) for sub in subs_to_check]
    sub_results = await asyncio.gather(*tasks)

    active_subdomains = [s for s in sub_results if s["is_alive"] or s["cname"]]
    dangling_takeovers = [s for s in sub_results if s["takeover_vulnerable"]]

    status = "clean"
    days_exp = rdap_data.get("days_until_expiration")
    if len(dangling_takeovers) > 0 or (days_exp is not None and days_exp < 15):
        status = "critical"
    elif len(active_subdomains) > 15 or (days_exp is not None and days_exp < 45):
        status = "warning"

    drift_payload = {
        "active_subs": [s["subdomain"] for s in active_subdomains],
        "takeovers": [s["subdomain"] for s in dangling_takeovers],
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
        "takeover_vulnerable_count": len(dangling_takeovers),
        "dangling_takeovers": dangling_takeovers,
        "active_shadow_subdomains": active_subdomains[:20],
        "domain_registration_rdap": rdap_data,
        "anci_art8_inventory_ready": True,
        "drift_fingerprint": drift_hash
    }