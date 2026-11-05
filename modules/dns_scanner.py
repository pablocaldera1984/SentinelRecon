# modules/dns_scanner.py
import asyncio
import socket
import ssl
import re
import httpx
import dns.resolver
import dns.asyncresolver
import dns.reversename
from typing import Dict, Any, List, Optional
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from config import DKIM_SELECTORS, DNS_TIMEOUT

# Catálogo Universal de Proveedores de Hosting, DNS y Nube
HOSTING_PROVIDER_CATALOG = [
    {"match": ["v2networks"], "label": "V2Networks (Chile)"},
    {"match": ["cdmon"], "label": "CDMON"},
    {"match": ["ecohosting"], "label": "Ecohosting (Chile)"},
    {"match": ["hostname", "hn.cl"], "label": "Hostname (Chile)"},
    {"match": ["webhosting.cl"], "label": "Webhosting.cl"},
    {"match": ["bluehosting"], "label": "BlueHosting (Chile)"},
    {"match": ["pluschile"], "label": "PlusChile"},
    {"match": ["hosting.cl"], "label": "Hosting.cl"},
    {"match": ["planetahosting"], "label": "PlanetaHosting"},
    {"match": ["inc.cl"], "label": "INC Hosting"},
    {"match": ["cloudflare"], "label": "Cloudflare"},
    {"match": ["hostgator"], "label": "HostGator"},
    {"match": ["godaddy", "domaincontrol"], "label": "GoDaddy"},
    {"match": ["awsdns", "amazonaws"], "label": "Amazon Web Services (AWS)"},
    {"match": ["googledomains", "ns-cloud", "google"], "label": "Google Cloud"},
    {"match": ["azure-dns", "microsoft"], "label": "Microsoft Azure"},
    {"match": ["digitalocean"], "label": "DigitalOcean"},
    {"match": ["linode", "akam"], "label": "Akamai / Linode"},
    {"match": ["ovh."], "label": "OVHcloud"},
    {"match": ["hetzner"], "label": "Hetzner"},
    {"match": ["wixdns", "wix.com"], "label": "Wix Cloud"},
    {"match": ["myshopify", "shopify"], "label": "Shopify Cloud"},
    {"match": ["squarespace"], "label": "Squarespace"},
    {"match": ["wpengine"], "label": "WP Engine"},
    {"match": ["kinsta"], "label": "Kinsta"},
    {"match": ["siteground"], "label": "SiteGround"},
    {"match": ["ionos", "1and1"], "label": "IONOS"},
    {"match": ["hostinger"], "label": "Hostinger"},
    {"match": ["namecheap", "registrar-servers"], "label": "Namecheap"},
    {"match": ["zoho"], "label": "Zoho"}
]


async def check_spf(domain: str, resolver: dns.asyncresolver.Resolver) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "exists": False,
        "status": "NOT_CONFIGURED",
        "raw_record": None,
        "is_strict": False,
        "dns_lookup_count": 0,
        "authorized_third_parties": [],
        "error": None
    }
    try:
        answers = await resolver.resolve(domain, 'TXT')
        for rdata in answers:
            txt_content = "".join([part.decode('utf-8', errors='ignore') for part in rdata.strings])
            if txt_content.startswith("v=spf1"):
                result["exists"] = True
                result["raw_record"] = txt_content
                if "-all" in txt_content:
                    result["status"] = "STRICT"
                    result["is_strict"] = True
                elif "~all" in txt_content:
                    result["status"] = "SOFTFAIL"
                elif "?all" in txt_content:
                    result["status"] = "NEUTRAL"
                elif "+all" in txt_content:
                    result["status"] = "PERMISSIVE"

                mechanisms = txt_content.split()
                lookups = sum(1 for m in mechanisms if m.startswith(('include:', 'a', 'mx', 'ptr', 'exists:', 'redirect=')))
                result["dns_lookup_count"] = lookups

                auth_senders = [
                    m for m in mechanisms
                    if m.startswith(("include:", "ip4:", "a:", "mx:", "redirect="))
                ]
                result["authorized_third_parties"] = auth_senders[:8]

                if lookups > 10:
                    result["error"] = "PermError: Más de 10 consultas DNS declaradas"
                break
    except dns.resolver.NXDOMAIN:
        result["error"] = "Dominio inexistente"
    except (dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        result["status"] = "NOT_CONFIGURED"
    except Exception as e:
        result["error"] = str(e)

    return result


async def check_dmarc(domain: str, resolver: dns.asyncresolver.Resolver) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "exists": False,
        "status": "NOT_CONFIGURED",
        "policy": "none",
        "raw_record": None,
        "error": None
    }
    dmarc_domain = f"_dmarc.{domain}"
    try:
        answers = await resolver.resolve(dmarc_domain, 'TXT')
        for rdata in answers:
            txt_content = "".join([part.decode('utf-8', errors='ignore') for part in rdata.strings])
            if txt_content.startswith("v=DMARC1"):
                result["exists"] = True
                result["raw_record"] = txt_content
                tags = [t.strip() for t in txt_content.split(';') if t.strip()]
                for tag in tags:
                    if tag.startswith("p="):
                        policy = tag.split("=")[1].lower()
                        result["policy"] = policy
                        result["status"] = "CONFIGURED"
                break
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        result["status"] = "NOT_CONFIGURED"
    except Exception as e:
        result["error"] = str(e)

    return result


async def check_dkim_selector(domain: str, selector: str, resolver: dns.asyncresolver.Resolver) -> Dict[str, Any]:
    target = f"{selector}._domainkey.{domain}"
    try:
        answers = await resolver.resolve(target, 'TXT')
        for rdata in answers:
            txt_content = "".join([part.decode('utf-8', errors='ignore') for part in rdata.strings])
            if "p=" in txt_content:
                p_value = ""
                for part in txt_content.split(';'):
                    if part.strip().startswith('p='):
                        p_value = part.strip().split('=')[1]

                key_bits = len(p_value) * 6
                is_weak = key_bits < 2048 if key_bits > 0 else True

                return {
                    "selector": selector,
                    "found": True,
                    "raw_record": txt_content,
                    "key_length_est": key_bits,
                    "weak_key": is_weak
                }
    except Exception:
        pass
    return {"selector": selector, "found": False}


async def check_aaaa(domain: str, resolver: dns.asyncresolver.Resolver) -> Dict[str, Any]:
    ipv6_list: List[str] = []
    try:
        answers = await resolver.resolve(domain, 'AAAA')
        ipv6_list = [r.to_text().strip() for r in answers]
    except Exception:
        ipv6_list = []

    return {
        "has_ipv6": len(ipv6_list) > 0,
        "addresses": ipv6_list
    }


async def check_nameservers(domain: str, resolver: dns.asyncresolver.Resolver) -> List[str]:
    ns_list: List[str] = []
    try:
        answers = await resolver.resolve(domain, 'NS')
        ns_list = [str(r.target).rstrip('.').lower() for r in answers]
    except Exception:
        pass
    return ns_list


async def check_mx_architecture(domain: str, resolver: dns.asyncresolver.Resolver) -> Dict[str, Any]:
    mx_info: Dict[str, Any] = {
        "mx_records": [],
        "mail_provider_detected": "Sin Correo Configurado"
    }
    try:
        answers = await resolver.resolve(domain, 'MX')
        records = sorted([(r.preference, str(r.exchange).rstrip('.').lower()) for r in answers])
        mx_hosts = [h for _, h in records]
        mx_info["mx_records"] = mx_hosts

        joined = " ".join(mx_hosts)
        if "google.com" in joined or "googlemail.com" in joined:
            mx_info["mail_provider_detected"] = "Google Workspace (Gmail Corporativo)"
        elif "outlook.com" in joined or "protection.outlook.com" in joined:
            mx_info["mail_provider_detected"] = "Microsoft 365 (Exchange Online)"
        elif "zoho.com" in joined:
            mx_info["mail_provider_detected"] = "Zoho Mail"
        elif "correos.cl" in joined or "entel" in joined:
            mx_info["mail_provider_detected"] = "Servidor de Correo Entel"
        elif any(h == domain or h.endswith(f".{domain}") for h in mx_hosts):
            mx_info["mail_provider_detected"] = "Servidor de Correo Propio / Local (cPanel / Postfix / Exim en el mismo Hosting)"
        elif mx_hosts:
            mx_info["mail_provider_detected"] = f"Proveedor Externo ({mx_hosts[0]})"
    except Exception:
        pass
    return mx_info


async def check_single_srv(prefix: str, service_name: str, domain: str, resolver: dns.asyncresolver.Resolver) -> List[Dict[str, Any]]:
    target = f"{prefix}.{domain}"
    found: List[Dict[str, Any]] = []
    try:
        answers = await resolver.resolve(target, 'SRV')
        for r in answers:
            found.append({
                "service": service_name,
                "query": target,
                "target_host": str(r.target).rstrip('.'),
                "port": r.port,
                "priority": r.priority,
                "weight": r.weight
            })
    except Exception:
        pass
    return found


async def check_srv_records(domain: str, resolver: dns.asyncresolver.Resolver) -> Dict[str, Any]:
    srv_probes = [
        ("_autodiscover._tcp", "Microsoft Exchange / M365 Autodiscover"),
        ("_sip._tls", "Telefonía SIP / Comunicaciones Unificadas"),
        ("_ldap._tcp", "Active Directory LDAP Expuesto"),
        ("_kerberos._tcp", "Controlador de Dominio Kerberos")
    ]

    tasks = [check_single_srv(prefix, name, domain, resolver) for prefix, name in srv_probes]
    results = await asyncio.gather(*tasks)
    detected = [srv for sublist in results for srv in sublist]

    return {
        "probes_count": len(srv_probes),
        "detected_count": len(detected),
        "records": detected
    }


async def check_advanced_dns_governance(domain: str, resolver: dns.asyncresolver.Resolver) -> Dict[str, Any]:
    gov: Dict[str, Any] = {
        "caa_configured": False,
        "caa_records": [],
        "mta_sts_configured": False,
        "tls_rpt_configured": False,
        "bimi_configured": False,
        "dnssec_enabled": False
    }

    try:
        caa_ans = await resolver.resolve(domain, 'CAA')
        gov["caa_records"] = [r.to_text() for r in caa_ans]
        gov["caa_configured"] = len(gov["caa_records"]) > 0
    except Exception:
        pass

    try:
        sts_ans = await resolver.resolve(f"_mta-sts.{domain}", 'TXT')
        for r in sts_ans:
            txt = "".join([p.decode('utf-8', errors='ignore') for p in r.strings])
            if "v=STSv1" in txt:
                gov["mta_sts_configured"] = True
    except Exception:
        pass

    try:
        tlsrpt_ans = await resolver.resolve(f"_smtp._tls.{domain}", 'TXT')
        for r in tlsrpt_ans:
            txt = "".join([p.decode('utf-8', errors='ignore') for p in r.strings])
            if "v=TLSRPTv1" in txt:
                gov["tls_rpt_configured"] = True
    except Exception:
        pass

    try:
        bimi_ans = await resolver.resolve(f"default._bimi.{domain}", 'TXT')
        for r in bimi_ans:
            txt = "".join([p.decode('utf-8', errors='ignore') for p in r.strings])
            if "v=BIMI1" in txt:
                gov["bimi_configured"] = True
    except Exception:
        pass

    try:
        await resolver.resolve(domain, 'DNSKEY')
        gov["dnssec_enabled"] = True
    except Exception:
        pass

    return gov


async def check_rbl_blacklists(ip: Optional[str], resolver: dns.asyncresolver.Resolver) -> Dict[str, Any]:
    rbl_result: Dict[str, Any] = {
        "checked_ip": ip,
        "is_blacklisted": False,
        "listed_count": 0,
        "blacklists_detected": []
    }
    if not ip:
        return rbl_result

    parts = ip.split(".")
    if len(parts) != 4:
        return rbl_result

    reversed_ip = ".".join(reversed(parts))
    rbl_providers = [
        ("zen.spamhaus.org", "Spamhaus ZEN"),
        ("bl.spamcop.net", "SpamCop Blocking List"),
        ("b.barracudacentral.org", "Barracuda Reputation Block List"),
        ("dnsbl.sorbs.net", "SORBS DNSBL")
    ]

    async def query_rbl(zone: str, label: str):
        query_host = f"{reversed_ip}.{zone}"
        try:
            ans = await resolver.resolve(query_host, 'A')
            for r in ans:
                resp_ip = r.to_text().strip()
                if resp_ip.startswith("127.0.0."):
                    rbl_result["blacklists_detected"].append(label)
                    break
        except Exception:
            pass

    await asyncio.gather(*(query_rbl(z, lbl) for z, lbl in rbl_providers))
    rbl_result["listed_count"] = len(rbl_result["blacklists_detected"])
    rbl_result["is_blacklisted"] = rbl_result["listed_count"] > 0
    return rbl_result


def _extract_cert_hostname_by_ip(ip: str, port: int = 2083) -> str:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((ip, port), timeout=2.0) as sock:
            with ctx.wrap_socket(sock) as ssock:
                der_cert = ssock.getpeercert(binary_form=True)
                if not der_cert:
                    return ""
                cert = x509.load_der_x509_certificate(der_cert, default_backend())
                for attr in cert.subject:
                    if attr.oid == x509.NameOID.COMMON_NAME:
                        cn = str(attr.value).strip().lower()
                        if "." in cn and not cn.startswith("*."):
                            return cn
                san_ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                san_val = san_ext.value
                if isinstance(san_val, x509.SubjectAlternativeName):
                    sans = san_val.get_values_for_type(x509.DNSName)
                    for s in sans:
                        s_clean = s.strip().lower().lstrip("*.")
                        if "." in s_clean:
                            return s_clean
    except Exception:
        pass
    return ""


async def _grab_smtp_banner_hostname(ip: str) -> str:
    for port in (25, 587):
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=2.0)
            banner_bytes = await asyncio.wait_for(reader.readline(), timeout=2.0)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            banner = banner_bytes.decode("utf-8", errors="ignore").strip()
            m = re.search(r'^220[\s-]+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', banner)
            if m:
                return m.group(1).lower()
        except Exception:
            pass
    return ""


async def unmask_hidden_server_and_neighbors(
    ip: str,
    domain: str,
    ns_list: List[str],
    isp_org: str,
    resolver: dns.asyncresolver.Resolver
) -> Dict[str, Any]:
    unmask: Dict[str, Any] = {
        "ptr_reverse_dns": None,
        "master_server_hostname": None,
        "uses_dynamic_dns_trick": False,
        "dynamic_dns_provider": None,
        "is_inhouse_or_artisan_server": False,
        "cohosted_neighbors_count": 0,
        "cohosted_domains_sample": [],
        "forensic_summary_executive": None
    }
    if not ip:
        return unmask

    ns_joined = " ".join(ns_list).lower()
    if any(k in ns_joined for k in ["ddns.net", "no-ip", "dyndns", "afraid.org", "duckdns"]):
        unmask["uses_dynamic_dns_trick"] = True
        unmask["dynamic_dns_provider"] = "No-IP / DDNS.net"

    try:
        rev_name = dns.reversename.from_address(ip)
        ptr_ans = await resolver.resolve(rev_name, "PTR")
        for r in ptr_ans:
            unmask["ptr_reverse_dns"] = str(r.target).rstrip(".").lower()
            break
    except Exception:
        pass

    loop = asyncio.get_running_loop()
    cert_2083_task = loop.run_in_executor(None, _extract_cert_hostname_by_ip, ip, 2083)
    cert_993_task = loop.run_in_executor(None, _extract_cert_hostname_by_ip, ip, 993)
    smtp_task = _grab_smtp_banner_hostname(ip)

    async def fetch_cohosted_neighbors() -> List[str]:
        neighbors = set()
        headers = {"User-Agent": "Mozilla/5.0 SentinelRecon/2.3"}
        async with httpx.AsyncClient(timeout=3.5, headers=headers) as client:
            try:
                r_ht = await client.get(f"https://api.hackertarget.com/reverseiplookup/?q={ip}")
                if r_ht.status_code == 200 and "error" not in r_ht.text.lower() and "no records" not in r_ht.text.lower():
                    for line in r_ht.text.splitlines():
                        d_clean = line.strip().lower()
                        if "." in d_clean and " " not in d_clean:
                            if not d_clean.endswith(domain) and not any(x in d_clean for x in ["entel", "in-addr.arpa", "digitalocean"]):
                                neighbors.add(d_clean)
            except Exception:
                pass

            try:
                r_sh = await client.get(f"https://internetdb.shodan.io/{ip}")
                if r_sh.status_code == 200:
                    for h in r_sh.json().get("hostnames", []):
                        h_clean = h.strip().lower()
                        if not h_clean.endswith(domain) and "." in h_clean:
                            neighbors.add(h_clean)
            except Exception:
                pass
        return sorted(list(neighbors))

    c2083, c993, smtp_host, neighbors_list = await asyncio.gather(
        cert_2083_task, cert_993_task, smtp_task, fetch_cohosted_neighbors()
    )

    candidates = [c for c in [c2083, smtp_host, c993, unmask["ptr_reverse_dns"]] if c]
    non_client_candidates = [c for c in candidates if domain not in c]
    master_host = non_client_candidates[0] if non_client_candidates else (candidates[0] if candidates else None)
    unmask["master_server_hostname"] = master_host

    if master_host and any(k in master_host for k in ["ddns.net", "no-ip", "dyndns", "afraid.org", "duckdns"]):
        unmask["uses_dynamic_dns_trick"] = True
        unmask["dynamic_dns_provider"] = "No-IP / DDNS.net"

    clean_neighbor_roots: List[str] = []
    for n in neighbors_list:
        root_n = re.sub(r'^(?:www|mail|cpanel|webmail|autodiscover|cpcalendars|cpcontacts|ftp)\.', '', n)
        if root_n != domain and root_n != master_host and root_n not in clean_neighbor_roots:
            clean_neighbor_roots.append(root_n)

    unmask["cohosted_neighbors_count"] = len(clean_neighbor_roots)
    unmask["cohosted_domains_sample"] = clean_neighbor_roots[:6]

    isp_low = (isp_org or "").lower()
    if any(telco in isp_low for telco in ["entel", "gtd", "telsur", "movistar", "telefonica", "vtr", "claro", "mundo pacifico", "wom"]):
        if unmask["uses_dynamic_dns_trick"] or (unmask["ptr_reverse_dns"] and any(x in unmask["ptr_reverse_dns"] for x in ["clientes", "static", "dinamico", "entel", "gtd"])):
            unmask["is_inhouse_or_artisan_server"] = True

    resumen_partes = []
    if unmask["uses_dynamic_dns_trick"]:
        resumen_partes.append(
            f"Redirección mediante DNS Dinámico ({unmask['dynamic_dns_provider']}) hacia '{master_host or ip}' en red {isp_org}."
        )
    elif master_host:
        resumen_partes.append(f"Servidor matriz identificado como '{master_host}'.")
    if clean_neighbor_roots:
        resumen_partes.append(
            f"Comparte la misma dirección IP con otros {len(clean_neighbor_roots)} sitios vecinos ({', '.join(clean_neighbor_roots[:3])})."
        )
    unmask["forensic_summary_executive"] = " ".join(resumen_partes) if resumen_partes else None

    return unmask


def classify_hosting_architecture(
    domain: str,
    ns_list: List[str],
    asn_info: Dict[str, Any],
    mx_info: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Motor de Inteligencia de Infraestructura (5 Escenarios Universales):
    Entrega todos los textos ejecutivos, alertas y estado de semáforo listos para pintar en el PDF/Portal.
    """
    unm = asn_info.get("forensic_unmasking", {}) or {}
    datacenter = asn_info.get("isp_org") or "Centro de Datos Externo"
    country = asn_info.get("country") or "Exterior"
    hosted_cl = asn_info.get("hosted_in_chile", False)
    isp_low = datacenter.lower()
    ns_joined = " ".join(ns_list).lower()

    # 1. Identificar proveedor comercial de Hosting / DNS
    commercial_provider = ""
    for item in HOSTING_PROVIDER_CATALOG:
        if any(m in ns_joined for m in item["match"]):
            commercial_provider = item["label"]
            break

    if not commercial_provider and ns_list:
        valid_ns = next((n for n in ns_list if not re.search(r'nic\.cl|ddns\.net|dyndns|no-ip|afraid\.org|duckdns', n, re.I)), None)
        if valid_ns:
            parts = valid_ns.lower().rstrip('.').split('.')
            root_ns = ".".join(parts[-2:]) if len(parts) >= 2 else valid_ns
            if root_ns != domain:
                commercial_provider = root_ns.upper()

    master_host = unm.get("master_server_hostname")
    if not commercial_provider and master_host and master_host != domain:
        commercial_provider = master_host

    # 2. Clasificar entre los 5 Escenarios Universales
    is_cdn = any(k in isp_low for k in ["cloudflare", "fastly", "akamai", "imperva", "incapsula", "cloudfront", "sucuri"])
    is_telco = any(k in isp_low for k in ["entel", "gtd", "telsur", "movistar", "telefonica", "vtr", "claro", "mundo pacifico", "wom"])
    uses_ddns = unm.get("uses_dynamic_dns_trick", False)
    has_explicit_provider = bool(commercial_provider and commercial_provider.lower() != isp_low)

    if uses_ddns:
        scenario = "ESCENARIO_C_DNS_DINAMICO"
        semaphore = "PELIGRO"
    elif is_cdn:
        scenario = "ESCENARIO_A_CDN_PROXY"
        semaphore = "BIEN" if hosted_cl else "ATENCION"
    elif is_telco and unm.get("is_inhouse_or_artisan_server"):
        scenario = "ESCENARIO_D_SERVIDOR_ENLACE_TELCO"
        semaphore = "ATENCION"
    elif (unm.get("cohosted_neighbors_count") or 0) > 0:
        scenario = "ESCENARIO_E_HOSTING_COMPARTIDO"
        semaphore = "BIEN" if hosted_cl else "ATENCION"
    else:
        scenario = "ESCENARIO_B_CLOUD_DATACENTER"
        semaphore = "BIEN" if hosted_cl else "ATENCION"

    # 3. Construir Título y Bajada para la Barra Superior de Propiedad
    if is_cdn:
        top_bar_title = f"Escudo CDN: {datacenter} ({country})"
    elif has_explicit_provider and commercial_provider.lower().split()[0] not in isp_low:
        label_prefix = "Proveedor" if uses_ddns else "Hosting"
        top_bar_title = f"{label_prefix}: {commercial_provider} → Red {datacenter} ({country})"
    elif has_explicit_provider:
        top_bar_title = f"Hosting: {commercial_provider} ({country})"
    else:
        top_bar_title = f"{datacenter} ({country})"

    if uses_ddns:
        top_bar_subtitle = (
            f"Atención: Su proveedor ({commercial_provider or 'externo'}) administra este servidor en {country} ({datacenter}) "
            f"usando redirección gratuita {unm.get('dynamic_dns_provider') or 'No-IP/DDNS'}, lo que expone a caídas de servicio."
        )
    elif is_cdn:
        top_bar_subtitle = f"Su sitio filtra el tráfico mediante la red perimetral {datacenter}, ocultando la IP física del servidor ante ataques directos."
    elif hosted_cl:
        top_bar_subtitle = f"Sus datos están alojados físicamente dentro de Chile ({datacenter}), facilitando el cumplimiento de la Ley N° 21.719."
    else:
        top_bar_subtitle = (
            f"Su servicio es gestionado vía {commercial_provider or datacenter}, pero los datos físicos residen en {country}. "
            "La Ley N° 21.719 exige resguardar datos almacenados fuera de Chile."
        )

    # 4. Construir Textos Ejecutivos para el Recuadro 1 del Semáforo (v2.3)
    if is_cdn:
        card1_main = (
            f"Su sitio está protegido detrás de la red perimetral {datacenter} ({country})"
            f"{f' con administración DNS en {commercial_provider}' if has_explicit_provider else ''}, ocultando la dirección IP real del servidor."
        )
    elif has_explicit_provider:
        card1_main = (
            f"Su dominio y servicios son administrados a través de {commercial_provider}, "
            f"utilizando infraestructura física conectada en {datacenter} ({country})."
        )
    else:
        card1_main = f"Su sitio opera directamente sobre infraestructura física de {datacenter} ({country})."

    if hosted_cl:
        card1_main += " Cumple residencia física de datos en Chile (Ley N° 21.719)."
    else:
        card1_main += f" Al almacenarse físicamente en {country}, la Ley N° 21.719 exige declarar el flujo internacional de datos."

    card1_danger_alert = None
    if uses_ddns:
        ddns_prov = unm.get("dynamic_dns_provider") or "No-IP / DDNS.net"
        host_ref = master_host or "ddns.net"
        card1_danger_alert = (
            f"⚠️ RIESGO DE CONTINUIDAD (DNS DINÁMICO {ddns_prov}): Su proveedor informático conectó el dominio usando un "
            f"redireccionador casero pensado para cámaras o conexiones domésticas ({host_ref}). Si esa cuenta externa caduca o "
            "cambia la conexión, su empresa quedará sin página web ni correos de inmediato."
        )

    neighbors = [n for n in (unm.get("cohosted_domains_sample") or []) if n != master_host and n != domain]
    card1_shared_alert = None
    if not is_cdn and neighbors:
        total_n = unm.get("cohosted_neighbors_count") or len(neighbors)
        card1_shared_alert = (
            f"🔎 INFRAESTRUCTURA COMPARTIDA ({total_n} {'vecino' if total_n == 1 else 'vecinos'} en la misma IP): "
            f"Este servidor comparte la misma dirección IP y red con {', '.join(neighbors[:3])}. Si un sitio vecino sufre un ataque "
            "o cae en listas negras de Spam, puede afectar la disponibilidad de su empresa."
        )
    elif is_telco and master_host and master_host != domain and not uses_ddns:
        card1_shared_alert = f"🔎 SERVIDOR EN ENLACE DEDICADO: La máquina responde bajo el identificador interno {master_host} sobre la red de {datacenter}."

    mx_prov = mx_info.get("mail_provider_detected") or ""
    card1_mail_note = None
    if any(k in mx_prov for k in ["Google", "Microsoft", "Zoho"]):
        card1_mail_note = f"✉️ Sus casillas de correo operan separadas del servidor web a través de {mx_prov}."

    return {
        "scenario_code": scenario,
        "semaphore": semaphore,
        "commercial_provider": commercial_provider or datacenter,
        "physical_datacenter": datacenter,
        "physical_country": country,
        "hosted_in_chile": hosted_cl,
        "is_cdn_proxy": is_cdn,
        "uses_dynamic_dns": uses_ddns,
        "top_bar_title": top_bar_title,
        "top_bar_subtitle": top_bar_subtitle,
        "annex_server_label": f"{commercial_provider + ' / ' if has_explicit_provider else ''}{datacenter} ({country})",
        "card1_main_text": card1_main,
        "card1_danger_alert": card1_danger_alert,
        "card1_shared_alert": card1_shared_alert,
        "card1_mail_note": card1_mail_note
    }


async def check_asn_and_data_sovereignty(
    domain: str,
    ns_list: List[str],
    resolver: dns.asyncresolver.Resolver
) -> Dict[str, Any]:
    info: Dict[str, Any] = {
        "primary_ip": None,
        "asn": None,
        "isp_org": None,
        "country": None,
        "country_code": None,
        "hosted_in_chile": False,
        "data_sovereignty_status": "DESCONOCIDO",
        "forensic_unmasking": {}
    }
    try:
        a_ans = await resolver.resolve(domain, 'A')
        ips = [r.to_text().strip() for r in a_ans]
        if ips:
            info["primary_ip"] = ips[0]
    except Exception:
        try:
            info["primary_ip"] = socket.gethostbyname(domain)
        except Exception:
            pass

    if info["primary_ip"]:
        try:
            async with httpx.AsyncClient(timeout=2.5) as client:
                resp = await client.get(f"http://ip-api.com/json/{info['primary_ip']}?fields=status,country,countryCode,isp,org,as")
                if resp.status_code == 200:
                    data = resp.json()
                    if data.get("status") == "success":
                        info["asn"] = data.get("as")
                        info["isp_org"] = data.get("org") or data.get("isp")
                        info["country"] = data.get("country")
                        info["country_code"] = data.get("countryCode")
                        info["hosted_in_chile"] = data.get("countryCode") == "CL"
                        info["data_sovereignty_status"] = (
                            "ALOJAMIENTO LOCAL (CHILE)" if info["hosted_in_chile"]
                            else f"FLUJO TRANSFRONTERIZO ({info['country']} - Auditar Ley 21.719)"
                        )
        except Exception:
            pass

        info["forensic_unmasking"] = await unmask_hidden_server_and_neighbors(
            info["primary_ip"], domain, ns_list, info["isp_org"] or "", resolver
        )

    return info


async def scan_dns_email(domain: str) -> Dict[str, Any]:
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = DNS_TIMEOUT
    resolver.lifetime = DNS_TIMEOUT

    ns_res = await check_nameservers(domain, resolver)

    spf_task = check_spf(domain, resolver)
    dmarc_task = check_dmarc(domain, resolver)
    aaaa_task = check_aaaa(domain, resolver)
    mx_task = check_mx_architecture(domain, resolver)
    srv_task = check_srv_records(domain, resolver)
    gov_task = check_advanced_dns_governance(domain, resolver)
    asn_task = check_asn_and_data_sovereignty(domain, ns_res, resolver)
    dkim_tasks = [check_dkim_selector(domain, sel, resolver) for sel in DKIM_SELECTORS]

    spf_res, dmarc_res, aaaa_res, mx_res, srv_res, gov_res, asn_res, *dkim_results = await asyncio.gather(
        spf_task, dmarc_task, aaaa_task, mx_task, srv_task, gov_task, asn_task, *dkim_tasks
    )

    # Clasificar la arquitectura de hosting en el backend (5 Escenarios Universales)
    asn_res["hosting_profile"] = classify_hosting_architecture(domain, ns_res, asn_res, mx_res)

    rbl_res = await check_rbl_blacklists(asn_res.get("primary_ip"), resolver)
    active_dkim = [res for res in dkim_results if res.get("found")]

    return {
        "domain": domain,
        "nameservers": ns_res,
        "mx_architecture": mx_res,
        "spf": spf_res,
        "dmarc": dmarc_res,
        "dkim": {
            "selectors_tested": len(DKIM_SELECTORS),
            "selectors_found": active_dkim,
            "has_dkim": len(active_dkim) > 0
        },
        "ipv6": aaaa_res,
        "srv": srv_res,
        "governance": gov_res,
        "asn_sovereignty": asn_res,
        "hosting_profile": asn_res["hosting_profile"],
        "rbl_blacklist": rbl_res
    }