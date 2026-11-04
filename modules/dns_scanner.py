# modules/dns_scanner.py
import asyncio
import socket
import ssl
import re
import httpx
import dns.resolver
import dns.asyncresolver
import dns.reversename
from typing import Dict, Any, List
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from config import DKIM_SELECTORS, DNS_TIMEOUT


async def check_spf(domain: str, resolver: dns.asyncresolver.Resolver) -> Dict[str, Any]:
    result = {
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

                # Extraer qué proveedores o IPs externas autorizó el informático en el SPF
                auth_senders = []
                for m in mechanisms:
                    if m.startswith(("include:", "ip4:", "a:", "mx:", "redirect=")):
                        auth_senders.append(m)
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
    result = {
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
    """Consulta explícita de registros IPv6 (AAAA)."""
    ipv6_list = []
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
    """Obtiene los NameServers (NS) del dominio para identificar al proveedor de Hosting comercial."""
    ns_list = []
    try:
        answers = await resolver.resolve(domain, 'NS')
        ns_list = [str(r.target).rstrip('.').lower() for r in answers]
    except Exception:
        pass
    return ns_list


async def check_mx_architecture(domain: str, resolver: dns.asyncresolver.Resolver) -> Dict[str, Any]:
    """Desenmascara quién administra realmente el correo electrónico de la empresa (MX)."""
    mx_info = {
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
    """Consulta un registro SRV individual."""
    target = f"{prefix}.{domain}"
    found = []
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
    """Sondeo de registros de servicio SRV clave (Active Directory, Exchange/M365, Telefonía SIP)."""
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
    """Audita CAA (Control de Emisión SSL), MTA-STS, TLS-RPT, BIMI y firma DNSSEC."""
    gov = {
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


async def check_rbl_blacklists(ip: str, resolver: dns.asyncresolver.Resolver) -> Dict[str, Any]:
    """
    Verifica si la IP principal del dominio o servidor de correo figura bloqueada
    en las principales listas negras internacionales Anti-Spam (DNSBL / RBL).
    """
    rbl_result = {
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
    """
    Se conecta por SSL directamente a la IP (sin SNI del cliente) en puertos administrativos
    (2083 cPanel, 2087 WHM, 993 IMAPS, 443) para obligar al servidor a revelar el certificado
    maestro con el verdadero nombre del proveedor de hosting o máquina del informático.
    """
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
                # Buscar Common Name (CN)
                for attr in cert.subject:
                    if attr.oid == x509.NameOID.COMMON_NAME:
                        cn = str(attr.value).strip().lower()
                        if "." in cn and not cn.startswith("*."):
                            return cn
                # O buscar primer SAN DNSName
                san_ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                sans = san_ext.value.get_values_for_type(x509.DNSName)
                for s in sans:
                    s_clean = s.strip().lower().lstrip("*.")
                    if "." in s_clean:
                        return s_clean
    except Exception:
        pass
    return ""


async def _grab_smtp_banner_hostname(ip: str) -> str:
    """Lee el saludo inicial del puerto 25 o 587 para descubrir el hostname interno real del servidor."""
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
            # Formato típico: "220 srv1.hosting-oculto.cl ESMTP Exim..."
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
    """
    Motor de Desenmascaramiento Forense de Servidores Privados y Co-Hosting:
    Descubre el verdadero nombre de la máquina (PTR, Cert cPanel/WHM, Banner SMTP),
    qué otros dominios comparten esa misma IP (Vecinos de Co-Hosting) y si es un servidor artesanal/in-house.
    """
    unmask = {
        "ptr_reverse_dns": None,
        "master_server_hostname": None,
        "unmasked_provider_clue": None,
        "uses_dynamic_dns_trick": False,
        "dynamic_dns_provider": None,
        "is_inhouse_or_artisan_server": False,
        "cohosted_neighbors_count": 0,
        "cohosted_domains_sample": [],
        "forensic_summary_executive": None
    }
    if not ip:
        return unmask

    # 1. Detectar si el informático usó el truco de DNS dinámico (ddns.net, no-ip, dyndns)
    ns_joined = " ".join(ns_list).lower()
    if any(k in ns_joined for k in ["ddns.net", "no-ip", "dyndns", "afraid.org", "duckdns"]):
        unmask["uses_dynamic_dns_trick"] = True
        unmask["dynamic_dns_provider"] = "No-IP / DDNS.net (DNS Dinámico)"

    # 2. Consultar Reverse DNS (PTR) de la IP
    try:
        rev_name = dns.reversename.from_address(ip)
        ptr_ans = await resolver.resolve(rev_name, "PTR")
        for r in ptr_ans:
            unmask["ptr_reverse_dns"] = str(r.target).rstrip(".").lower()
            break
    except Exception:
        pass

    # 3. Interrogar en paralelo certificados administrativos (2083 cPanel, 2087 WHM, 993 IMAPS) y Banner SMTP
    loop = asyncio.get_running_loop()
    cert_2083_task = loop.run_in_executor(None, _extract_cert_hostname_by_ip, ip, 2083)
    cert_993_task = loop.run_in_executor(None, _extract_cert_hostname_by_ip, ip, 993)
    smtp_task = _grab_smtp_banner_hostname(ip)

    # 4. Consultar Vecinos de Co-Hosting (Reverse IP Lookup en HackerTarget + Shodan InternetDB hostnames)
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
                            # Extraer dominio raíz o subdominio relevante que no sea del mismo cliente
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

    # Determinar el Hostname Maestro de la máquina
    candidates = [c for c in [c2083, smtp_host, c993, unmask["ptr_reverse_dns"]] if c]
    non_client_candidates = [c for c in candidates if domain not in c]
    master_host = non_client_candidates[0] if non_client_candidates else (candidates[0] if candidates else None)
    unmask["master_server_hostname"] = master_host

    # Filtrar vecinos para mostrar dominios raíz limpios de otras empresas alojadas en el mismo servidor
    clean_neighbor_roots = []
    for n in neighbors_list:
        root_n = re.sub(r'^(?:www|mail|cpanel|webmail|autodiscover|cpcalendars|cpcontacts|ftp)\.', '', n)
        if root_n != domain and root_n not in clean_neighbor_roots:
            clean_neighbor_roots.append(root_n)

    unmask["cohosted_neighbors_count"] = len(clean_neighbor_roots)
    unmask["cohosted_domains_sample"] = clean_neighbor_roots[:6]

    # Evaluar si es un servidor artesanal / in-house sobre enlace de telecomunicaciones (Entel, GTD, Movistar, VTR)
    isp_low = (isp_org or "").lower()
    if any(telco in isp_low for telco in ["entel", "gtd", "telsur", "movistar", "telefonica", "vtr", "claro", "mundo pacifico"]):
        if unmask["uses_dynamic_dns_trick"] or (unmask["ptr_reverse_dns"] and any(x in unmask["ptr_reverse_dns"] for x in ["clientes", "static", "dinamico", "entel", "gtd"])):
            unmask["is_inhouse_or_artisan_server"] = True

    # Construir resumen forense ejecutivo para dejar con la boca abierta al gerente y al informático
    resumen_partes = []
    if unmask["uses_dynamic_dns_trick"]:
        resumen_partes.append(
            f"Se detectó el uso de un servicio de DNS Dinámico ({unmask['dynamic_dns_provider']}) para redirigir el dominio hacia una IP de {isp_org}, práctica típica de servidores administrados de forma casera o independiente."
        )
    if master_host:
        resumen_partes.append(f"Identidad interna de la máquina (PTR/SSL): '{master_host}'.")
    if clean_neighbor_roots:
        resumen_partes.append(
            f"Este servidor es compartido con otros {len(clean_neighbor_roots)} dominios externos (ej: {', '.join(clean_neighbor_roots[:4])})."
        )
    unmask["forensic_summary_executive"] = " ".join(resumen_partes) if resumen_partes else None

    return unmask


async def check_asn_and_data_sovereignty(
    domain: str,
    ns_list: List[str],
    resolver: dns.asyncresolver.Resolver
) -> Dict[str, Any]:
    """Resuelve IP primaria, obtiene ASN, Jurisdicción (Ley 21.719) y ejecuta el Desenmascarador Forense."""
    info = {
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

        # Ejecutar el desenmascarador forense sobre la IP descubierta
        info["forensic_unmasking"] = await unmask_hidden_server_and_neighbors(
            info["primary_ip"], domain, ns_list, info["isp_org"] or "", resolver
        )

    return info


async def scan_dns_email(domain: str) -> Dict[str, Any]:
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = DNS_TIMEOUT
    resolver.lifetime = DNS_TIMEOUT

    # Primero obtenemos los NameServers para pasárselos también al desenmascarador forense
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
        "rbl_blacklist": rbl_res
    }