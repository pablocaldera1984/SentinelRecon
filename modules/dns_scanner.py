# modules/dns_scanner.py
import asyncio
import socket
import httpx
import dns.resolver
import dns.asyncresolver
from typing import Dict, Any, List
from config import DKIM_SELECTORS, DNS_TIMEOUT


async def check_spf(domain: str, resolver: dns.asyncresolver.Resolver) -> Dict[str, Any]:
    result = {
        "exists": False,
        "status": "NOT_CONFIGURED",
        "raw_record": None,
        "is_strict": False,
        "dns_lookup_count": 0,
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

    # 1. CAA
    try:
        caa_ans = await resolver.resolve(domain, 'CAA')
        gov["caa_records"] = [r.to_text() for r in caa_ans]
        gov["caa_configured"] = len(gov["caa_records"]) > 0
    except Exception:
        pass

    # 2. MTA-STS (_mta-sts.domain)
    try:
        sts_ans = await resolver.resolve(f"_mta-sts.{domain}", 'TXT')
        for r in sts_ans:
            txt = "".join([p.decode('utf-8', errors='ignore') for p in r.strings])
            if "v=STSv1" in txt:
                gov["mta_sts_configured"] = True
    except Exception:
        pass

    # 3. SMTP TLS Reporting (_smtp._tls.domain)
    try:
        tlsrpt_ans = await resolver.resolve(f"_smtp._tls.{domain}", 'TXT')
        for r in tlsrpt_ans:
            txt = "".join([p.decode('utf-8', errors='ignore') for p in r.strings])
            if "v=TLSRPTv1" in txt:
                gov["tls_rpt_configured"] = True
    except Exception:
        pass

    # 4. BIMI (default._bimi.domain)
    try:
        bimi_ans = await resolver.resolve(f"default._bimi.{domain}", 'TXT')
        for r in bimi_ans:
            txt = "".join([p.decode('utf-8', errors='ignore') for p in r.strings])
            if "v=BIMI1" in txt:
                gov["bimi_configured"] = True
    except Exception:
        pass

    # 5. DNSSEC (DNSKEY / DS)
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
                # Spamhaus devuelve 127.255.255.x cuando se consulta desde un resolver público abierto; lo filtramos para evitar falsos positivos
                if resp_ip.startswith("127.0.0."):
                    rbl_result["blacklists_detected"].append(label)
                    break
        except Exception:
            pass

    await asyncio.gather(*(query_rbl(z, lbl) for z, lbl in rbl_providers))
    rbl_result["listed_count"] = len(rbl_result["blacklists_detected"])
    rbl_result["is_blacklisted"] = rbl_result["listed_count"] > 0
    return rbl_result


async def check_asn_and_data_sovereignty(domain: str, resolver: dns.asyncresolver.Resolver) -> Dict[str, Any]:
    """Resuelve IP primaria y obtiene ASN, Proveedor BGP y Jurisdicción de Datos (Ley 21.719)."""
    info = {
        "primary_ip": None,
        "asn": None,
        "isp_org": None,
        "country": None,
        "country_code": None,
        "hosted_in_chile": False,
        "data_sovereignty_status": "DESCONOCIDO"
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

    return info


async def scan_dns_email(domain: str) -> Dict[str, Any]:
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = DNS_TIMEOUT
    resolver.lifetime = DNS_TIMEOUT
    
    # Lanzar todas las sondas concurrentemente
    spf_task = check_spf(domain, resolver)
    dmarc_task = check_dmarc(domain, resolver)
    aaaa_task = check_aaaa(domain, resolver)
    ns_task = check_nameservers(domain, resolver)
    srv_task = check_srv_records(domain, resolver)
    gov_task = check_advanced_dns_governance(domain, resolver)
    asn_task = check_asn_and_data_sovereignty(domain, resolver)
    dkim_tasks = [check_dkim_selector(domain, sel, resolver) for sel in DKIM_SELECTORS]
    
    spf_res, dmarc_res, aaaa_res, ns_res, srv_res, gov_res, asn_res, *dkim_results = await asyncio.gather(
        spf_task, dmarc_task, aaaa_task, ns_task, srv_task, gov_task, asn_task, *dkim_tasks
    )
    
    # Consultar listas negras RBL sobre la IP primaria resuelta
    rbl_res = await check_rbl_blacklists(asn_res.get("primary_ip"), resolver)
    
    active_dkim = [res for res in dkim_results if res.get("found")]
    
    return {
        "domain": domain,
        "nameservers": ns_res,
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