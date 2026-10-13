import asyncio
import dns.resolver
import dns.asyncresolver
from typing import Dict, Any, List
from config import DKIM_SELECTORS, DNS_TIMEOUT


async def check_spf(domain: str, resolver: dns.asyncresolver.Resolver) -> Dict[str, Any]:
    result = {
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


async def scan_dns_email(domain: str) -> Dict[str, Any]:
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = DNS_TIMEOUT
    resolver.lifetime = DNS_TIMEOUT
    
    spf_task = check_spf(domain, resolver)
    dmarc_task = check_dmarc(domain, resolver)
    dkim_tasks = [check_dkim_selector(domain, sel, resolver) for sel in DKIM_SELECTORS]
    
    spf_res, dmarc_res, *dkim_results = await asyncio.gather(
        spf_task, dmarc_task, *dkim_tasks
    )
    
    active_dkim = [res for res in dkim_results if res.get("found")]
    
    return {
        "domain": domain,
        "spf": spf_res,
        "dmarc": dmarc_res,
        "dkim": {
            "selectors_tested": len(DKIM_SELECTORS),
            "selectors_found": active_dkim,
            "has_dkim": len(active_dkim) > 0
        }
    }
