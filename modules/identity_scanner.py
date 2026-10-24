# modules/identity_scanner.py
import asyncio
import hashlib
import json
import httpx
from typing import Dict, Any

HUDSON_ROCK_DOMAIN_URL = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain"
HUDSON_ROCK_EMAIL_URL = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email"


async def probe_entra_id_federation(domain: str, client: httpx.AsyncClient) -> Dict[str, Any]:
    """
    Reconocimiento pasivo no intrusivo de identidad federada corporativa (Microsoft Entra ID / Azure AD).
    Extrae Tenant ID, tipo de autenticación (Managed vs Federated) y región de nube sin credenciales.
    """
    sso_info = {
        "uses_entra_id": False,
        "tenant_id": None,
        "tenant_region": None,
        "name_space_type": None,  # Managed (Cloud-only) | Federated (ADFS/Okta/Ping) | Unknown
        "federation_brand_name": None,
        "cloud_instance": None
    }

    # 1. Consultar OpenID Connect Discovery público del dominio
    oidc_url = f"https://login.microsoftonline.com/{domain}/v2.0/.well-known/openid-configuration"
    realm_url = f"https://login.microsoftonline.com/getuserrealm.srf?login=admin@{domain}&json=1"

    try:
        oidc_resp, realm_resp = await asyncio.gather(
            client.get(oidc_url, timeout=3.0),
            client.get(realm_url, timeout=3.0),
            return_exceptions=True
        )

        if isinstance(oidc_resp, httpx.Response) and oidc_resp.status_code == 200:
            data = oidc_resp.json()
            issuer = data.get("issuer", "")
            # Formato típico: https://login.microsoftonline.com/{tenant_id}/v2.0
            parts = [p for p in issuer.split("/") if p]
            for p in parts:
                if len(p) == 36 and p.count("-") == 4:
                    sso_info["uses_entra_id"] = True
                    sso_info["tenant_id"] = p
                    break
            sso_info["tenant_region"] = data.get("tenant_region_scope")
            sso_info["cloud_instance"] = data.get("cloud_instance_name")

        if isinstance(realm_resp, httpx.Response) and realm_resp.status_code == 200:
            r_data = realm_resp.json()
            ns_type = r_data.get("NameSpaceType")
            if ns_type and ns_type != "Unknown":
                sso_info["uses_entra_id"] = True
                sso_info["name_space_type"] = ns_type
                sso_info["federation_brand_name"] = r_data.get("FederationBrandName")
    except Exception:
        pass

    return sso_info


async def scan_identity_exposure(domain: str, timeout: float = 6.0) -> Dict[str, Any]:
    """
    Módulo 1: Sentinel Identity, Infostealer Radar & Entra ID Tenant Recon.
    Consulta pasivamente Hudson Rock Cavalier y el plano de federación SSO corporativo.
    """
    clean_domain = domain.strip().lower()
    
    result: Dict[str, Any] = {
        "module": "identity_infostealer_radar",
        "domain": clean_domain,
        "status": "clean",  # clean | warning | critical | error
        "compromised_employees": 0,
        "compromised_users": 0,
        "third_parties": 0,
        "total_compromised": 0,
        "last_infection_date": None,
        "stealer_families": [],
        "affected_systems_stats": {},
        "corporate_sso_federation": {},
        "drift_fingerprint": "",
        "anci_art8_compliance": True,
        "error": None
    }

    headers = {
        "User-Agent": "SentinelRecon-EASM/2.0 (Passive-Security-Audit)",
        "Accept": "application/json"
    }

    try:
        async with httpx.AsyncClient(timeout=timeout, headers=headers) as client:
            hr_task = client.get(HUDSON_ROCK_DOMAIN_URL, params={"domain": clean_domain})
            sso_task = probe_entra_id_federation(clean_domain, client)

            response, sso_data = await asyncio.gather(hr_task, sso_task, return_exceptions=True)

            if isinstance(sso_data, dict):
                result["corporate_sso_federation"] = sso_data

            if isinstance(response, httpx.Response):
                if response.status_code == 200:
                    data = response.json()
                    
                    employees = int(data.get("employees", 0) or 0)
                    users = int(data.get("users", 0) or 0)
                    third_parties = int(data.get("third_parties", 0) or 0)
                    total = employees + users

                    stealers_raw = data.get("stealerFamilies", {})
                    families = []
                    if isinstance(stealers_raw, dict):
                        families = [k for k in stealers_raw.keys() if k.lower() != "total"]
                    elif isinstance(stealers_raw, list):
                        families = stealers_raw

                    last_date = data.get("last_employee_compromised") or data.get("last_user_compromised")

                    stats_os = {}
                    data_stats = data.get("stats", {})
                    if isinstance(data_stats, dict):
                        stats_os = {
                            "employees_urls": data_stats.get("employees_urls", [])[:5],
                            "clients_urls": data_stats.get("clients_urls", [])[:5]
                        }

                    result["compromised_employees"] = employees
                    result["compromised_users"] = users
                    result["third_parties"] = third_parties
                    result["total_compromised"] = total
                    result["last_infection_date"] = last_date
                    result["stealer_families"] = families[:10]
                    result["affected_systems_stats"] = stats_os

                    if employees > 0:
                        result["status"] = "critical"
                        result["anci_art8_compliance"] = False
                    elif users > 0 or third_parties > 0:
                        result["status"] = "warning"
                    else:
                        result["status"] = "clean"

                elif response.status_code == 404:
                    result["status"] = "clean"
                else:
                    result["status"] = "error"
                    result["error"] = f"HTTP {response.status_code}"
            elif isinstance(response, Exception):
                result["status"] = "error"
                result["error"] = str(response)

    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)

    drift_payload = {
        "employees": result["compromised_employees"],
        "users": result["compromised_users"],
        "third_parties": result["third_parties"],
        "last_date": result["last_infection_date"],
        "families": sorted(result["stealer_families"]),
        "tenant_id": result.get("corporate_sso_federation", {}).get("tenant_id")
    }
    result["drift_fingerprint"] = hashlib.sha256(
        json.dumps(drift_payload, sort_keys=True).encode("utf-8")
    ).hexdigest()

    return result