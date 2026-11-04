# modules/identity_scanner.py
import os
import asyncio
import hashlib
import json
import httpx
from typing import Dict, Any, List

HUDSON_ROCK_DOMAIN_URL = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain"
HUDSON_ROCK_EMAIL_URL = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email"
PROXYNOVA_COMB_URL = "https://api.proxynova.com/comb"
LEAKRADAR_DOMAIN_URL = "https://api.leakradar.io/v1/search/domain"
GITHUB_CODE_SEARCH_URL = "https://api.github.com/search/code"


def _mask_secret(secret: str) -> str:
    """Enmascara contraseñas filtradas para evidencia ejecutiva segura (Ley 21.719)."""
    s = (secret or "").strip()
    if len(s) <= 3:
        return "***"
    if len(s) <= 6:
        return f"{s[:1]}***{s[-1:]}"
    return f"{s[:2]}****{s[-2:]}"


async def probe_entra_id_federation(domain: str, client: httpx.AsyncClient) -> Dict[str, Any]:
    """
    Reconocimiento pasivo no intrusivo de identidad federada corporativa (Microsoft Entra ID / Azure AD).
    Extrae Tenant ID, tipo de autenticación (Managed vs Federated) y región de nube sin credenciales.
    """
    sso_info = {
        "uses_entra_id": False,
        "tenant_id": None,
        "tenant_region": None,
        "name_space_type": None,
        "federation_brand_name": None,
        "cloud_instance": None
    }

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


async def probe_combolists_and_breaches(domain: str, client: httpx.AsyncClient) -> Dict[str, Any]:
    """
    Sonda de Combolists (3.2B+ credenciales en texto plano) y Brechas Históricas de Terceros.
    Consulta ProxyNova COMB en vivo y opcionalmente LeakRadar API si existe LEAKRADAR_API_KEY.
    """
    combo_data: Dict[str, Any] = {
        "combolist_hits_count": 0,
        "unique_leaked_emails_count": 0,
        "leaked_samples_masked": [],
        "historical_breach_sources": [],
        "leakradar_active": False
    }

    unique_emails = set()
    masked_samples: List[str] = []

    try:
        comb_resp = await client.get(
            PROXYNOVA_COMB_URL,
            params={"query": f"@{domain}", "start": 0, "limit": 100},
            timeout=4.0
        )
        if comb_resp.status_code == 200:
            c_json = comb_resp.json()
            lines = c_json.get("lines", []) or []
            for line in lines:
                if not isinstance(line, str) or ":" not in line:
                    continue
                email_part, pwd_part = line.split(":", 1)
                email_clean = email_part.strip().lower()
                if email_clean.endswith(f"@{domain}"):
                    if email_clean not in unique_emails:
                        unique_emails.add(email_clean)
                        if len(masked_samples) < 8:
                            masked_samples.append(f"{email_clean} (Clave filtrada: {_mask_secret(pwd_part)})")

            combo_data["combolist_hits_count"] = len(lines) if unique_emails else 0
            combo_data["unique_leaked_emails_count"] = len(unique_emails)
            combo_data["leaked_samples_masked"] = masked_samples
            if unique_emails:
                combo_data["historical_breach_sources"].append("COMB (Compilation of Many Breaches - 3.2B Combolist)")
    except Exception:
        pass

    leakradar_key = os.getenv("LEAKRADAR_API_KEY", "").strip()
    if leakradar_key:
        try:
            lr_resp = await client.get(
                f"{LEAKRADAR_DOMAIN_URL}/{domain}",
                headers={"Authorization": f"Bearer {leakradar_key}", "X-API-Key": leakradar_key},
                timeout=4.0
            )
            if lr_resp.status_code == 200:
                lr_json = lr_resp.json()
                combo_data["leakradar_active"] = True
                lr_total = int(lr_json.get("total", 0) or lr_json.get("count", 0) or 0)
                if lr_total > combo_data["unique_leaked_emails_count"]:
                    combo_data["unique_leaked_emails_count"] = lr_total
                if lr_total > 0:
                    combo_data["historical_breach_sources"].append("LeakRadar Dark Web Combolist Feed")
        except Exception:
            pass

    return combo_data


async def probe_github_public_leaks(domain: str, client: httpx.AsyncClient) -> Dict[str, Any]:
    """
    Cazador de Fugitivos en GitHub Público (Secret & Code Leak Radar).
    Busca si programadores o terceros subieron archivos de configuración o código mencionando el dominio.
    """
    gh_data: Dict[str, Any] = {
        "github_leaks_count": 0,
        "exposed_repositories": []
    }

    gh_headers = {"Accept": "application/vnd.github.v3+json"}
    gh_token = os.getenv("GITHUB_TOKEN", "").strip()
    if gh_token:
        gh_headers["Authorization"] = f"Bearer {gh_token}"

    try:
        resp = await client.get(
            GITHUB_CODE_SEARCH_URL,
            params={"q": f'"{domain}"', "per_page": 5},
            headers=gh_headers,
            timeout=3.5
        )
        if resp.status_code == 200:
            data = resp.json()
            total_count = int(data.get("total_count", 0) or 0)
            items = data.get("items", []) or []
            repos = []
            for item in items[:5]:
                repo_name = item.get("repository", {}).get("full_name", "")
                file_path = item.get("path", "")
                if repo_name:
                    repos.append(f"{repo_name} ({file_path})")
            gh_data["github_leaks_count"] = total_count
            gh_data["exposed_repositories"] = repos
    except Exception:
        pass

    return gh_data


async def scan_identity_exposure(domain: str, timeout: float = 6.5) -> Dict[str, Any]:
    """
    Módulo 1: Sentinel Identity, Infostealer Radar, Combolist Scanner, GitHub Leak Radar & Entra ID Recon.
    """
    clean_domain = domain.strip().lower()

    result: Dict[str, Any] = {
        "module": "identity_infostealer_radar",
        "domain": clean_domain,
        "status": "clean",
        "compromised_employees": 0,
        "compromised_users": 0,
        "third_parties": 0,
        "total_compromised": 0,
        "last_infection_date": None,
        "stealer_families": [],
        "affected_systems_stats": {},
        "combolist_intelligence": {},
        "github_code_leaks": {},
        "corporate_sso_federation": {},
        "drift_fingerprint": "",
        "anci_art8_compliance": True,
        "error": None
    }

    headers = {
        "User-Agent": "SentinelRecon-EASM/2.2 (Passive-Security-Audit)",
        "Accept": "application/json"
    }

    try:
        async with httpx.AsyncClient(timeout=timeout, headers=headers) as client:
            hr_task = client.get(HUDSON_ROCK_DOMAIN_URL, params={"domain": clean_domain})
            sso_task = probe_entra_id_federation(clean_domain, client)
            combo_task = probe_combolists_and_breaches(clean_domain, client)
            gh_task = probe_github_public_leaks(clean_domain, client)

            response, sso_data, combo_data, gh_data = await asyncio.gather(
                hr_task, sso_task, combo_task, gh_task, return_exceptions=True
            )

            if isinstance(sso_data, dict):
                result["corporate_sso_federation"] = sso_data

            combo_unique_count = 0
            if isinstance(combo_data, dict):
                result["combolist_intelligence"] = combo_data
                combo_unique_count = int(combo_data.get("unique_leaked_emails_count", 0) or 0)

            if isinstance(gh_data, dict):
                result["github_code_leaks"] = gh_data

            if isinstance(response, httpx.Response):
                if response.status_code == 200:
                    data = response.json()

                    employees = int(data.get("employees", 0) or 0)
                    users = int(data.get("users", 0) or 0)
                    third_parties = int(data.get("third_parties", 0) or 0)

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

                    effective_employees = max(employees, combo_unique_count)
                    total = effective_employees + users

                    if combo_unique_count > 0 and "Combolist Credential Dump" not in families:
                        families.append("Combolist Credential Dump")

                    result["compromised_employees"] = effective_employees
                    result["compromised_users"] = users
                    result["third_parties"] = third_parties
                    result["total_compromised"] = total
                    result["last_infection_date"] = last_date
                    result["stealer_families"] = families[:10]
                    result["affected_systems_stats"] = stats_os

                    if effective_employees > 0:
                        result["status"] = "critical"
                        result["anci_art8_compliance"] = False
                    elif users > 0 or third_parties > 0:
                        result["status"] = "warning"
                    else:
                        result["status"] = "clean"

                elif response.status_code == 404:
                    if combo_unique_count > 0:
                        result["compromised_employees"] = combo_unique_count
                        result["total_compromised"] = combo_unique_count
                        result["stealer_families"] = ["Combolist Credential Dump"]
                        result["status"] = "critical"
                        result["anci_art8_compliance"] = False
                    else:
                        result["status"] = "clean"
                else:
                    result["status"] = "error"
                    result["error"] = f"HTTP {response.status_code}"
            elif isinstance(response, Exception):
                if combo_unique_count > 0:
                    result["compromised_employees"] = combo_unique_count
                    result["total_compromised"] = combo_unique_count
                    result["status"] = "critical"
                else:
                    result["status"] = "error"
                    result["error"] = str(response)

    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)

    drift_payload = {
        "employees": result["compromised_employees"],
        "users": result["compromised_users"],
        "third_parties": result["third_parties"],
        "combolist_emails": result.get("combolist_intelligence", {}).get("unique_leaked_emails_count", 0),
        "github_leaks": result.get("github_code_leaks", {}).get("github_leaks_count", 0),
        "last_date": result["last_infection_date"],
        "families": sorted(result["stealer_families"]),
        "tenant_id": result.get("corporate_sso_federation", {}).get("tenant_id")
    }
    result["drift_fingerprint"] = hashlib.sha256(
        json.dumps(drift_payload, sort_keys=True).encode("utf-8")
    ).hexdigest()

    return result