# modules/identity_scanner.py
import hashlib
import json
import httpx
from typing import Dict, Any

HUDSON_ROCK_DOMAIN_URL = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain"
HUDSON_ROCK_EMAIL_URL = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email"

async def scan_identity_exposure(domain: str, timeout: float = 6.0) -> Dict[str, Any]:
    """
    Módulo 1: Sentinel Identity & Infostealer Radar.
    Consulta pasivamente la telemetría OSINT de Hudson Rock Cavalier para detectar
    máquinas infectadas por malware infostealer vinculadas al dominio corporativo.
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
            response = await client.get(
                HUDSON_ROCK_DOMAIN_URL,
                params={"domain": clean_domain}
            )

            if response.status_code == 200:
                data = response.json()
                
                # Extracción de contadores de máquinas comprometidas
                employees = int(data.get("employees", 0) or 0)
                users = int(data.get("users", 0) or 0)
                third_parties = int(data.get("third_parties", 0) or 0)
                total = employees + users

                # Extracción de familias de malware stealer (Lumma, Redline, etc.)
                stealers_raw = data.get("stealerFamilies", {})
                families = []
                if isinstance(stealers_raw, dict):
                    families = [k for k in stealers_raw.keys() if k.lower() != "total"]
                elif isinstance(stealers_raw, list):
                    families = stealers_raw

                # Fecha de última infección registrada
                last_date = data.get("last_employee_compromised") or data.get("last_user_compromised")

                # Estadísticas de sistemas operativos afectados (ej. Windows 10/11)
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

                # Evaluación determinista de severidad
                if employees > 0:
                    result["status"] = "critical"
                    result["anci_art8_compliance"] = False
                elif users > 0 or third_parties > 0:
                    result["status"] = "warning"
                else:
                    result["status"] = "clean"

            elif response.status_code == 404:
                # 404 en Cavalier significa 0 registros de infección conocidos
                result["status"] = "clean"
            else:
                result["status"] = "error"
                result["error"] = f"HTTP {response.status_code}"

    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)

    # Huella determinista (SHA-256) para el Motor de Deriva (Drift Engine)
    drift_payload = {
        "employees": result["compromised_employees"],
        "users": result["compromised_users"],
        "third_parties": result["third_parties"],
        "last_date": result["last_infection_date"],
        "families": sorted(result["stealer_families"])
    }
    result["drift_fingerprint"] = hashlib.sha256(
        json.dumps(drift_payload, sort_keys=True).encode("utf-8")
    ).hexdigest()

    return result