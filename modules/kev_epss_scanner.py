# modules/kev_epss_scanner.py
import asyncio
import hashlib
import json
import httpx
from typing import Dict, Any, List, Optional

CISA_KEV_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
FIRST_EPSS_API_URL = "https://api.first.org/data/v1/epss"

# Mapeo determinista de vectores críticos perimetrales (Windows Server / Linux / AI Local)
# Asocia puertos y servicios expuestos en internet con CVEs emblemáticos monitoreados por CISA/FIRST
PERIMETER_PORT_RISK_MAP = {
    3389: {
        "service": "Windows Remote Desktop (RDP)",
        "os_focus": "Windows Server / Windows 10-11",
        "reference_cves": ["CVE-2019-0708", "CVE-2024-38077"],
        "risk_summary": "Exposición directa de escritorio remoto Windows a fuerza bruta y exploits pre-autenticación."
    },
    445: {
        "service": "Windows SMB (Server Message Block)",
        "os_focus": "Windows Server / Active Directory",
        "reference_cves": ["CVE-2017-0144", "CVE-2020-0796", "CVE-2024-38060"],
        "risk_summary": "Protocolo de archivos Windows expuesto a internet; vector primario de propagación de Ransomware."
    },
    135: {
        "service": "Windows MSRPC (Remote Procedure Call)",
        "os_focus": "Windows Server / Endpoint",
        "reference_cves": ["CVE-2022-26809", "CVE-2024-38074"],
        "risk_summary": "Interfaz RPC de Windows expuesta fuera de la red local; alto riesgo de ejecución remota de código."
    },
    22: {
        "service": "OpenSSH / SSH Remote Access",
        "os_focus": "Linux / Windows OpenSSH",
        "reference_cves": ["CVE-2024-6387", "CVE-2023-38408"],
        "risk_summary": "Consola administrativa SSH expuesta al perímetro público (ej. regreSSHion)."
    },
    8080: {
        "service": "HTTP Proxy / Panel Administrativo Alternativo",
        "os_focus": "Multiplataforma (Tomcat / Jenkins / Web Admin)",
        "reference_cves": ["CVE-2024-23897", "CVE-2024-38856"],
        "risk_summary": "Puerto de administración o aplicación secundaria sin blindaje TLS estricto."
    },
    11434: {
        "service": "Ollama Local LLM Server",
        "os_focus": "AI Server / Workstation",
        "reference_cves": ["CVE-2024-37032"],
        "risk_summary": "Servidor de Inteligencia Artificial (Ollama) expuesto sin autenticación a robo de modelos o RCE."
    }
}

# Caché ligero en memoria para no descargar el JSON completo de CISA en cada petición seguida
_CISA_CACHE: Dict[str, Any] = {"catalog": {}, "version": None}


async def _load_cisa_kev_catalog(timeout: float = 8.0) -> Dict[str, Dict[str, Any]]:
    """
    Descarga y mapea en memoria el catálogo oficial CISA Known Exploited Vulnerabilities (KEV).
    """
    if _CISA_CACHE["catalog"]:
        return _CISA_CACHE["catalog"]

    headers = {"User-Agent": "SentinelRecon-EASM/2.0 (CISA-KEV-Sync)"}
    try:
        async with httpx.AsyncClient(timeout=timeout, headers=headers) as client:
            resp = await client.get(CISA_KEV_FEED_URL)
            if resp.status_code == 200:
                data = resp.json()
                _CISA_CACHE["version"] = data.get("catalogVersion")
                vulns = data.get("vulnerabilities", [])
                catalog_map = {}
                for v in vulns:
                    cve_id = v.get("cveID")
                    if cve_id:
                        catalog_map[cve_id] = {
                            "vendorProject": v.get("vendorProject"),
                            "product": v.get("product"),
                            "vulnerabilityName": v.get("vulnerabilityName"),
                            "dateAdded": v.get("dateAdded"),
                            "dueDate": v.get("dueDate"),
                            "knownRansomwareCampaignUse": v.get("knownRansomwareCampaignUse", "Unknown"),
                            "requiredAction": v.get("requiredAction")
                        }
                _CISA_CACHE["catalog"] = catalog_map
                return catalog_map
    except Exception:
        pass
    return {}


async def _fetch_epss_scores(cve_list: List[str], timeout: float = 5.0) -> Dict[str, Dict[str, float]]:
    """
    Consulta por lotes la API pública de FIRST EPSS (sin API Key) para obtener
    la probabilidad matemática de explotación en los próximos 30 días.
    """
    if not cve_list:
        return {}

    unique_cves = sorted(list(set(cve_list)))
    csv_cves = ",".join(unique_cves)
    scores_map: Dict[str, Dict[str, float]] = {}

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.get(FIRST_EPSS_API_URL, params={"cve": csv_cves})
            if resp.status_code == 200:
                data = resp.json()
                for item in data.get("data", []):
                    cve_id = item.get("cve")
                    if cve_id:
                        scores_map[cve_id] = {
                            "epss_probability": round(float(item.get("epss", 0.0)), 4),
                            "epss_percentage": round(float(item.get("epss", 0.0)) * 100, 2),
                            "percentile": round(float(item.get("percentile", 0.0)) * 100, 2)
                        }
    except Exception:
        pass

    return scores_map


async def scan_kev_epss_prioritization(
    domain: str,
    open_ports_data: Optional[Dict[str, Any]] = None,
    web_data: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Módulo 4: Sentinel KEV-EPSS Prioritizer.
    Cruza los puertos y servicios expuestos en el perímetro con CISA KEV (explotación activa)
    y FIRST EPSS (predicción a 30 días) para separar emergencias P0 del ruido teórico.
    """
    clean_domain = domain.strip().lower()

    # Extraer lista de números de puerto abiertos
    open_ports: List[int] = []
    if open_ports_data and "open_ports" in open_ports_data:
        for p in open_ports_data["open_ports"]:
            if isinstance(p, dict) and "port" in p:
                open_ports.append(int(p["port"]))
            elif isinstance(p, int):
                open_ports.append(p)

    # Identificar CVEs candidatos según la superficie expuesta (excluyendo 80 y 443 estándar)
    candidate_cves: List[str] = []
    exposed_Risk_surfaces: List[Dict[str, Any]] = []

    for port in open_ports:
        if port in PERIMETER_PORT_RISK_MAP:
            mapping = PERIMETER_PORT_RISK_MAP[port]
            candidate_cves.extend(mapping["reference_cves"])
            exposed_Risk_surfaces.append({
                "port": port,
                "service": mapping["service"],
                "os_focus": mapping["os_focus"],
                "risk_summary": mapping["risk_summary"],
                "evaluated_cves": mapping["reference_cves"]
            })

    # Descargar en paralelo el catálogo CISA KEV y los puntajes FIRST EPSS
    cisa_catalog, epss_scores = await asyncio.gather(
        _load_cisa_kev_catalog(),
        _fetch_epss_scores(candidate_cves)
    )

    prioritized_findings: List[Dict[str, Any]] = []
    same_day_p0_count = 0
    ransomware_vectors_count = 0

    for surface in exposed_Risk_surfaces:
        for cve_id in surface["evaluated_cves"]:
            in_kev = cve_id in cisa_catalog
            kev_info = cisa_catalog.get(cve_id, {})
            epss_info = epss_scores.get(cve_id, {
                "epss_probability": 0.0,
                "epss_percentage": 0.0,
                "percentile": 0.0
            })

            is_ransomware = kev_info.get("knownRansomwareCampaignUse") == "Known"
            epss_prob = epss_info["epss_probability"]

            # Triaje Determinista Pre-LLM (P0 Same-Day Incident vs P1/P2)
            if in_kev or epss_prob >= 0.50:
                triage_decision = "P0_SAME_DAY_INCIDENT"
                same_day_p0_count += 1
            elif epss_prob >= 0.15:
                triage_decision = "P1_URGENT_72H"
            else:
                triage_decision = "P2_SCHEDULED_PATCH"

            if is_ransomware:
                ransomware_vectors_count += 1

            prioritized_findings.append({
                "cve_id": cve_id,
                "Trigger_port": surface["port"],
                "service": surface["service"],
                "os_focus": surface["os_focus"],
                "in_cisa_kev": in_kev,
                "known_ransomware_use": is_ransomware,
                "cisa_vulnerability_name": kev_info.get("vulnerabilityName", "Exposición de Servicio Crítico Perimetral"),
                "cisa_date_added": kev_info.get("dateAdded"),
                "epss_30d_probability_pct": epss_info["epss_percentage"],
                "epss_percentile": epss_info["percentile"],
                "deterministic_triage": triage_decision,
                "remediation_sla": "Inmediato (< 24h)" if triage_decision == "P0_SAME_DAY_INCIDENT" else "72 horas"
            })

    status = "clean"
    if same_day_p0_count > 0:
        status = "critical"
    elif len(exposed_Risk_surfaces) > 0:
        status = "warning"

    drift_payload = {
        "ports": sorted(open_ports),
        "p0_count": same_day_p0_count,
        "findings": [
            {"cve": f["cve_id"], "kev": f["in_cisa_kev"], "triage": f["deterministic_triage"]}
            for f in prioritized_findings
        ]
    }
    drift_hash = hashlib.sha256(
        json.dumps(drift_payload, sort_keys=True).encode("utf-8")
    ).hexdigest()

    return {
        "module": "kev_epss_prioritizer",
        "domain": clean_domain,
        "status": status,
        "cisa_catalog_loaded": len(cisa_catalog) > 0,
        "cisa_total_kev_tracked": len(cisa_catalog),
        "critical_ports_exposed_count": len(exposed_Risk_surfaces),
        "same_day_p0_incidents_count": same_day_p0_count,
        "ransomware_active_vectors_count": ransomware_vectors_count,
        "prioritized_cve_matrix": prioritized_findings,
        "anci_art8_patch_sla_ready": True,
        "drift_fingerprint": drift_hash
    }