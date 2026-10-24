# modules/cloud_leak_scanner.py
import asyncio
import hashlib
import json
import re
import httpx
from typing import Dict, Any, List

BUCKET_SUFFIXES = [
    "", "-backup", "-backups", "-dev", "-prod", "-staging",
    "-public", "-files", "-data", "-assets", "-media", "-docs",
    "-clientes", "-facturas", "-ai"
]

SENSITIVE_EXTENSIONS = (".sql", ".bak", ".json", ".env", ".xlsx", ".csv", ".pdf", ".zip", ".key", ".pem")


def _extract_brand_keyword(domain: str) -> str:
    clean = domain.strip().lower()
    parts = clean.split(".")
    return parts[0] if parts else clean


async def _probe_single_cloud_endpoint(
    provider: str,
    bucket_name: str,
    url: str,
    client: httpx.AsyncClient,
    sem: asyncio.Semaphore
) -> Dict[str, Any]:
    """
    Verifica de forma no invasiva contenedores AWS S3, GCP Storage, Azure Blob y Firebase Realtime DB.
    """
    async with sem:
        try:
            resp = await client.get(url)
            status_code = resp.status_code
            body_preview = resp.text[:4000] if status_code == 200 else ""

            # Caso Especial: Firebase Realtime Database abierta (.json?shallow=true retorna JSON distinto de null)
            if provider == "Google Firebase Realtime DB":
                if status_code == 200 and body_preview.strip() not in ["null", "", "{}"]:
                    return {
                        "provider": provider,
                        "bucket_name": bucket_name,
                        "endpoint_url": url.split("?")[0],
                        "access_state": "PUBLIC_OPEN_LISTABLE",
                        "risk_level": "critical",
                        "exposed_files_sample": ["Root JSON Nodes Exposed"],
                        "sensitive_files_detected": ["realtime_db_root.json"],
                        "remediation_cli": f"Configurar Firebase Security Rules (.read: false) en '{bucket_name}'"
                    }
                elif status_code in [401, 403]:
                    return {
                        "provider": provider,
                        "bucket_name": bucket_name,
                        "endpoint_url": url.split("?")[0],
                        "access_state": "PROTECTED_PRIVATE",
                        "risk_level": "info",
                        "exposed_files_sample": [],
                        "sensitive_files_detected": [],
                        "remediation_cli": None
                    }
                return {}

            # Caso 1: Bucket Público y Listable (HTTP 200 con ListBucketResult XML) -> CRÍTICO
            if status_code == 200 and ("<ListBucketResult" in body_preview or "<EnumerationResults" in body_preview):
                keys = re.findall(r"<Key>([^<]+)</Key>", body_preview)
                if not keys:
                    keys = re.findall(r"<Name>([^<]+)</Name>", body_preview)

                critical_files = [k for k in keys if k.lower().endswith(SENSITIVE_EXTENSIONS)]

                return {
                    "provider": provider,
                    "bucket_name": bucket_name,
                    "endpoint_url": url,
                    "access_state": "PUBLIC_OPEN_LISTABLE",
                    "risk_level": "critical",
                    "exposed_files_sample": keys[:10],
                    "sensitive_files_detected": critical_files[:10],
                    "remediation_cli": f"Bloquear ACL pública (BlockPublicAcls=True) en {provider} para '{bucket_name}'"
                }

            # Caso 2: Bucket Existe pero está Protegido (HTTP 403 AccessDenied)
            elif status_code == 403:
                return {
                    "provider": provider,
                    "bucket_name": bucket_name,
                    "endpoint_url": url,
                    "access_state": "PROTECTED_PRIVATE",
                    "risk_level": "info",
                    "exposed_files_sample": [],
                    "sensitive_files_detected": [],
                    "remediation_cli": None
                }

        except Exception:
            pass

        return {}


async def scan_cloud_storage_leaks(domain: str, timeout: float = 3.5) -> Dict[str, Any]:
    """
    Módulo 3: Sentinel Cloud & BaaS Leak Hunter (S3, GCP, Azure Blob, Firebase).
    """
    clean_domain = domain.strip().lower()
    brand = _extract_brand_keyword(clean_domain)

    probes = []
    for suffix in BUCKET_SUFFIXES:
        candidate = f"{brand}{suffix}"
        probes.append(("AWS S3", candidate, f"https://{candidate}.s3.amazonaws.com"))
        probes.append(("Google Cloud Storage", candidate, f"https://storage.googleapis.com/{candidate}"))
        azure_acc = candidate.replace("-", "")
        probes.append(("Azure Blob Storage", candidate, f"https://{azure_acc}.blob.core.windows.net/{candidate}?restype=container&comp=list"))

    # Sondeo adicional de bases Firebase Realtime asociadas a la marca
    for fb_suffix in ["", "-prod", "-default-rtdb", "-app"]:
        fb_cand = f"{brand}{fb_suffix}"
        probes.append(("Google Firebase Realtime DB", fb_cand, f"https://{fb_cand}.firebaseio.com/.json?shallow=true"))

    headers = {"User-Agent": "SentinelRecon-EASM/2.0 (Cloud-Posture-Audit)"}
    sem = asyncio.Semaphore(15)

    async with httpx.AsyncClient(timeout=timeout, headers=headers, verify=False) as client:
        tasks = [
            _probe_single_cloud_endpoint(prov, b_name, url, client, sem)
            for prov, b_name, url in probes
        ]
        raw_results = await asyncio.gather(*tasks, return_exceptions=True)

    valid_findings = [
        r for r in raw_results
        if isinstance(r, dict) and r.get("bucket_name")
    ]

    open_buckets = [f for f in valid_findings if f["access_state"] == "PUBLIC_OPEN_LISTABLE"]
    private_buckets = [f for f in valid_findings if f["access_state"] == "PROTECTED_PRIVATE"]

    status = "critical" if len(open_buckets) > 0 else "clean"

    drift_payload = {
        "open": [b["endpoint_url"] for b in open_buckets],
        "private": [b["endpoint_url"] for b in private_buckets]
    }
    drift_hash = hashlib.sha256(
        json.dumps(drift_payload, sort_keys=True).encode("utf-8")
    ).hexdigest()

    return {
        "module": "cloud_leak_hunter",
        "domain": clean_domain,
        "brand_keyword": brand,
        "status": status,
        "containers_probed_count": len(probes),
        "public_leaking_buckets_count": len(open_buckets),
        "private_discovered_buckets_count": len(private_buckets),
        "public_leaking_buckets": open_buckets,
        "private_cloud_footprints": private_buckets[:10],
        "ley_21719_data_protection_compliant": len(open_buckets) == 0,
        "drift_fingerprint": drift_hash
    }