# api.py
import os
import asyncio
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from modules.dns_scanner import scan_dns_email
from modules.web_scanner import scan_web_crypto
from modules.port_scanner import scan_critical_ports
from modules.identity_scanner import scan_identity_exposure
from modules.brand_typosquatting_scanner import scan_brand_typosquatting
from modules.shadow_dns_scanner import scan_shadow_dns_and_takeover
from modules.kev_epss_scanner import scan_kev_epss_prioritization
from modules.cloud_leak_scanner import scan_cloud_storage_leaks

from core.scoring import evaluate_security_posture
from core.report_ai import generate_executive_analysis

app = FastAPI(title="SentinelRecon EASM & DRPS API", version="2.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class ScanRequest(BaseModel):
    domain: str


@app.get("/")
def health_check():
    return {"status": "ok", "service": "SentinelRecon EASM + DRPS + TPRM v2.1"}


@app.post("/api/scan")
async def run_scan(payload: ScanRequest):
    domain = payload.domain.strip().lower()
    if not domain:
        raise HTTPException(status_code=400, detail="Debe proporcionar un dominio válido.")

    try:
        # 1. Fase A: Escaneo en paralelo de sondas primarias
        (
            dns_res,
            web_res,
            port_res,
            identity_res,
            shadow_res,
            cloud_res
        ) = await asyncio.gather(
            scan_dns_email(domain),
            scan_web_crypto(domain),
            scan_critical_ports(domain),
            scan_identity_exposure(domain),
            scan_shadow_dns_and_takeover(domain),
            scan_cloud_storage_leaks(domain)
        )

        # 2. Fase B: Cruce de Favicon Hash (Clones Visuales) y Matriz KEV/EPSS + Shodan InternetDB
        fav_hash = web_res.get("http_headers", {}).get("favicon_mmh3")
        typo_res, kev_res = await asyncio.gather(
            scan_brand_typosquatting(domain, original_favicon_mmh3=fav_hash),
            scan_kev_epss_prioritization(domain, open_ports_data=port_res, web_data=web_res)
        )

        # 3. Evaluación de Postura y Scoring Determinista
        posture = evaluate_security_posture(
            dns_res, web_res, port_res,
            identity_data=identity_res,
            typosquatting_data=typo_res,
            shadow_dns_data=shadow_res,
            kev_epss_data=kev_res,
            cloud_leak_data=cloud_res
        )

        telemetria = {
            "dns": dns_res,
            "web": web_res,
            "puertos": port_res,
            "identidad": identity_res,
            "typosquatting": typo_res,
            "shadow_dns": shadow_res,
            "kev_epss": kev_res,
            "cloud_leaks": cloud_res
        }

        pipeline_payload = {
            "target": domain,
            "postura": posture,
            "telemetria": telemetria
        }

        # 4. Síntesis Cognitiva Multirrol con Gemini
        reporte_ia = generate_executive_analysis(pipeline_payload)

        return {
            "target": domain,
            "postura": posture,
            "analisis_cognitivo": reporte_ia,
            "telemetria_tecnica": telemetria
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error durante el escaneo: {str(e)}")

# Agregar en api.py de SentinelRecon
from typing import Optional, List
from modules.zero_hour_cti_scanner import run_zero_hour_cti_sweep
from core.cti_notifier import generate_developer_advisory_with_gemini, dispatch_email_and_whatsapp_alert

class ZeroHourScanRequest(BaseModel):
    client_name: str = "Cliente Desarrollador USA"
    client_domain_or_ip: Optional[str] = None
    client_email: Optional[str] = None
    admin_email: str = "pablocaldera1984@gmail.com"
    force_notify_top: bool = False
    processed_state_hashes: Optional[List[str]] = []

@app.post("/api/cti/zero-hour-scan")
async def run_zero_hour_scan_endpoint(payload: ZeroHourScanRequest):
    try:
        sweep = await run_zero_hour_cti_sweep(client_domain_or_ip=payload.client_domain_or_ip)
        seen_hashes = set(payload.processed_state_hashes or [])

        # Filtrar solo alertas P0/P1 nuevas que no hayan sido notificadas antes
        new_actionable = [
            a for a in sweep["actionable_alerts"]
            if a["state_hash"] not in seen_hashes
        ]

        # Si el administrador presionó "Forzar Investigación" y quiere ver el borrador del top 1 aunque no haya P0 nuevo
        if payload.force_notify_top and not new_actionable and sweep["all_ranked_signals"]:
            new_actionable = [sweep["all_ranked_signals"][0]]

        dispatched_advisories = []
        for alert_item in new_actionable[:2]:  # Máximo 2 alertas por ciclo para evitar saturación
            advisory = generate_developer_advisory_with_gemini(
                alert_item,
                sweep["client_perimeter_profile"],
                client_name=payload.client_name
            )
            notif_res = await dispatch_email_and_whatsapp_alert(
                advisory,
                alert_item,
                admin_email=payload.admin_email,
                client_email=payload.client_email or ""
            )
            dispatched_advisories.append({
                "vuln_id": alert_item["vuln_id"],
                "zhr_score": alert_item["zhr_score"],
                "alert_tier": alert_item["alert_tier"],
                "matched_technologies": alert_item["matched_technologies"],
                "state_hash": alert_item["state_hash"],
                "advisory": advisory,
                "notification_status": notif_res
            })

        return {
            "status": "ok",
            "sweep_summary": {
                "timestamp_utc": sweep["timestamp_utc"],
                "total_evaluated": sweep["total_evaluated"],
                "actionable_p0_p1_count": sweep["actionable_p0_p1_count"],
                "perimeter_profile": sweep["client_perimeter_profile"]
            },
            "dispatched_advisories": dispatched_advisories,
            "all_ranked_signals": sweep["all_ranked_signals"][:10]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error en Zero-Hour CTI: {str(e)}")

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8080))
    uvicorn.run("api:app", host="0.0.0.0", port=port)