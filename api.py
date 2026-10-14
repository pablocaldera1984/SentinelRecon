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

app = FastAPI(title="SentinelRecon EASM & DRPS API", version="2.0.0")

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
    return {"status": "ok", "service": "SentinelRecon EASM + DRPS + TPRM v2.0"}


@app.post("/api/scan")
async def run_scan(payload: ScanRequest):
    domain = payload.domain.strip().lower()
    if not domain:
        raise HTTPException(status_code=400, detail="Debe proporcionar un dominio válido.")

    try:
        # 1. Escaneo Asíncrono en Paralelo de los 7 motores
        (
            dns_res,
            web_res,
            port_res,
            identity_res,
            typo_res,
            shadow_res,
            cloud_res
        ) = await asyncio.gather(
            scan_dns_email(domain),
            scan_web_crypto(domain),
            scan_critical_ports(domain),
            scan_identity_exposure(domain),
            scan_brand_typosquatting(domain),
            scan_shadow_dns_and_takeover(domain),
            scan_cloud_storage_leaks(domain)
        )

        kev_res = await scan_kev_epss_prioritization(domain, open_ports_data=port_res, web_data=web_res)

        # 2. Evaluación de Postura y Scoring Determinista
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

        # 3. Síntesis Cognitiva Multirrol con Gemini
        reporte_ia = generate_executive_analysis(pipeline_payload)

        return {
            "target": domain,
            "postura": posture,
            "analisis_cognitivo": reporte_ia,
            "telemetria_tecnica": telemetria
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error durante el escaneo: {str(e)}")


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8080))
    uvicorn.run("api:app", host="0.0.0.0", port=port)