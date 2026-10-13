import os
import asyncio
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from modules.dns_scanner import scan_dns_email
from modules.web_scanner import scan_web_crypto
from modules.port_scanner import scan_critical_ports
from core.scoring import evaluate_security_posture
from core.report_ai import generate_executive_analysis
from core.pdf_generator import generate_html_report

app = FastAPI(title="SentinelRecon API", version="1.0.0")

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
    return {"status": "ok", "service": "SentinelRecon EASM"}

@app.post("/api/scan")
async def run_scan(payload: ScanRequest):
    domain = payload.domain.strip().lower()
    if not domain:
        raise HTTPException(status_code=400, detail="Debe proporcionar un dominio válido.")

    try:
        # 1. Escaneo Asíncrono en Paralelo (< 3 seg)
        dns_res, web_res, port_res = await asyncio.gather(
            scan_dns_email(domain),
            scan_web_crypto(domain),
            scan_critical_ports(domain)
        )

        # 2. Evaluación de Postura y Scoring
        posture = evaluate_security_posture(dns_res, web_res, port_res)

        pipeline_payload = {
            "target": domain,
            "postura": posture,
            "dns_email": dns_res,
            "web_ssl": web_res,
            "puertos": port_res
        }

        # 3. Síntesis Cognitiva con Gemini
        reporte_ia = generate_executive_analysis(pipeline_payload)

        return {
            "target": domain,
            "postura": posture,
            "analisis_cognitivo": reporte_ia,
            "telemetria_tecnica": {
                "dns": dns_res,
                "web": web_res,
                "puertos": port_res
            }
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error durante el escaneo: {str(e)}")

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8080))
    uvicorn.run("api:app", host="0.0.0.0", port=port)
