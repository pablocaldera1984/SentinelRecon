import asyncio
import json
from modules.dns_scanner import scan_dns_email
from modules.web_scanner import scan_web_crypto
from modules.port_scanner import scan_critical_ports
from core.scoring import evaluate_security_posture
from core.report_ai import generate_executive_analysis

async def main():
    target = "google.com"
    print(f"[*] 1. Escaneando perimetro para: {target}...")

    dns_res, web_res, port_res = await asyncio.gather(
        scan_dns_email(target),
        scan_web_crypto(target),
        scan_critical_ports(target)
    )

    posture = evaluate_security_posture(dns_res, web_res, port_res)

    pipeline_payload = {
        "target": target,
        "postura": posture,
        "dns_email": dns_res,
        "web_ssl": web_res,
        "puertos": port_res
    }

    print("[*] 2. Generando reporte ejecutivo con Gemini 3.5 Flash-Lite...")
    informe_ia = generate_executive_analysis(pipeline_payload)

    print("\n================ REPORTE GENERADO POR IA ================\n")
    print(json.dumps(informe_ia, indent=2, ensure_ascii=False))

if __name__ == "__main__":
    asyncio.run(main())
