import asyncio
import json
from modules.dns_scanner import scan_dns_email
from modules.web_scanner import scan_web_crypto
from modules.port_scanner import scan_critical_ports
from core.scoring import evaluate_security_posture

async def main():
    target = "google.com"
    print(f"[*] Ejecutando escaneo concurrente en: {target}...")

    # Ejecución asíncrona simultánea (<3 segundos)
    dns_res, web_res, port_res = await asyncio.gather(
        scan_dns_email(target),
        scan_web_crypto(target),
        scan_critical_ports(target)
    )

    # Procesamiento del motor de scoring
    posture = evaluate_security_posture(dns_res, web_res, port_res)

    output = {
        "target": target,
        "evaluacion_ejecutiva": posture,
        "resumen_tecnico": {
            "puertos_abiertos": [p["port"] for p in port_res["open_ports"]],
            "dmarc_policy": dns_res["dmarc"]["policy"],
            "spf_status": dns_res["spf"]["status"],
            "ssl_dias_vigencia": web_res["ssl_certificate"]["days_until_expiry"]
        }
    }

    print(json.dumps(output, indent=2, ensure_ascii=False))

if __name__ == "__main__":
    asyncio.run(main())
