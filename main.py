import asyncio
import sys
import os
import json
from modules.dns_scanner import scan_dns_email
from modules.web_scanner import scan_web_crypto
from modules.port_scanner import scan_critical_ports
from core.scoring import evaluate_security_posture
from core.report_ai import generate_executive_analysis
from core.pdf_generator import generate_html_report

async def run_sentinel_recon(target_domain: str):
    print("=" * 60)
    print(f"[*] INICIANDO AUDITORÍA EASM NO INVASIVA: {target_domain}")
    print("=" * 60)

    # 1. Escaneo Concurrente Asíncrono
    print("[1/4] Ejecutando sondas DNS, Web/TLS y Puertos Críticos...")
    dns_res, web_res, port_res = await asyncio.gather(
        scan_dns_email(target_domain),
        scan_web_crypto(target_domain),
        scan_critical_ports(target_domain)
    )

    # 2. Evaluación de Postura y Riesgo Matemático
    print("[2/4] Calculando scoring de riesgo y postura ejecutiva...")
    posture = evaluate_security_posture(dns_res, web_res, port_res)

    pipeline_payload = {
        "target": target_domain,
        "postura": posture,
        "dns_email": dns_res,
        "web_ssl": web_res,
        "puertos": port_res
    }

    # 3. Síntesis Cognitiva con IA
    print("[3/4] Generando informe cognitivo y prescripción EDR con Gemini...")
    reporte_ia = generate_executive_analysis(pipeline_payload)

    # 4. Generación del Reporte Ejecutivo
    print("[4/4] Renderizando reporte corporativo...")
    output_filename = f"reporte_{target_domain.replace('.', '_')}.html"
    generate_html_report(target_domain, reporte_ia, output_filename)

    print("\n" + "=" * 60)
    print(f"[+] AUDITORÍA COMPLETADA CON ÉXITO")
    print(f"[+] Postura: Grado {reporte_ia['resumen_ejecutivo']['calificacion_postura']} ({reporte_ia['resumen_ejecutivo']['puntaje_global']}/100)")
    print(f"[+] Reporte generado: {os.path.abspath(output_filename)}")
    print("=" * 60)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        target = "google.com"
        print(f"[*] No se especificó dominio. Usando objetivo de prueba: {target}")
    else:
        target = sys.argv[1]

    asyncio.run(run_sentinel_recon(target))
