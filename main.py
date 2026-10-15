# main.py
import asyncio
import sys
import os
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
from core.pdf_generator import generate_html_report


async def run_sentinel_recon(target_domain: str):
    print("=" * 72)
    print(f"[*] INICIANDO AUDITORÍA EASM + DRPS + CUMPLIMIENTO ANCI: {target_domain}")
    print("=" * 72)

    # 1. Escaneo Concurrente Asíncrono de las 7 Sondas Externas
    print("[1/4] Ejecutando sondas asíncronas: DNS, Web/TLS, Puertos, Infostealers,")
    print("      Typosquatting BEC, Shadow DNS/NIC.cl y Cloud Buckets...")
    (
        dns_res,
        web_res,
        port_res,
        identity_res,
        typo_res,
        shadow_res,
        cloud_res
    ) = await asyncio.gather(
        scan_dns_email(target_domain),
        scan_web_crypto(target_domain),
        scan_critical_ports(target_domain),
        scan_identity_exposure(target_domain),
        scan_brand_typosquatting(target_domain),
        scan_shadow_dns_and_takeover(target_domain),
        scan_cloud_storage_leaks(target_domain)
    )

    # Cruce determinista con CISA KEV y FIRST EPSS según puertos/servicios detectados
    kev_res = await scan_kev_epss_prioritization(target_domain, open_ports_data=port_res, web_data=web_res)

    # 2. Evaluación de Postura y Riesgo Matemático
    print("[2/4] Calculando scoring determinista de postura y huella de deriva (Drift)...")
    posture = evaluate_security_posture(
        dns_res, web_res, port_res,
        identity_data=identity_res,
        typosquatting_data=typo_res,
        shadow_dns_data=shadow_res,
        kev_epss_data=kev_res,
        cloud_leak_data=cloud_res
    )

    telemetria_consolidada = {
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
        "target": target_domain,
        "postura": posture,
        "telemetria": telemetria_consolidada
    }

    # 3. Síntesis Cognitiva con IA (Gemini)
    print("[3/4] Generando informe ejecutivo multirrol, comandos TI y pre-alerta ANCI con Gemini...")
    reporte_ia = generate_executive_analysis(pipeline_payload)

    # 4. Generación del Reporte Ejecutivo HTML/PDF
    print("[4/4] Renderizando Súper Reporte Corporativo HTML...")
    output_filename = f"reporte_{target_domain.replace('.', '_')}.html"
    generate_html_report(
        target_domain, 
        reporte_ia, 
        output_filename, 
        raw_telemetry=telemetria_consolidada,
        posture=posture
    )

    print("\n" + "=" * 72)
    print(f"[+] AUDITORÍA COMPLETADA CON ÉXITO")
    print(f"[+] Postura: Grado {reporte_ia['resumen_ejecutivo']['calificacion_postura']} ({reporte_ia['resumen_ejecutivo']['puntaje_global']}/100)")
    print(f"[+] Huella de Deriva (Drift Hash): {posture['global_drift_hash'][:16]}...")
    print(f"[+] Reporte generado: {os.path.abspath(output_filename)}")
    print("=" * 72)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        target = "global365.cl"
        print(f"[*] No se especificó dominio. Usando objetivo por defecto: {target}")
    else:
        target = sys.argv[1].strip()

    asyncio.run(run_sentinel_recon(target))