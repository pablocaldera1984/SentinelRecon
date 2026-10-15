# test_all_modules.py
import asyncio
import json
import sys
import warnings

warnings.filterwarnings("ignore")

# Importación de todos los módulos testeados en tus archivos .py
from modules.dns_scanner import scan_dns_email
from modules.web_scanner import scan_web_crypto
from modules.port_scanner import scan_critical_ports
from modules.identity_scanner import scan_identity_exposure
from modules.brand_typosquatting_scanner import scan_brand_typosquatting
from modules.shadow_dns_scanner import scan_shadow_dns_and_takeover
from modules.cloud_leak_scanner import scan_cloud_storage_leaks
from modules.kev_epss_scanner import scan_kev_epss_prioritization
from core.scoring import evaluate_security_posture
from core.report_ai import generate_executive_analysis


async def run_all_tests(target: str, run_ai: bool = False):
    print("=" * 80)
    print(f"[*] INICIANDO AUDITORÍA INTEGRAL DE TODOS LOS MÓDULOS PARA: {target}")
    print("=" * 80)

    # 1. Ejecución asíncrona concurrente de todas las sondas de recolección
    print("\n[*] [1/3] Lanzando sondas asíncronas simultáneas...")
    (
        dns_res,
        web_res,
        port_res,
        id_res,
        typo_res,
        shadow_res,
        cloud_res
    ) = await asyncio.gather(
        scan_dns_email(target),
        scan_web_crypto(target),
        scan_critical_ports(target),
        scan_identity_exposure(target),
        scan_brand_typosquatting(target),
        scan_shadow_dns_and_takeover(target),
        scan_cloud_storage_leaks(target)
    )

    # 2. El módulo KEV-EPSS correlaciona puertos abiertos y banners web
    print("[*] [2/3] Correlacionando catálogo CISA KEV / EPSS...")
    kev_res = await scan_kev_epss_prioritization(target, open_ports_data=port_res, web_data=web_res)

    # 3. Evaluación de postura perimetral y cálculo de Drift Hash
    print("[*] [3/3] Calculando postura de seguridad y huella de deriva...")
    posture = evaluate_security_posture(
        dns_res,
        web_res,
        port_res,
        identity_data=id_res,
        typosquatting_data=typo_res,
        shadow_dns_data=shadow_res,
        kev_epss_data=kev_res,
        cloud_leak_data=cloud_res
    )

    # Impresión detallada de la telemetría técnica (lo que no siempre cabe en el PDF)
    print("\n" + "#" * 80)
    print("--- [SECCIÓN A] TELEMETRÍA TÉCNICA DETALLADA (BRUTO) ---")
    print("#" * 80)

    telemetria_completa = {
        "1_dns_y_correo": dns_res,
        "2_web_ssl_cabeceras": web_res,
        "3_puertos_expuestos": port_res,
        "4_radar_infostealers": id_res,
        "5_brand_typosquatting_bec": typo_res,
        "6_shadow_dns_rdap": shadow_res,
        "7_cisa_kev_epss": kev_res,
        "8_cloud_leaks_storage": cloud_res
    }
    print(json.dumps(telemetria_completa, indent=2, ensure_ascii=False))

    # Resumen comparativo directo
    print("\n" + "#" * 80)
    print("--- [SECCIÓN B] RESUMEN DE SCORING Y POSTURA (COMO EN PORTAL ADMIN) ---")
    print("#" * 80)

    resumen_postura = {
        "dominio_auditado": target,
        "postura": {
            "score": posture.get("score_posture"),
            "grade": posture.get("grade"),
            "risk_level": posture.get("risk_level"),
            "penalties": posture.get("penalties"),
            "global_drift_hash": posture.get("global_drift_hash")
        },
        "kpis_clave_comparacion": {
            "infostealers_empleados": id_res.get("compromised_employees", 0),
            "infostealers_usuarios": id_res.get("compromised_users", 0),
            "clones_typosquatting_totales": typo_res.get("active_lookalikes_count", 0),
            "clones_con_mx_correo": typo_res.get("mail_ready_clones_count", 0),
            "subdominios_descubiertos": shadow_res.get("active_subdomains_count", 0),
            "vulnerables_a_takeover": shadow_res.get("takeover_vulnerable_count", 0),
            "dias_expiracion_nic_cl": shadow_res.get("domain_registration_rdap", {}).get("days_until_expiration"),
            "puertos_abiertos": [p.get("port") for p in port_res.get("open_ports", [])],
            "incidentes_kev_p0": kev_res.get("same_day_p0_incidents_count", 0),
            "buckets_publicos_expuestos": cloud_res.get("public_leaking_buckets_count", 0),
            "spf_status": dns_res.get("spf", {}).get("status"),
            "dmarc_policy": dns_res.get("dmarc", {}).get("policy"),
            "dias_vigencia_ssl": web_res.get("ssl_certificate", {}).get("days_until_expiry")
        }
    }
    print(json.dumps(resumen_postura, indent=2, ensure_ascii=False))

    # Opcional: Generación del informe cognitivo con Gemini
    if run_ai:
        print("\n" + "#" * 80)
        print("--- [SECCIÓN C] ANÁLISIS COGNITIVO IA (GEMINI) ---")
        print("#" * 80)
        pipeline_payload = {
            "target": target,
            "postura": posture,
            "telemetria_tecnica": telemetria_completa
        }
        informe_ia = generate_executive_analysis(pipeline_payload)
        print(json.dumps(informe_ia, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    target_dominio = sys.argv[1].strip() if len(sys.argv) > 1 else "astralsalud.cl"
    # Si quieres incluir la inferencia de Gemini, pasa '--ai' como segundo argumento
    incluir_ia = "--ai" in sys.argv
    asyncio.run(run_all_tests(target_dominio, run_ai=incluir_ia))