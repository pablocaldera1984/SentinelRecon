# core/report_ai.py
import json
import os
from typing import List, Dict, Any
from pydantic import BaseModel, Field
from dotenv import load_dotenv
from google import genai
from google.genai import types
from config import MODELO_GEMINI

load_dotenv()


class ExecutiveSummary(BaseModel):
    calificacion_postura: str = Field(description="Grado ejecutivo A, B, C, D o F")
    puntaje_global: int = Field(description="Puntaje de 0 a 100")
    impacto_financiero_estimado: str = Field(description="Riesgo comercial y reputacional directo en lenguaje simple (PROHIBIDO inventar cifras en millones de pesos o dólares): riesgo de estafas en pagos a clientes por correo falso, pérdida de ventas/pacientes o costos de recuperación web.")
    impacto_operacional: str = Field(description="Explicación clara y sin tecnicismos de cómo las brechas detectadas pueden interrumpir la operación diaria (caída de la página web, páginas secundarias olvidadas expuestas, bloqueo de correos o secuestro de información).")
    exposicion_regulatoria: str = Field(description="Clasificación automática del rol de la empresa bajo la Ley N° 21.663 (Servicio Esencial PSE, OIV o Proveedor de Cadena de Suministro Art. 8) y deberes de resguardo de datos de clientes/pacientes bajo la Ley N° 21.719.")


class PriorityFinding(BaseModel):
    vector: str = Field(description="Título claro y directo del problema entendible por un gerente (ej: 'Correos corporativos desprotegidos ante suplantación y estafas')")
    criticidad: str = Field(description="CRÍTICO, ALTO o MEDIO")
    puerto_servicio: str = Field(description="Área afectada en simple + referencia técnica breve (ej: 'Correo Electrónico (SPF/DMARC)' o 'Código Página Web (PHP/CSP)')")
    evidencia_tecnica: str = Field(description="Dato exacto encontrado por el escáner que sirve de prueba (ej: 'Sin registro DMARC / Puerto 22 abierto / Cabecera X-Powered-By expuesta')")
    explicacion_tecnica: str = Field(description="Explicación en lenguaje 100% claro para el dueño de la empresa: qué significa este problema, cómo un atacante puede aprovecharlo para afectar a sus clientes o botar su web, y entre paréntesis la referencia técnica o CVE.")


class EDRAction(BaseModel):
    modulo_edr: str = Field(description="Nombre claro del escudo de SentinelAgent (ej: 'Escudo Anti-Ransomware y Bloqueo de Virus', 'Protección de Contraseñas en Computadores')")
    control_compensatorio: str = Field(description="Explicación en lenguaje sencillo de cómo protege los computadores de los trabajadores en la oficina")
    mitigacion_vector_perimetral: str = Field(description="Cómo evita que un error humano o correo falso en la oficina comprometa a la empresa")


class EDRPrescription(BaseModel):
    necesidad_defensa_profundidad: str = Field(description="Explicación clara para el gerente de por qué arreglar la página web no basta si un trabajador abre un correo falso o descarga un archivo infectado en su computador de oficina, justificando instalar SentinelAgent y SentinelVault.")
    acciones_inmediatas_edr: List[EDRAction]
    argumentario_cierre_comercial: str


class DRPSPersistenceInsights(BaseModel):
    diagnostico_infostealers_identidad: str = Field(description="Resumen claro sobre contraseñas filtradas en internet (Hudson Rock Stealer Logs y Combolists), filtraciones de código en GitHub público y si cuentan o no con cuentas centralizadas Microsoft 365.")
    diagnostico_typosquatting_bec: str = Field(description="Explicación clara sobre dominios parecidos activos (Lookalike Domains con correo MX o clonación visual Favicon) y el riesgo de que confundan a clientes en pagos o cobranzas.")
    diagnostico_shadow_dns_nic: str = Field(description="Explicación clara del proveedor de hosting detectado, país donde se guardan los datos (Ley 21.719), vigencia en NIC Chile y cantidad exacta de páginas web o portales anexos abiertos bajo el dominio (postulaciones, clientes, dev, test, cpanel).")
    diagnostico_kev_epss_cloud: str = Field(description="Explicación clara de las fallas sin actualizar en el servidor web (Shodan/KEV/Fechas EOL), salud del código web (PHP/Scripts/Pagos Webpay/Metadatos PDF), listas negras de correo y bases de datos en la nube.")
    justificacion_monitoreo_continuo: str = Field(description="Por qué es vital que SentinelRecon vigile automáticamente la empresa todas las semanas.")


class TechnicalRemediationCommand(BaseModel):
    responsable_ejecucion: str = Field(description="Destinatario claro: 'Proveedor de Hosting / DNS', 'Proveedor de Servidor / Cloud', 'Desarrollador / Programador Web', o 'Equipo Interno TI / Gerencia'")
    componente_afectado: str = Field(description="Ej: 'Configuración de Correos del Dominio', 'Servidor de la Página Web', 'Páginas Web Anexas / Subdominios', 'Computadores de la Oficina'")
    accion_inmediata: str = Field(description="Resumen en una línea y en lenguaje simple de lo que el gerente le está pidiendo hacer a su proveedor")
    comando_o_script_sugerido: str = Field(description="Mensaje formal listo para copiar y enviar por correo o WhatsApp al técnico/proveedor, incluyendo las instrucciones o comandos exactos bien separados con espacios.")


class ANCIGovernancePack(BaseModel):
    estado_inventario_art8: str = Field(description="Clasificación del rol de la empresa ante la ANCI (Ley 21.663 Art. 8) y nivel de cumplimiento en protección de datos personales (Ley 21.719).")
    borrador_alerta_temprana_3h_csirt: str = Field(description="Plantilla preventiva de contingencia interna (< 3 horas Art. 9 Ley 21.663) para uso del encargado técnico en caso de incidente.")
    directriz_cadena_suministro_tprm: str = Field(description="Recomendación práctica para exigir a los proveedores tecnológicos (hosting y programadores) que mantengan al día la seguridad.")


class EASMExecutiveReport(BaseModel):
    resumen_ejecutivo: ExecutiveSummary
    hallazgos_prioritarios: List[PriorityFinding]
    inteligencia_drps_persistencia: DRPSPersistenceInsights
    comandos_remediacion_ti: List[TechnicalRemediationCommand]
    gobernanza_anci_ley21663: ANCIGovernancePack
    prescripcion_endpoint_edr: EDRPrescription


def _extract_telemetry(scan_data: Dict[str, Any]) -> Dict[str, Any]:
    """Desempaqueta telemetría tanto si viene desde api.py (pipeline_payload) como directa."""
    return scan_data.get("telemetria") or scan_data.get("telemetria_tecnica") or scan_data


def _build_anci_9_basicos_coverage(scan_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Evalúa determinísticamente los 9 Básicos de la Ciberseguridad de la ANCI (Res. Exenta N° 140 / Ley 21.663).
    Marca como auditados por SentinelRecon los 4 controles perimetrales (1, 5, 7 y 8) con su color de cumplimiento
    (VERDE, NARANJA, ROJO) y deja en GRIS los 5 controles de alcance interno de PCs / organización (2, 3, 4, 6 y 9).
    """
    tel = _extract_telemetry(scan_data)
    web = tel.get("web") or {}
    dns = tel.get("dns") or {}
    ports = tel.get("puertos") or tel.get("ports") or {}
    identidad = tel.get("identidad") or {}
    kev = tel.get("kev_epss") or {}
    shadow = tel.get("shadow_dns") or {}

    code_audit = web.get("code_security_audit") or {}
    eol_list = code_audit.get("eol_software_detected") or []
    outdated_js = code_audit.get("outdated_js_libraries") or []
    cves = ports.get("shodan_cves") or ports.get("vulnerabilities") or (ports.get("shodan_internetdb") or {}).get("vulns") or []
    kev_hits = kev.get("kev_matches") or kev.get("cisa_kev_active") or []
    extra_pages = shadow.get("additional_open_web_pages") or []

    # 1. Actualizar periódicamente (Auditado por SentinelRecon)
    if len(kev_hits) > 0 or len(cves) > 0 or len(eol_list) > 0:
        b1_color = "ROJO"
        b1_status = "PELIGRO"
        b1_detail = f"Tecnología vencida ({len(eol_list)} EOL) o {len(cves)} fallas públicas sin parchear."
    elif len(outdated_js) > 0 or len(extra_pages) > 2:
        b1_color = "NARANJA"
        b1_status = "ATENCIÓN"
        b1_detail = "Librerías web secundarias desactualizadas o páginas anexas por revisar."
    else:
        b1_color = "VERDE"
        b1_status = "BIEN"
        b1_detail = "Servidor web y componentes perimetrales al día."

    # 5. Asegurar redes (Auditado por SentinelRecon)
    dmarc_data = dns.get("dmarc") or {}
    spf_data = dns.get("spf") or {}
    if isinstance(dmarc_data, dict):
        dmarc_ok = bool(dmarc_data.get("present") or dmarc_data.get("valid"))
        dmarc_policy = str(dmarc_data.get("policy") or dmarc_data.get("record") or "").lower()
    else:
        dmarc_ok = bool(dns.get("dmarc_present") or (dmarc_data and str(dmarc_data) != "No configurado"))
        dmarc_policy = str(dns.get("dmarc_policy") or dmarc_data or "").lower()

    if isinstance(spf_data, dict):
        spf_ok = bool(spf_data.get("present") or spf_data.get("valid"))
    else:
        spf_ok = bool(dns.get("spf_present") or (spf_data and str(spf_data) != "No configurado"))

    dmarc_strict = ("reject" in dmarc_policy) or ("quarantine" in dmarc_policy)
    ssl_info = web.get("ssl_certificate") or web
    ssl_valid = bool(ssl_info.get("valid", ssl_info.get("ssl_valid", True)))

    open_ports_raw = ports.get("open_ports") or []
    open_port_nums = [
        p.get("port") if isinstance(p, dict) else p
        for p in open_ports_raw
    ]
    risky_ports = [p for p in open_port_nums if p in (21, 22, 23, 445, 1433, 3306, 3389, 5432, 6379, 27017)]

    headers_sec = (web.get("http_headers") or {}).get("security_headers") or web
    has_hsts = bool(headers_sec.get("Strict-Transport-Security") or headers_sec.get("hsts"))
    has_csp = bool(headers_sec.get("Content-Security-Policy") or headers_sec.get("csp"))

    if not dmarc_ok or not spf_ok or not ssl_valid or len(risky_ports) > 0:
        b5_color = "ROJO"
        b5_status = "PELIGRO"
        b5_detail = "Correos desprotegidos (SPF/DMARC) o puertos críticos expuestos a internet."
    elif not dmarc_strict or not has_hsts or not has_csp:
        b5_color = "NARANJA"
        b5_status = "ATENCIÓN"
        b5_detail = "Faltan cabeceras de blindaje web (CSP/HSTS) o política DMARC estricta."
    else:
        b5_color = "VERDE"
        b5_status = "BIEN"
        b5_detail = "Perímetro de red, correo y cifrado SSL correctamente asegurados."

    # 7. Monitorear en tiempo real (Auditado por SentinelRecon)
    is_continuous = bool(scan_data.get("monitoreo_continuo_activo") or scan_data.get("vigilancia_24_7"))
    if is_continuous:
        b7_color = "VERDE"
        b7_status = "BIEN"
        b7_detail = "Vigilancia perimetral continua 24/7 activa en SentinelRecon."
    else:
        b7_color = "NARANJA"
        b7_status = "ATENCIÓN"
        b7_detail = "Diagnóstico activo; se recomienda habilitar monitoreo continuo 24/7."

    # 8. Usar múltiples factores de autenticación - MFA (Auditado en Perímetro por SentinelRecon)
    m365_info = identidad.get("m365_tenant_recon") or identidad.get("entra_id") or {}
    mx_arch = str(dns.get("email_architecture") or dns.get("mx_provider") or "").lower()
    has_federated_sso = bool(
        m365_info.get("tenant_found")
        or m365_info.get("is_federated")
        or "google" in mx_arch
        or "microsoft" in mx_arch
    )
    combo_count = int((identidad.get("combolist_intelligence") or {}).get("total_leaks", 0) or identidad.get("compromised_employees", 0) or 0)
    admin_portals = shadow.get("exposed_admin_or_dev_portals") or []

    if combo_count > 0 or (len(admin_portals) > 0 and not has_federated_sso):
        b8_color = "ROJO"
        b8_status = "PELIGRO"
        b8_detail = "Accesos o claves expuestas sin protección centralizada MFA verificada."
    elif not m365_info.get("tenant_found"):
        b8_color = "NARANJA"
        b8_status = "ATENCIÓN"
        b8_detail = "Sin acceso corporativo blindado de Microsoft 365; claves individuales más vulnerables."
    else:
        b8_color = "VERDE"
        b8_status = "BIEN"
        b8_detail = "Identidad corporativa centralizada compatible con MFA."

    items = [
        {
            "numero": 1,
            "nombre_corto": "Actualizar Software",
            "nombre_oficial": "Actualizar periódicamente",
            "audited_by_recon": True,
            "color": b1_color,
            "estado": b1_status,
            "alcance_label": "Evaluado en Web",
            "detalle": b1_detail
        },
        {
            "numero": 2,
            "nombre_corto": "Capacitar Personal",
            "nombre_oficial": "Capacitar periódicamente",
            "audited_by_recon": False,
            "color": "GRIS",
            "estado": "INTERNO",
            "alcance_label": "Gestión Interna",
            "detalle": "Requiere programa de formación continua y simulaciones al personal."
        },
        {
            "numero": 3,
            "nombre_corto": "Mínimo Privilegio",
            "nombre_oficial": "Minimizar privilegios",
            "audited_by_recon": False,
            "color": "GRIS",
            "estado": "INTERNO",
            "alcance_label": "Control en PCs",
            "detalle": "Requiere auditar cuentas de usuario dentro de los computadores."
        },
        {
            "numero": 4,
            "nombre_corto": "Respaldar Datos",
            "nombre_oficial": "Respaldar periódicamente la información",
            "audited_by_recon": False,
            "color": "GRIS",
            "estado": "INTERNO",
            "alcance_label": "Control en PCs",
            "detalle": "Requiere copias de seguridad desconectadas y cifradas (Regla 3-2-1)."
        },
        {
            "numero": 5,
            "nombre_corto": "Asegurar Redes",
            "nombre_oficial": "Asegurar redes",
            "audited_by_recon": True,
            "color": b5_color,
            "estado": b5_status,
            "alcance_label": "Evaluado en Red",
            "detalle": b5_detail
        },
        {
            "numero": 6,
            "nombre_corto": "Asegurar Equipos",
            "nombre_oficial": "Asegurar equipos",
            "audited_by_recon": False,
            "color": "GRIS",
            "estado": "INTERNO",
            "alcance_label": "Control en PCs",
            "detalle": "Requiere cifrado de disco y bloqueo de amenazas en cada computador."
        },
        {
            "numero": 7,
            "nombre_corto": "Monitorear 24/7",
            "nombre_oficial": "Monitorear en tiempo real",
            "audited_by_recon": True,
            "color": b7_color,
            "estado": b7_status,
            "alcance_label": "Vigilancia Activa",
            "detalle": b7_detail
        },
        {
            "numero": 8,
            "nombre_corto": "Uso de MFA",
            "nombre_oficial": "Usar múltiples factores de autenticación (MFA)",
            "audited_by_recon": True,
            "color": b8_color,
            "estado": b8_status,
            "alcance_label": "Evaluado en Accesos",
            "detalle": b8_detail
        },
        {
            "numero": 9,
            "nombre_corto": "Gestor de Claves",
            "nombre_oficial": "Usar un gestor de contraseñas",
            "audited_by_recon": False,
            "color": "GRIS",
            "estado": "INTERNO",
            "alcance_label": "Control en PCs",
            "detalle": "Requiere bóveda de contraseñas y protección de navegadores en PCs."
        }
    ]

    approved_count = sum(1 for item in items if item["audited_by_recon"] and item["color"] == "VERDE")

    return {
        "framework": "Los 9 Básicos de la Ciberseguridad ANCI (Ley N° 21.663 / Res. Exenta N° 140)",
        "covered_by_recon_count": 4,
        "internal_controls_count": 5,
        "total_controls": 9,
        "approved_in_recon_count": approved_count,
        "items": items
    }


def _build_open_web_pages_summary(scan_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Consolida el inventario de páginas web abiertas (sitio principal + sitios/portales anexos olvidados)
    descubiertos por shadow_dns_scanner.py para que el frontend lo pinte directamente.
    """
    tel = _extract_telemetry(scan_data)
    shadow = tel.get("shadow_dns") or {}
    domain = (scan_data.get("target") or scan_data.get("domain") or shadow.get("domain") or "").strip().lower()

    active_sites = shadow.get("active_web_sites") or []
    additional_pages = shadow.get("additional_open_web_pages") or []
    admin_portals = shadow.get("exposed_admin_or_dev_portals") or []

    if not active_sites and domain:
        active_sites = [{
            "subdomain": domain,
            "url": f"https://{domain}",
            "page_title": "Sitio Web Principal",
            "http_status": 200,
            "server_tech": None,
            "has_login_form": False,
            "role": "Sitio Web Principal",
            "ips": [],
            "is_main_site": True
        }]

    total_open_sites = max(1, len(active_sites))
    extra_count = max(len(additional_pages), len(admin_portals))

    if extra_count == 0:
        status_badge = "BIEN"
        headline = f"1 Sitio Web Principal activo ({domain}) — Sin páginas secundarias olvidadas"
        explanation = (
            f"Su empresa mantiene únicamente 1 sitio web principal abierto ({domain}), "
            "sin páginas olvidadas de campañas antiguas, sistemas de postulación ni paneles de prueba expuestos a internet."
        )
    else:
        status_badge = "PELIGRO" if any(p.get("has_login_form") for p in additional_pages) or len(admin_portals) > 0 else "ATENCIÓN"
        source_list = additional_pages if len(additional_pages) > 0 else admin_portals
        sample_names = [
            f"{p.get('subdomain')} ({p.get('page_title') or p.get('role')})"
            for p in source_list[:5]
        ]
        headline = f"{total_open_sites} Páginas Web Abiertas ({extra_count} sitios o portales anexos detectados)"
        explanation = (
            f"Además de su página principal ({domain}), se detectaron {extra_count} páginas o portales anexos abiertos en internet: "
            f"{', '.join(sample_names)}. Estas páginas secundarias (creadas para programas, campañas o pruebas pasadas) suelen quedar "
            "olvidadas sin actualización y representan puertas de entrada vulnerables hacia la empresa."
        )

    return {
        "total_open_web_sites": total_open_sites,
        "additional_open_pages_count": extra_count,
        "status_badge": status_badge,
        "headline": headline,
        "explanation": explanation,
        "main_domain": domain,
        "additional_pages": additional_pages[:12],
        "exposed_portals": admin_portals[:12]
    }


def _enforce_deterministic_coverage_and_clean_typos(
    report_dict: Dict[str, Any],
    scan_data: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Sanea el dominio en los textos generados y garantiza que el 100% de las brechas críticas
    (incluyendo páginas anexas olvidadas) tengan su mensaje listo para enviar en comandos_remediacion_ti.
    """
    tel = _extract_telemetry(scan_data)
    shadow = tel.get("shadow_dns") or {}
    domain = (scan_data.get("target") or scan_data.get("domain") or shadow.get("domain") or "").strip().lower()
    additional_pages = shadow.get("additional_open_web_pages") or []
    admin_portals = shadow.get("exposed_admin_or_dev_portals") or []

    commands = report_dict.get("comandos_remediacion_ti")
    if not isinstance(commands, list):
        commands = []

    if (len(additional_pages) > 0 or len(admin_portals) > 0) and domain:
        source_list = additional_pages if len(additional_pages) > 0 else admin_portals
        sub_list = [p.get("subdomain") for p in source_list if p.get("subdomain")]
        sub_str = ", ".join(sub_list[:6])
        already_covered = any(
            "subdominio" in (c.get("accion_inmediata", "") + c.get("comando_o_script_sugerido", "")).lower()
            or "páginas anexas" in (c.get("accion_inmediata", "") + c.get("comando_o_script_sugerido", "")).lower()
            for c in commands
        )
        if not already_covered and sub_str:
            commands.append({
                "responsable_ejecucion": "Proveedor de Hosting / DNS",
                "componente_afectado": "Páginas Web Anexas y Subdominios Activos",
                "accion_inmediata": f"Revisar y dar de baja las páginas web secundarias o portales en desuso ({len(sub_list)} detectados)",
                "comando_o_script_sugerido": (
                    f"ESTIMADO PROVEEDOR / ENCARGADO WEB, en nuestra auditoría de seguridad detectamos que además del sitio principal {domain} "
                    f"se encuentran abiertas y accesibles desde internet las siguientes páginas o subdominios anexos: {sub_str} . "
                    "Favor confirmar cuáles siguen en operación activa con sus parches al día y proceder a dar de baja o restringir el acceso público "
                    "a todas aquellas páginas de campañas antiguas, pruebas o portales que ya no se utilicen."
                )
            })

    report_dict["comandos_remediacion_ti"] = commands
    report_dict["anci_9_basicos"] = _build_anci_9_basicos_coverage(scan_data)
    report_dict["resumen_paginas_abiertas"] = _build_open_web_pages_summary(scan_data)
    return report_dict


def generate_executive_analysis(scan_data: Dict[str, Any]) -> Dict[str, Any]:
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        raise ValueError("No se encontró GEMINI_API_KEY configurada.")

    client = genai.Client(api_key=api_key)

    system_instruction = """
    Eres el Consultor Ejecutivo Principal de Ciberseguridad de Global365 SpA (Chile) operando el motor SentinelRecon v2.3.
    Tu lector principal NO es un ingeniero informático: es el DUEÑO DE LA EMPRESA o GERENTE GENERAL de una organización que no tiene departamento de TI experto.
    Tu objetivo es que el gerente entienda en una sola lectura rápida qué riesgos reales corre su negocio hoy, cuántas páginas web tiene abiertas en internet sin saberlo, cómo se encuentra frente a los 9 Básicos de la ANCI y qué mensajes claros debe enviarle a su informático o proveedor de hosting para solucionarlo.

    REGLAS DE ORO DE REDACCIÓN Y TONO COMERCIAL:
    1. PROHIBIDO INVENTAR MULTAS EN DINERO O CIFRAS MILLONARIAS:
    - En `impacto_financiero_estimado` y en todo el informe está ESTRICTAMENTE PROHIBIDO mencionar montos en pesos (CLP), dólares (USD) o UTM.
    - Enfoca el riesgo económico en situaciones reales de negocio: desvío de pagos de facturas por correos falsificados (fraude BEC), pérdida de clientes o pacientes por caída de la página web, intrusión a través de páginas web secundarias olvidadas, bloqueo de correos corporativos por caer en listas negras de Spam, y costos de emergencia por secuestro de datos.

    2. LENGUAJE 100% CLARO EN RESÚMENES Y HALLAZGOS (TRADUCTOR DE NEGOCIO):
    - En `hallazgos_prioritarios`, redacta el título (`vector`) y la explicación (`explicacion_tecnica`) en español cotidiano y directo, explicando el impacto práctico para la empresa.
    - Explica el concepto en simple (para qué sirve el programa vencido, la página anexa olvidada o el puerto abierto) y pon el dato técnico o código CVE entre paréntesis como evidencia pericial.

    3. CORRELACIÓN PROFUNDA DE SONDAS AVANZADAS Y PÁGINAS ABIERTAS v2.3:
    - Revisa `shadow_dns`:
      - Fíjate en `active_web_sites_count`, `additional_open_web_pages` y `exposed_admin_or_dev_portals`.
      - Si existen páginas web secundarias o subdominios abiertos además del sitio principal (ej. portales de postulación, campañas antiguas, intranet, cpanel, webmail, dev, test), destácalo claramente en `diagnostico_shadow_dns_nic` y en `hallazgos_prioritarios`, nombrando los subdominios y sus títulos web para demostrarle a la gerencia qué sitios tiene abiertos su empresa en internet.
    - Revisa `web.code_security_audit`:
      - Si `eol_software_detected` o `outdated_js_libraries` tienen elementos, destaca explícitamente qué componente está vencido, en qué año venció y para qué sirve (ej. formularios, servidor web o cifrado).
      - Si `ecommerce_magecart_risk.magecart_skimming_risk` es true, alerta el riesgo sobre su pasarela de pagos o carrito web.
      - Si `public_documents_metadata.exposed_authors_or_users` tiene nombres de usuarios o software extraídos de archivos PDF públicos, menciónalo como "Fuga de Identidad Interna en Documentos Públicos".
      - Si `whatsapp_impersonation_surface.has_whatsapp_widget` es true, advierte la importancia de resguardar su canal de WhatsApp corporativo ante suplantaciones a clientes.
    - Revisa `identidad`:
      - Si `combolist_intelligence.leaked_samples_masked` tiene muestras o `compromised_employees > 0`, menciónalo claramente.
      - Si `github_code_leaks.github_leaks_count > 0`, alerta que existen referencias o código del dominio publicados en repositorios externos de GitHub.

    4. CLASIFICACIÓN LEGAL AUTOMÁTICA (LEY N° 21.663, 9 BÁSICOS ANCI Y LEY N° 21.719):
    - En `exposicion_regulatoria` y `estado_inventario_art8`, orienta a la empresa indicando por qué le aplica la Ley N° 21.663 (Servicios Esenciales o Proveedor de la Cadena de Suministro bajo el Artículo 8, alineado con los 9 Básicos de la ANCI) y por qué le aplica la Ley N° 21.719 (protección de datos de clientes/pacientes y ubicación física del servidor).

    5. FORMATO IMPECABLE EN LAS MINUTAS PARA PROVEEDORES (`comandos_remediacion_ti`):
    - Clasifica cada tarjeta según a quién debe enviarla el dueño: 'Proveedor de Hosting / DNS', 'Proveedor de Servidor / Cloud', 'Desarrollador / Programador Web', o 'Equipo Interno TI / Gerencia'.
    - En `comando_o_script_sugerido`, redacta un mensaje cordial, claro y bien espaciado que empiece con "ESTIMADO PROVEEDOR..." o "ESTIMADO PROGRAMADOR WEB...". Deja SIEMPRE un espacio en blanco antes y después de cualquier paréntesis o comilla. Usa siempre el dominio exacto auditado.
    """

    prompt = f"""
    Analiza la siguiente evidencia técnica recolectada por SentinelRecon v2.3 sobre la empresa auditada:
    {json.dumps(scan_data, indent=2, ensure_ascii=False)}

    Genera el informe ejecutivo estructurado en español, traducido a lenguaje claro de negocio para el dueño o gerente de la empresa, respaldado por la evidencia técnica recolectada.
    """

    response = client.models.generate_content(
        model=MODELO_GEMINI,
        contents=prompt,
        config=types.GenerateContentConfig(
            system_instruction=system_instruction,
            response_mime_type="application/json",
            response_schema=EASMExecutiveReport,
            temperature=0.2,
        ),
    )

    raw_report = json.loads(response.text or "{}")
    return _enforce_deterministic_coverage_and_clean_typos(raw_report, scan_data)