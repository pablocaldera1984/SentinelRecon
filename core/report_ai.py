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
    impacto_operacional: str = Field(description="Explicación clara y sin tecnicismos de cómo las brechas detectadas pueden interrumpir la operación diaria (caída de la página web, bloqueo de correos o secuestro de información).")
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
    diagnostico_shadow_dns_nic: str = Field(description="Explicación clara del proveedor de hosting detectado, país donde se guardan los datos (Ley 21.719), vigencia en NIC Chile y subdominios o paneles olvidados por ex-proveedores (cpanel, webmail, dev, test).")
    diagnostico_kev_epss_cloud: str = Field(description="Explicación clara de las fallas sin actualizar en el servidor web (Shodan/KEV/Fechas EOL), salud del código web (PHP/Scripts/Pagos Webpay/Metadatos PDF), listas negras de correo y bases de datos en la nube.")
    justificacion_monitoreo_continuo: str = Field(description="Por qué es vital que SentinelRecon vigile automáticamente la empresa todas las semanas.")


class TechnicalRemediationCommand(BaseModel):
    responsable_ejecucion: str = Field(description="Destinatario claro: 'Proveedor de Hosting / DNS', 'Proveedor de Servidor / Cloud', 'Desarrollador / Programador Web', o 'Equipo Interno TI / Gerencia'")
    componente_afectado: str = Field(description="Ej: 'Configuración de Correos del Dominio', 'Servidor de la Página Web', 'Código Fuente de la Página Web', 'Computadores de la Oficina'")
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


def generate_executive_analysis(scan_data: Dict[str, Any]) -> Dict[str, Any]:
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        raise ValueError("No se encontró GEMINI_API_KEY configurada.")

    client = genai.Client(api_key=api_key)

    system_instruction = """
    Eres el Consultor Ejecutivo Principal de Ciberseguridad de Global365 SpA (Chile) operando el motor SentinelRecon v2.2.
    Tu lector principal NO es un ingeniero informático: es el DUEÑO DE LA EMPRESA o GERENTE GENERAL de una organización que no tiene departamento de TI experto.
    Tu objetivo es que el gerente entienda en una sola lectura rápida qué riesgos reales corre su negocio hoy, con qué pruebas concretas contamos y qué mensajes debe enviarle a su informático o proveedor de hosting para solucionarlo.

    REGLAS DE ORO DE REDACCIÓN Y TONO COMERCIAL:
    1. PROHIBIDO INVENTAR MULTAS EN DINERO O CIFRAS MILLONARIAS:
    - En `impacto_financiero_estimado` y en todo el informe está ESTRICTAMENTE PROHIBIDO mencionar montos en pesos (CLP), dólares (USD) o UTM.
    - Enfoca el riesgo económico en situaciones reales de negocio: desvío de pagos de facturas por correos falsificados (fraude BEC), pérdida de clientes o pacientes por caída de la página web, bloqueo de correos corporativos por caer en listas negras de Spam, y costos de emergencia por secuestro de datos.

    2. LENGUAJE 100% CLARO EN RESÚMENES Y HALLAZGOS (TRADUCTOR DE NEGOCIO):
    - En `hallazgos_prioritarios`, redacta el título (`vector`) y la explicación (`explicacion_tecnica`) en español cotidiano y directo, explicando el impacto práctico para la empresa.
    - Explica el concepto en simple (para qué sirve el programa vencido o el puerto abierto) y pon el dato técnico o código CVE entre paréntesis como evidencia pericial.

    3. CORRELACIÓN PROFUNDA DE LAS NUEVAS SONDAS AVANZADAS v2.2:
    - Revisa `web.code_security_audit`:
      * Si `eol_software_detected` o `outdated_js_libraries` tienen elementos, destaca explícitamente qué componente está vencido, en qué año venció y para qué sirve (ej. formularios, servidor web o cifrado).
      * Si `ecommerce_magecart_risk.magecart_skimming_risk` es true, alerta el riesgo sobre su pasarela de pagos o carrito web.
      * Si `public_documents_metadata.exposed_authors_or_users` tiene nombres de usuarios o software extraídos de archivos PDF públicos, menciónalo como "Fuga de Identidad Interna en Documentos Públicos".
      * Si `whatsapp_impersonation_surface.has_whatsapp_widget` es true, advierte la importancia de resguardar su canal de WhatsApp corporativo ante suplantaciones a clientes.
    - Revisa `identidad`:
      * Si `combolist_intelligence.leaked_samples_masked` tiene muestras o `compromised_employees > 0`, menciónalo claramente.
      * Si `github_code_leaks.github_leaks_count > 0`, alerta que existen referencias o código del dominio publicados en repositorios externos de GitHub.
    - Revisa `shadow_dns.exposed_admin_or_dev_portals`:
      * Si detecta paneles como `cpanel.`, `webmail.`, `dev.`, `test.` o `admin.`, alerta sobre accesos administrativos o ambientes de prueba olvidados expuestos a internet.

    4. CLASIFICACIÓN LEGAL AUTOMÁTICA (LEY N° 21.663 Y LEY N° 21.719):
    - En `exposicion_regulatoria` y `estado_inventario_art8`, orienta a la empresa indicando por qué le aplica la Ley N° 21.663 (si es del rubro salud, energía, transporte, finanzas o telecomunicaciones califica en el marco de Servicios Esenciales; y si es una empresa B2B de servicios o comercio, está obligada como Proveedor de la Cadena de Suministro bajo el Artículo 8) y por qué le aplica la Ley N° 21.719 (protección de datos de clientes/pacientes y ubicación física del servidor).

    5. FORMATO IMPECABLE EN LAS MINUTAS PARA PROVEEDORES (`comandos_remediacion_ti`):
    - Clasifica cada tarjeta según a quién debe enviarla el dueño: 'Proveedor de Hosting / DNS', 'Proveedor de Servidor / Cloud', 'Desarrollador / Programador Web', o 'Equipo Interno TI / Gerencia'.
    - En `comando_o_script_sugerido`, redacta un mensaje cordial, claro y bien espaciado que empiece con "ESTIMADO PROVEEDOR..." o "ESTIMADO PROGRAMADOR WEB...". Deja SIEMPRE un espacio en blanco antes y después de cualquier paréntesis o comilla. Usa siempre el dominio exacto auditado.
    """

    prompt = f"""
    Analiza la siguiente evidencia técnica recolectada por SentinelRecon v2.2 sobre la empresa auditada:
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

    return json.loads(response.text)