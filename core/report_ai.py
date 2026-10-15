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
    impacto_financiero_estimado: str = Field(description="Costos proyectados realistas de rescate, fraude BEC, contingencia u horas no operativas")
    impacto_operacional: str = Field(description="Afectación a la continuidad operacional del negocio")
    exposicion_regulatoria: str = Field(description="Estándar Ley 21.663 ANCI, Ley 21.719 (Datos) y Ley 21.459 delimitado con realismo al tipo de entidad")


class PriorityFinding(BaseModel):
    vector: str
    criticidad: str
    puerto_servicio: str
    evidencia_tecnica: str
    explicacion_tecnica: str


class EDRAction(BaseModel):
    modulo_edr: str = Field(description="Módulo específico de SentinelAgent que interviene en el PC/Servidor Windows")
    control_compensatorio: str = Field(description="Acción que ejecuta el agente en el host")
    mitigacion_vector_perimetral: str = Field(description="Cómo neutraliza el riesgo detectado por fuera (incluyendo Infostealers y accesos RDP/SMB)")


class EDRPrescription(BaseModel):
    necesidad_defensa_profundidad: str
    acciones_inmediatas_edr: List[EDRAction]
    argumentario_cierre_comercial: str


class DRPSPersistenceInsights(BaseModel):
    diagnostico_infostealers_identidad: str = Field(description="Análisis de credenciales/sesiones comprometidas en Hudson Rock y riesgo en equipos Windows")
    diagnostico_typosquatting_bec: str = Field(description="Análisis de dominios gemelos detectados con web o correo MX activo para fraude BEC")
    diagnostico_shadow_dns_nic: str = Field(description="Estado de subdominios sombra en CT Logs, CNAMEs huérfanos y vigencia en NIC Chile")
    diagnostico_kev_epss_cloud: str = Field(description="Evaluación de vulnerabilidades CISA KEV / FIRST EPSS y exposición de Buckets Cloud")
    justificacion_monitoreo_continuo: str = Field(description="Por qué la empresa debe mantener SentinelRecon vigilando cambios (Drift) cada semana/mes")


class TechnicalRemediationCommand(BaseModel):
    responsable_ejecucion: str = Field(description="Ej: 'Proveedor de Hosting / Webmaster', 'Proveedor de Servidor / Cloud', 'Equipo Interno TI / Gerencia'")
    componente_afectado: str = Field(description="Ej: Zona DNS del Dominio, Servidor Web Nginx, Firewall Perimetral, Endpoint Windows")
    accion_inmediata: str = Field(description="Breve requerimiento formal para la solicitud o ticket")
    comando_o_script_sugerido: str = Field(description="Texto exacto del requerimiento para el ticket de soporte o comando técnico listo para copiar")


class ANCIGovernancePack(BaseModel):
    estado_inventario_art8: str = Field(description="Dictamen sobre el cumplimiento de inventario continuo y gestión de parches (Art. 8 Ley 21.663)")
    borrador_alerta_temprana_3h_csirt: str = Field(description="Plantilla técnica pre-llenada lista para reportar al CSIRT Nacional en < 3 horas (Art. 9) en caso de incidente activo")
    directriz_cadena_suministro_tprm: str = Field(description="Recomendación para auditar y exigir higiene perimetral a los proveedores críticos del cliente")


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
    Eres el motor de análisis cognitivo pericial de SentinelRecon para Global365 SpA (Chile).
    Tu objetivo es estructurar un informe ejecutivo sensato, rigurosamente técnico, objetivo y legalmente prudente que:
    1. Demuestre el valor de mantener SentinelRecon como servicio de vigilancia perimetral continua (EASM + DRPS + TPRM) mes a mes.
    2. Justifique el despliegue de SentinelAgent (EDR) en las estaciones de trabajo y servidores Windows del cliente para proteger desde adentro.

    DIRECTRICES LEGALES, TÉCNICAS Y OPERATIVAS:
    1. DISTINCIÓN DE RESPONSABILIDADES Y GESTIÓN DE PROVEEDORES (TPRM - LEY 21.663):
       Muchas empresas delegan su web y correos en proveedores de hosting o desarrolladores externos.
       Explica con claridad que aunque la configuración técnica la ejecuta el proveedor de hosting o webmaster,
       la RESPONSABILIDAD LEGAL y el riesgo ante clientes y la ANCI recae siempre en la empresa contratante (Art. 8 Ley 21.663).
       En `comandos_remediacion_ti`, especifica claramente en `responsable_ejecucion` quién debe ejecutar la acción:
       - 'Proveedor de Hosting / DNS' (ej. para agregar registros SPF y DMARC).
       - 'Proveedor de Servidor / Cloud' (ej. para cerrar o restringir el puerto SSH 22).
       - 'Desarrollador Web' (ej. para configurar cabeceras HSTS/CSP en Nginx).
       - 'Equipo Interno TI / Gerencia' (ej. para desplegar SentinelAgent en computadores de oficina).
       En `comando_o_script_sugerido`, redacta las solicitudes en formato de MINUTA DE TICKET DE SOPORTE clara y directa que el cliente pueda copiar y pegar a su proveedor.

    2. DOMINIOS CERCANOS Y HOMÓGRAFOS (PRUDENCIA LEGAL):
       Al analizar dominios similares o typosquatting, NUNCA acuses categóricamente de 'plagio', 'estafa activa' ni 'delincuencia',
       a menos que exista evidencia probada de suplantación visual explícita de marca.
       Clasifícalos técnicamente como: 'Superficie de Confusión Tipográfica y Riesgo de Desvío de Comunicaciones (Lookalike Domain)'.
       Explica que, aun cuando pertenezca a otra entidad por alcance de nombre, la existencia de correo activo (MX) en el dominio cercano
       sumada a la ausencia de SPF/DMARC en el cliente auditado genera un riesgo crítico de fuga involuntaria de información médica o sensible (Ley 21.719)
       y confusión en facturación o pagos. Recomienda DMARC en modo reject para blindar el canal propio.

    3. LEY 21.663 (ANCI) Y LEY 21.719 (PROTECCIÓN DE DATOS):
       Detalla cómo el inventario continuo de activos (Art. 8), la trazabilidad perimetral y la preparación de
       pre-alertas en < 3 horas ante el CSIRT Nacional (Art. 9) constituyen debida diligencia comprobable ante la autoridad.

    4. INTEGRACIÓN DE LOS 7 PILARES:
       Analiza con precisión DNS/Correo, SSL/Web, Puertos Críticos, Infostealers (Hudson Rock), Dominios Cercanos/BEC,
       Subdominios Sombra/NIC Chile, CISA KEV/EPSS y Buckets Cloud. Cita datos exactos de la telemetría (IPs, banner Nginx, días de SSL y NIC Chile).
    """

    prompt = f"""
    Analiza la siguiente telemetría perimetral e inteligencia DRPS recolectada por SentinelRecon:
    {json.dumps(scan_data, indent=2, ensure_ascii=False)}

    Genera el diagnóstico estructurado en español completando con rigor técnico y visión comercial B2B el esquema JSON.
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