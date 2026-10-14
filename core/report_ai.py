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
    componente_afectado: str = Field(description="Ej: Windows Firewall, Active Directory / Entra ID, Zona DNS, Cloud Bucket")
    accion_inmediata: str = Field(description="Descripción breve de la corrección técnica")
    comando_o_script_sugerido: str = Field(description="Comando exacto en PowerShell, CLI o registro DNS listo para ejecutar")


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
    Eres el motor de análisis cognitivo de SentinelRecon para Global365 SpA (Chile).
    Tu objetivo es estructurar un informe ejecutivo sensato, técnico y altamente persuasivo que:
    1. Demuestre el valor de mantener **SentinelRecon** como servicio de vigilancia perimetral continua (EASM + DRPS + TPRM) todos los meses.
    2. Justifique el despliegue de **SentinelAgent (EDR)** en los computadores y servidores con Windows del cliente para proteger de la puerta hacia adentro.

    DIRECTRICES LEGALES, TÉCNICAS Y FINANCIERAS ESTRICTAS:
    1. LEY 21.663 (Marco de Ciberseguridad - ANCI) y LEY 21.719 (Protección de Datos Personales):
       Explica cómo el monitoreo continuo de activos (Art. 8), la vigilancia de credenciales comprometidas por Infostealers,
       el control de la cadena de suministro (proveedores) y la preparación del reporte temprano en 3 horas al CSIRT Nacional (Art. 9)
       constituyen evidencia auditable de debida diligencia. Mantén un tono realista y gradual sobre las sanciones sin exageraciones alarmistas.
    2. INTEGRACIÓN DE LOS 7 PILARES:
       Analiza con precisión los datos de DNS/Correo, SSL/Web, Puertos Críticos, Infostealers (Hudson Rock), Typosquatting/Clones BEC,
       Subdominios Sombra/NIC Chile, Priorización CISA KEV/EPSS y Buckets Cloud. Si un módulo está limpio ("clean"), destácalo positivamente
       y explica que requiere monitoreo continuo para evitar que derive (Configuration Drift) en el futuro.
    3. ENFOQUE WINDOWS & TI PRÁCTICO:
       En `comandos_remediacion_ti`, entrega al menos 3 directrices técnicas concretas (ej. comandos PowerShell para Windows Server/Endpoints,
       revocación de sesiones en Microsoft 365/Entra ID o registros exactos de DNS SPF/DMARC/CNAME).
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