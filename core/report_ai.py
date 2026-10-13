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
    impacto_financiero_estimado: str = Field(description="Costos proyectados realistas de rescate, contingencia u horas no operativas")
    impacto_operacional: str = Field(description="Afectación a la continuidad operacional del negocio")
    exposicion_regulatoria: str = Field(description="Estándar Ley 21.663 ANCI y Ley 21.459 delimitado al tipo de entidad")

class PriorityFinding(BaseModel):
    vector: str
    criticidad: str
    puerto_servicio: str
    evidencia_tecnica: str
    explicacion_tecnica: str

class EDRAction(BaseModel):
    modulo_edr: str = Field(description="Módulo específico de SentinelAgent que interviene")
    control_compensatorio: str = Field(description="Acción que ejecuta el agente en el host")
    mitigacion_vector_perimetral: str = Field(description="Cómo neutraliza el riesgo detectado por fuera")

class EDRPrescription(BaseModel):
    necesidad_defensa_profundidad: str
    acciones_inmediatas_edr: List[EDRAction]
    argumentario_cierre_comercial: str

class EASMExecutiveReport(BaseModel):
    resumen_ejecutivo: ExecutiveSummary
    hallazgos_prioritarios: List[PriorityFinding]
    prescripcion_endpoint_edr: EDRPrescription


def generate_executive_analysis(scan_data: Dict[str, Any]) -> Dict[str, Any]:
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        raise ValueError("No se encontró GEMINI_API_KEY configurada.")

    client = genai.Client(api_key=api_key)

    system_instruction = """
    Eres el motor de análisis cognitivo de SentinelRecon para Global365.
    Tu objetivo es estructurar un informe ejecutivo sensato, técnico y convincente que justifique 
    el despliegue de SentinelAgent (EDR) en los computadores o servidores del cliente.

    DIRECTRICES LEGALES Y FINANCIERAS ESTRICTAS:
    1. LEY 21.663 (Ciberseguridad): Aplica a organismos del Estado y a entidades privadas que presten Servicios Esenciales (SE) 
       u Operadores de Importancia Vital (OIV). Para empresas privadas generales, actúa como estándar de debida diligencia 
       y riesgo de cadena de suministro. NO menciones multas desmedidas de 40.000 UTM como una certeza absoluta; habla de marcos 
       sancionatorios graduales y la exigencia de reporte de incidentes en 3 horas ante la ANCI si califican como SE/OIV.
    2. LEY 21.459 (Delitos Informáticos): Explica cómo un perímetro vulnerable facilita accesos no autorizados e intrusiones en estaciones.
    3. IMPACTO FINANCIERO: Exprésalo de forma creíble (pérdida de horas de trabajo, costo de remediación, riesgo de fraude por suplantación/BEC), 
       evitando cifras astronómicas sin fundamento para una empresa mediana.
    """

    prompt = f"""
    Analiza la siguiente telemetría perimetral:
    {json.dumps(scan_data, indent=2, ensure_ascii=False)}

    Genera el diagnóstico estructurado completando con rigor y mesura el esquema JSON.
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
