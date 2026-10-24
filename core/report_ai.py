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
    exposicion_regulatoria: str = Field(description="Estándar Ley 21.663 ANCI, Ley 21.719 (Soberanía y Flujo Transfronterizo de Datos) y Ley 21.459 delimitado con realismo al tipo de entidad")


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
    diagnostico_infostealers_identidad: str = Field(description="Análisis de credenciales/sesiones en Hudson Rock + Reconocimiento de Federación SSO (Microsoft Entra ID Tenant ID, Managed/Federated)")
    diagnostico_typosquatting_bec: str = Field(description="Análisis de dominios gemelos con web o correo MX activo para fraude BEC y verificación de clonación visual por Favicon (mmh3)")
    diagnostico_shadow_dns_nic: str = Field(description="Estado de subdominios sombra en CT Logs, CNAMEs huérfanos, vigencia en NIC Chile, ASN/BGP, Soberanía de Datos (Ley 21.719) y gobernanza CAA/MTA-STS/DNSSEC")
    diagnostico_kev_epss_cloud: str = Field(description="Evaluación de vulnerabilidades CISA KEV / FIRST EPSS, inteligencia pasiva Shodan InternetDB, radares Shadow AI y exposición de Buckets/Firebase Cloud")
    justificacion_monitoreo_continuo: str = Field(description="Por qué la empresa debe mantener SentinelRecon vigilando cambios (Drift) cada semana/mes")


class TechnicalRemediationCommand(BaseModel):
    responsable_ejecucion: str = Field(description="Ej: 'Proveedor de Hosting / Webmaster', 'Proveedor de Servidor / Cloud', 'Desarrollador Web', 'Equipo Interno TI / Gerencia'")
    componente_afectado: str = Field(description="Ej: Zona DNS del Dominio, Servidor Web Nginx, Firewall Perimetral, Endpoint Windows")
    accion_inmediata: str = Field(description="Breve requerimiento formal para la solicitud o ticket")
    comando_o_script_sugerido: str = Field(description="Texto exacto del requerimiento para el ticket de soporte o comando técnico listo para copiar")


class ANCIGovernancePack(BaseModel):
    estado_inventario_art8: str = Field(description="Dictamen sobre el cumplimiento de inventario continuo, soberanía de datos y gestión de parches (Art. 8 Ley 21.663)")
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
    Eres el motor de análisis cognitivo pericial de SentinelRecon v2.1 para Global365 SpA (Chile).
    Tu objetivo es estructurar un informe ejecutivo sensato, rigurosamente técnico, objetivo y legalmente prudente que:
    1. Demuestre el valor de mantener SentinelRecon como servicio de vigilancia perimetral continua (EASM + DRPS + TPRM) mes a mes.
    2. Justifique el despliegue de SentinelAgent (EDR) en las estaciones de trabajo y servidores Windows del cliente para proteger desde adentro.

    DIRECTRICES LEGALES, TÉCNICAS Y OPERATIVAS:
    1. DISTINCIÓN DE RESPONSABILIDADES Y GESTIÓN DE PROVEEDORES (TPRM - LEY 21.663):
       Muchas empresas delegan su web y correos en proveedores de hosting o desarrolladores externos.
       Explica con claridad que aunque la configuración técnica la ejecuta el proveedor de hosting o webmaster,
       la RESPONSABILIDAD LEGAL y el riesgo ante clientes y la ANCI recae siempre en la empresa contratante (Art. 8 Ley 21.663).
       En `comandos_remediacion_ti`, especifica claramente en `responsable_ejecucion` quién debe ejecutar la acción:
       - 'Proveedor de Hosting / DNS' (ej. para agregar registros SPF, DMARC, CAA o MTA-STS).
       - 'Proveedor de Servidor / Cloud' (ej. para cerrar o restringir puertos expuestos como SSH 22, RDP 3389, bases de datos o motores Shadow AI).
       - 'Desarrollador Web' (ej. para configurar cabeceras HSTS/CSP, ocultar archivos Swagger/OpenAPI o desactivar SourceMaps .js.map en producción).
       - 'Equipo Interno TI / Gerencia' (ej. para desplegar SentinelAgent en computadores de oficina y endurecer Microsoft Entra ID).
       En `comando_o_script_sugerido`, redacta las solicitudes en formato de MINUTA DE TICKET DE SOPORTE clara y directa que el cliente pueda copiar y pegar a su proveedor.

    2. DOMINIOS CERCANOS, HOMÓGRAFOS Y CLONACIÓN VISUAL (PRUDENCIA LEGAL):
       - Si `visual_phishing_clones_count > 0` (coincidencia exacta del hash criptográfico `favicon_mmh3`), alerta prioritariamente de una 'Clonación Visual Confirmada por Huella Criptográfica de Favicon'.
       - En todos los demás casos (`visual_favicon_match: false`), NUNCA acuses categóricamente de 'plagio', 'estafa activa' ni 'delincuencia'.
         Clasifícalos técnicamente como: 'Superficie de Confusión Tipográfica y Riesgo de Desvío de Comunicaciones (Lookalike Domain)'.
         Explica que, aun cuando pertenezca a otra entidad por alcance de nombre, la existencia de correo activo (MX) en el dominio cercano
         sumada a la ausencia de SPF/DMARC en el cliente auditado genera un riesgo crítico de fuga involuntaria de información médica o sensible (Ley 21.719)
         y confusión en facturación o pagos. Recomienda DMARC en modo reject para blindar el canal propio.

    3. LEY 21.663 (ANCI) Y ALERTA TEMPRANA:
       En `borrador_alerta_temprana_3h_csirt`, NO redactes como si el informe ya hubiera enviado nada al CSIRT.
       Redáctalo estrictamente como una plantilla preventiva de uso interno para el cliente:
       Ejemplo: '[BORRADOR DE CONTINGENCIA INTERNA - ACTIVAR SOLO EN CASO DE BRECHA O EXPLOTACIÓN ACTIVA] Al CSIRT Nacional: Se reporta incidente en mitigación sobre IP {ip}...'.
       Aclara que las vulnerabilidades preventivas corresponden a debida diligencia del Art. 8 y que el Art. 9 solo se activa si hay un incidente consumado.
       Asegúrate de que en `comandos_remediacion_ti` el dominio que aparezca en los scripts de DNS sea SIEMPRE el objetivo auditado exacto y nunca el dominio similar.

    4. INTEGRACIÓN PROFUNDA DE LOS 7 PILARES Y LAS NUEVAS SONDAS AVANZADAS (v2.1):
       - Identidad y Federación SSO: En `diagnostico_infostealers_identidad`, reporta los hallazgos de Hudson Rock Y ADEMÁS cita los datos de `corporate_sso_federation` (si utiliza Microsoft Entra ID / Azure AD, menciona el `tenant_id` exacto descubierto y si opera en modo `Managed` o `Federated`).
       - Soberanía de Datos (Ley 21.719), BGP/ASN y Gobernanza DNS: En `diagnostico_shadow_dns_nic` y `exposicion_regulatoria`, cita la IP, el proveedor autónomo (`asn`, `isp_org`) y el país físico del servidor (`country`). Si está alojado fuera de Chile (`hosted_in_chile: false`), advierte sobre el cumplimiento de transferencia internacional de datos bajo la Ley N° 21.719. Menciona además el estado de los registros `CAA` (control de emisión SSL), `MTA-STS` y `DNSSEC`.
       - Criptografía Post-Cuántica (PQC) y Exposición Web: Cita la versión exacta de TLS negociada (`tls_version`), la suite de cifrado (`cipher_suite`), si el transporte es `pqc_ready_transport` (TLS 1.3), y si `exposure_audit` detectó especificaciones Swagger/OpenAPI abiertas, referencias a SourceMaps (`.js.map`) o CORS permisivo.
       - KEV/EPSS, Shodan InternetDB, Shadow AI y Cloud/Firebase: Cita datos exactos de puertos abiertos, motores de IA expuestos (Ollama/vLLM/Qdrant), CVEs reportados por Shodan InternetDB cruzados con FIRST EPSS / CISA KEV, y estado de buckets S3/GCP/Azure y bases Firebase Realtime DB.
    """

    prompt = f"""
    Analiza la siguiente telemetría perimetral e inteligencia DRPS recolectada por SentinelRecon v2.1:
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