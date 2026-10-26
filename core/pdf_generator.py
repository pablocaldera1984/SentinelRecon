# core/pdf_generator.py
import datetime
from jinja2 import Template
from typing import Dict, Any, Optional

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>Reporte Ejecutivo EASM & DRPS - SentinelRecon v2.1</title>
    <style>
        @page { size: A4; margin: 10mm; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            color: #1e293b;
            background-color: #ffffff;
            margin: 0;
            padding: 14px;
            font-size: 11px;
            line-height: 1.4;
        }
        .avoid-cut {
            break-inside: avoid !important;
            page-break-inside: avoid !important;
        }
        .header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            border-bottom: 2px solid #0f172a;
            padding-bottom: 10px;
            margin-bottom: 12px;
        }
        .logo-title h1 {
            margin: 0;
            font-size: 22px;
            color: #0f172a;
            letter-spacing: -0.5px;
        }
        .logo-title span {
            color: #0284c7;
            font-weight: bold;
        }
        .meta-box {
            text-align: right;
            font-size: 10px;
            color: #64748b;
            max-width: 48%;
            word-break: break-word;
        }
        .grade-card {
            display: flex;
            background: #f8fafc;
            border: 1px solid #e2e8f0;
            border-radius: 8px;
            padding: 10px 12px;
            margin-bottom: 12px;
            align-items: center;
        }
        .grade-badge {
            font-size: 32px;
            font-weight: 800;
            width: 60px;
            height: 60px;
            line-height: 60px;
            text-align: center;
            border-radius: 8px;
            margin-right: 14px;
            color: #ffffff;
            flex-shrink: 0;
        }
        .grade-A { background-color: #16a34a; }
        .grade-B { background-color: #0284c7; }
        .grade-C { background-color: #eab308; }
        .grade-D { background-color: #f97316; }
        .grade-F { background-color: #dc2626; }
        .grade-info h3 {
            margin: 0 0 3px 0;
            font-size: 13.5px;
            color: #0f172a;
        }
        .grade-info p {
            margin: 0;
            color: #475569;
            font-size: 10.5px;
        }
        .section-title {
            font-size: 12px;
            font-weight: 700;
            color: #0f172a;
            border-left: 4px solid #0284c7;
            padding-left: 8px;
            margin: 14px 0 8px 0;
            text-transform: uppercase;
        }
        .summary-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 8px;
            margin-bottom: 10px;
        }
        .summary-card {
            background: #f8fafc;
            padding: 9px 10px;
            border-radius: 6px;
            border: 1px solid #e2e8f0;
        }
        .summary-card h4 {
            margin: 0 0 4px 0;
            color: #0f172a;
            font-size: 10.5px;
        }
        .summary-card p {
            margin: 0;
            font-size: 9.8px;
            color: #334155;
        }
        .badge-ok { background: #dcfce7; color: #166534; padding: 2px 6px; border-radius: 4px; font-weight: bold; font-size: 8.5px; text-transform: uppercase; }
        .badge-warn { background: #fef3c7; color: #92400e; padding: 2px 6px; border-radius: 4px; font-weight: bold; font-size: 8.5px; text-transform: uppercase; }
        .badge-crit { background: #fee2e2; color: #991b1b; padding: 2px 6px; border-radius: 4px; font-weight: bold; font-size: 8.5px; text-transform: uppercase; }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 10px;
        }
        tr {
            break-inside: avoid !important;
            page-break-inside: avoid !important;
        }
        th, td {
            padding: 5px 7px;
            text-align: left;
            border-bottom: 1px solid #e2e8f0;
            font-size: 9.8px;
            vertical-align: top;
        }
        th {
            background-color: #0f172a;
            color: #ffffff;
            font-weight: 600;
        }
        code {
            background: #e2e8f0;
            padding: 1.5px 4px;
            border-radius: 4px;
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
            font-size: 9px;
            color: #0f172a;
            word-break: break-all;
        }
        .cmd-box {
            background: #0f172a;
            color: #38bdf8;
            padding: 6px 8px;
            border-radius: 4px;
            font-family: monospace;
            font-size: 8.5px;
            display: block;
            white-space: pre-wrap;
            word-break: break-all;
            line-height: 1.4;
        }
        .badge-provider {
            display: inline-block;
            background: #e0f2fe;
            color: #0369a1;
            padding: 3px 6px;
            border-radius: 4px;
            font-weight: bold;
            font-size: 8.8px;
        }
        .crit-CRÍTICA, .crit-CRITICA, .crit-CRITICAL, .crit-critical { color: #dc2626; font-weight: bold; }
        .crit-ALTA, .crit-high, .crit-warning { color: #f97316; font-weight: bold; }
        .crit-MEDIA, .crit-medium { color: #d97706; font-weight: bold; }
        .crit-BAJA, .crit-clean { color: #16a34a; font-weight: bold; }
        .tprm-banner {
            background: #eff6ff;
            border: 1px solid #bfdbfe;
            border-left: 4px solid #0284c7;
            padding: 8px 10px;
            border-radius: 6px;
            margin-bottom: 8px;
            font-size: 9.8px;
            color: #1e3a8a;
        }
        .anci-box {
            background: #fffbeb;
            border: 1px solid #fde68a;
            border-left: 4px solid #d97706;
            padding: 9px 11px;
            border-radius: 6px;
            margin-bottom: 10px;
            font-size: 9.8px;
        }
        .anci-box h4 {
            margin: 0 0 4px 0;
            color: #92400e;
            font-size: 10.5px;
        }
        .seal-banner {
            display: flex;
            justify-content: space-between;
            align-items: center;
            background: #f0f9ff;
            border: 1px solid #bae6fd;
            padding: 8px 11px;
            border-radius: 6px;
            margin-top: 10px;
            font-size: 9.8px;
        }
        .footer-cta {
            background: #0f172a;
            color: #ffffff;
            padding: 10px;
            border-radius: 8px;
            margin-top: 12px;
            text-align: center;
        }
        .footer-cta h3 {
            margin: 0 0 3px 0;
            color: #38bdf8;
            font-size: 12.5px;
        }
        .footer-cta p {
            margin: 0;
            font-size: 9.5px;
            color: #cbd5e1;
        }
    </style>
</head>
<body>
    <div class="header avoid-cut">
        <div class="logo-title">
            <h1>SENTINEL<span>RECON</span> <small style="font-size:12px; color:#0284c7;">v2.1</small></h1>
            <small>EASM, Digital Risk Protection (DRPS), Soberanía de Datos & Cumplimiento ANCI | Global365</small>
        </div>
        <div class="meta-box">
            <strong>Objetivo Auditado:</strong> {{ target }}<br>
            <strong>Fecha de Emisión:</strong> {{ fecha }}<br>
            <strong>Marco Normativo:</strong> Ley N° 21.663 (ANCI) / Ley N° 21.719 (Datos) / Ley N° 21.459
        </div>
    </div>

    <div class="grade-card avoid-cut">
        <div class="grade-badge grade-{{ reporte.resumen_ejecutivo.calificacion_postura }}">
            {{ reporte.resumen_ejecutivo.calificacion_postura }}
        </div>
        <div class="grade-info">
            <h3>Puntaje de Postura Perimetral y Riesgo Digital: {{ reporte.resumen_ejecutivo.puntaje_global }} / 100</h3>
            <p>{{ reporte.prescripcion_endpoint_edr.necesidad_defensa_profundidad }}</p>
        </div>
    </div>

    <div class="section-title avoid-cut">1. Impacto de Negocio y Exposición Regulatoria (Chile)</div>
    <div class="summary-grid avoid-cut">
        <div class="summary-card">
            <h4>Impacto Financiero y Operacional Proyectado</h4>
            <p><strong>Financiero:</strong> {{ reporte.resumen_ejecutivo.impacto_financiero_estimado }}</p>
            <p style="margin-top:4px;"><strong>Operacional:</strong> {{ reporte.resumen_ejecutivo.impacto_operacional }}</p>
        </div>
        <div class="summary-card">
            <h4>Exposición Legal (Ley 21.663 ANCI & Ley 21.719 Datos)</h4>
            <p>{{ reporte.resumen_ejecutivo.exposicion_regulatoria }}</p>
        </div>
    </div>

    <div class="section-title">2. Hallazgos Perimetrales y de Riesgo Digital Prioritarios</div>
    <table>
        <thead>
            <tr>
                <th style="width: 28%;">Vector de Amenaza</th>
                <th style="width: 12%;">Criticidad</th>
                <th style="width: 18%;">Interfaz / Activo</th>
                <th style="width: 42%;">Evidencia y Detalle Pericial</th>
            </tr>
        </thead>
        <tbody>
            {% for h in reporte.hallazgos_prioritarios %}
            <tr>
                <td><strong>{{ h.vector }}</strong></td>
                <td class="crit-{{ h.criticidad }}">{{ h.criticidad }}</td>
                <td>{{ h.puerto_servicio }}</td>
                <td>
                    <code>{{ h.evidencia_tecnica }}</code><br>
                    <span style="color:#475569; font-size:9.2px;">{{ h.explicacion_tecnica }}</span>
                </td>
            </tr>
            {% endfor %}
        </tbody>
    </table>

    <!-- NUEVA SECCIÓN PROTAGONISTA: LOS 8 PUNTOS DE INTELIGENCIA AVANZADA v2.1 -->
    {% if telemetria %}
    {% set asn = telemetria.dns.asn_sovereignty if telemetria.dns and telemetria.dns.asn_sovereignty else {} %}
    {% set gov = telemetria.dns.governance if telemetria.dns and telemetria.dns.governance else {} %}
    {% set ssl = telemetria.web.ssl_certificate if telemetria.web and telemetria.web.ssl_certificate else {} %}
    {% set exp = telemetria.web.exposure_audit if telemetria.web and telemetria.web.exposure_audit else {} %}
    {% set sso = telemetria.identidad.corporate_sso_federation if telemetria.identidad and telemetria.identidad.corporate_sso_federation else {} %}
    {% set sho = telemetria.puertos.passive_internetdb_intel if telemetria.puertos and telemetria.puertos.passive_internetdb_intel else {} %}
    <div class="section-title avoid-cut">3. Matriz de Controles Avanzados v2.1 (Soberanía, PQC, Entra ID, Shodan & Shadow AI)</div>
    <div class="summary-grid avoid-cut">
        <div class="summary-card">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:3px;">
                <h4>1. Soberanía de Datos & BGP/ASN (Ley 21.719)</h4>
                {% if asn.get('hosted_in_chile') %}
                    <span class="badge-ok">Alojamiento Local CL</span>
                {% else %}
                    <span class="badge-warn">Flujo Transfronterizo</span>
                {% endif %}
            </div>
            <p>
                IP: <code>{{ asn.get('primary_ip') or 'N/D' }}</code> | Proveedor: <strong>{{ asn.get('isp_org') or 'Cloud' }}</strong> ({{ asn.get('asn') or 'ASN' }}) en <strong>{{ asn.get('country') or 'Exterior' }}</strong>.
            </p>
        </div>

        <div class="summary-card">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:3px;">
                <h4>2. Criptografía Post-Cuántica (PQC) & TLS</h4>
                {% if ssl.get('pqc_ready_transport') %}
                    <span class="badge-ok">TLS 1.3 PQC Ready</span>
                {% else %}
                    <span class="badge-warn">{{ ssl.get('tls_version') or 'TLS 1.2' }}</span>
                {% endif %}
            </div>
            <p>
                Versión: <strong>{{ ssl.get('tls_version') or 'TLS' }}</strong> | Suite: <code>{{ ssl.get('cipher_suite') or 'Estándar' }}</code> ({{ ssl.get('days_until_expiry') }} días restantes).
            </p>
        </div>

        <div class="summary-card">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:3px;">
                <h4>3. Gobernanza DNS (CAA / MTA-STS / DNSSEC)</h4>
                {% if gov.get('caa_configured') and gov.get('dnssec_enabled') %}
                    <span class="badge-ok">Blindado</span>
                {% else %}
                    <span class="badge-crit">Incompleto</span>
                {% endif %}
            </div>
            <p>
                Control Emisión SSL (CAA): <strong>{{ 'Activo' if gov.get('caa_configured') else 'Ausente' }}</strong> |
                MTA-STS: <strong>{{ 'Activo' if gov.get('mta_sts_configured') else 'Ausente' }}</strong> |
                DNSSEC: <strong>{{ 'Activo' if gov.get('dnssec_enabled') else 'Inactivo' }}</strong>.
            </p>
        </div>

        <div class="summary-card">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:3px;">
                <h4>4. Identidad Federada SSO (Microsoft Entra ID)</h4>
                {% if sso.get('uses_entra_id') %}
                    <span class="badge-ok">{{ sso.get('name_space_type') or 'Entra ID' }}</span>
                {% else %}
                    <span class="badge-warn">Sin Federación M365</span>
                {% endif %}
            </div>
            <p>
                {% if sso.get('uses_entra_id') %}
                    Tenant ID: <code>{{ sso.get('tenant_id') }}</code> (Región: {{ sso.get('tenant_region') or 'Global' }}).
                {% else %}
                    Autenticación gestionada fuera de Microsoft Entra ID / sin federación OpenID pública.
                {% endif %}
            </p>
        </div>

        <div class="summary-card">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:3px;">
                <h4>5. Fusión Shodan InternetDB & CISA KEV</h4>
                {% if (sho.get('vulns') or []) | length == 0 %}
                    <span class="badge-ok">0 CVEs Shodan</span>
                {% else %}
                    <span class="badge-crit">{{ (sho.get('vulns') or []) | length }} CVEs Detectados</span>
                {% endif %}
            </div>
            <p>
                Puertos Shodan: <code>{{ (sho.get('shodan_ports') or []) | join(', ') or 'Ninguno' }}</code> |
                CVEs: <strong>{{ (sho.get('vulns') or [])[:4] | join(', ') or 'Limpio' }}</strong>.
            </p>
        </div>

        <div class="summary-card">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:3px;">
                <h4>6. Clonación Visual Phishing (Favicon mmh3)</h4>
                {% if (telemetria.typosquatting.visual_phishing_clones_count or 0) == 0 %}
                    <span class="badge-ok">0 Clones Visuales</span>
                {% else %}
                    <span class="badge-crit">Clon Visual Confirmado</span>
                {% endif %}
            </div>
            <p>
                Hash Favicon: <code>{{ telemetria.web.http_headers.favicon_mmh3 if telemetria.web and telemetria.web.http_headers else 'N/D' }}</code> |
                Lookalikes con MX: <strong>{{ telemetria.typosquatting.mail_ready_clones_count if telemetria.typosquatting else 0 }}</strong>.
            </p>
        </div>

        <div class="summary-card">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:3px;">
                <h4>7. Exposición API (Swagger / SourceMaps)</h4>
                {% if not exp.get('openapi_swagger_exposed') and not exp.get('sourcemaps_referenced') %}
                    <span class="badge-ok">Protegido</span>
                {% else %}
                    <span class="badge-crit">Metadatos Expuestos</span>
                {% endif %}
            </div>
            <p>
                Swagger/OpenAPI: <strong>{{ 'Expuesto' if exp.get('openapi_swagger_exposed') else 'Oculto' }}</strong> |
                SourceMaps (<code>.js.map</code>): <strong>{{ 'Expuestos' if exp.get('sourcemaps_referenced') else 'Ocultos' }}</strong>.
            </p>
        </div>

        <div class="summary-card">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:3px;">
                <h4>8. Radar Shadow AI (Ollama/vLLM) & Cloud</h4>
                {% if (telemetria.puertos.shadow_ai_exposed_count or 0) == 0 and (telemetria.cloud_leaks.public_leaking_buckets_count or 0) == 0 %}
                    <span class="badge-ok">Perímetro Limpio</span>
                {% else %}
                    <span class="badge-crit">Exposición Activa</span>
                {% endif %}
            </div>
            <p>
                Motores IA abiertos: <strong>{{ telemetria.puertos.shadow_ai_exposed_count if telemetria.puertos else 0 }}</strong> |
                Buckets S3/GCP/Azure/Firebase abiertos: <strong>{{ telemetria.cloud_leaks.public_leaking_buckets_count if telemetria.cloud_leaks else 0 }}</strong>.
            </p>
        </div>
    </div>
    {% endif %}

    {% if reporte.inteligencia_drps_persistencia %}
    <div class="section-title avoid-cut">4. Diagnóstico Cognitivo DRPS: Identidades, Marca, Shadow IT y KEV</div>
    <div class="summary-grid avoid-cut">
        <div class="summary-card">
            <h4>Radar Infostealers (Hudson Rock) & Federación SSO</h4>
            <p>{{ reporte.inteligencia_drps_persistencia.diagnostico_infostealers_identidad }}</p>
        </div>
        <div class="summary-card">
            <h4>Escudo Anti-Suplantación BEC y Clonación Visual</h4>
            <p>{{ reporte.inteligencia_drps_persistencia.diagnostico_typosquatting_bec }}</p>
        </div>
        <div class="summary-card">
            <h4>Superficie Sombra, Soberanía BGP/ASN y Vigencia NIC.cl</h4>
            <p>{{ reporte.inteligencia_drps_persistencia.diagnostico_shadow_dns_nic }}</p>
        </div>
        <div class="summary-card">
            <h4>Priorización CISA KEV / EPSS, Shodan InternetDB & Cloud</h4>
            <p>{{ reporte.inteligencia_drps_persistencia.diagnostico_kev_epss_cloud }}</p>
        </div>
    </div>
    {% endif %}

    <div class="section-title">5. Matriz de Responsabilidades y Minutas para Proveedores (TPRM)</div>
    <div class="tprm-banner avoid-cut">
        <strong>Modelo de Responsabilidad Compartida (Art. 8 Ley N° 21.663):</strong>
        A continuación se entregan las minutas técnicas listas para enviar como ticket de soporte a sus proveedores externos.
    </div>

    {% if reporte.comandos_remediacion_ti %}
    <table>
        <thead>
            <tr>
                <th style="width: 24%;">Responsable</th>
                <th style="width: 26%;">Componente / Acción</th>
                <th style="width: 50%;">Minuta Técnica para Ticket de Soporte / Comando</th>
            </tr>
        </thead>
        <tbody>
            {% for c in reporte.comandos_remediacion_ti %}
            <tr>
                <td><span class="badge-provider">{{ c.responsable_ejecucion or 'Proveedor Externo' }}</span></td>
                <td>
                    <strong>{{ c.componente_afectado }}</strong><br>
                    <span style="color:#64748b; font-size:9px;">{{ c.accion_inmediata }}</span>
                </td>
                <td><span class="cmd-box">{{ c.comando_o_script_sugerido }}</span></td>
            </tr>
            {% endfor %}
        </tbody>
    </table>
    {% endif %}

    {% if reporte.gobernanza_anci_ley21663 %}
    <div class="section-title avoid-cut">6. Gobernanza Ley N° 21.663 (ANCI) y Pre-Alerta CSIRT (≤ 3 Horas)</div>
    <div class="anci-box avoid-cut">
        <h4>Dictamen de Inventario Continuo (Art. 8), Soberanía de Datos (Ley 21.719) y TPRM</h4>
        <p><strong>Cumplimiento Art. 8:</strong> {{ reporte.gobernanza_anci_ley21663.estado_inventario_art8 }}</p>
        <p style="margin-top:4px;"><strong>Directriz Proveedores (TPRM):</strong> {{ reporte.gobernanza_anci_ley21663.directriz_cadena_suministro_tprm }}</p>
        <h4 style="margin-top:8px;">Plantilla Preventiva de Alerta Temprana CSIRT Nacional (Ventana Legal ≤ 3 Horas - Art. 9)</h4>
        <p><code>{{ reporte.gobernanza_anci_ley21663.borrador_alerta_temprana_3h_csirt }}</code></p>
    </div>
    {% endif %}

    <div class="section-title avoid-cut">7. Defensa en Profundidad: Despliegue de SentinelAgent (EDR) en PCs Windows</div>
    <table class="avoid-cut">
        <thead>
            <tr>
                <th style="width: 25%;">Módulo SentinelAgent</th>
                <th style="width: 40%;">Control Compensatorio en el Host Windows</th>
                <th style="width: 35%;">Mitigación de Brecha Perimetral / Identidad</th>
            </tr>
        </thead>
        <tbody>
            {% for a in reporte.prescripcion_endpoint_edr.acciones_inmediatas_edr %}
            <tr>
                <td><strong>{{ a.modulo_edr }}</strong></td>
                <td>{{ a.control_compensatorio }}</td>
                <td>{{ a.mitigacion_vector_perimetral }}</td>
            </tr>
            {% endfor %}
        </tbody>
    </table>

    <div class="footer-cta avoid-cut">
        <h3>Suscripción de Vigilancia Continua SentinelRecon + Piloto SentinelAgent (14 Días)</h3>
        <p>{{ reporte.prescripcion_endpoint_edr.argumentario_cierre_comercial }}</p>
        <p style="margin-top: 6px; font-weight: bold; color: #38bdf8;">Global365 SpA | EASM, DRPS, TPRM & Endpoint Security Intelligence</p>
    </div>
</body>
</html>
"""


def generate_html_report(
    target: str,
    report_data: Dict[str, Any],
    output_path: str = "reporte_ejecutivo.html",
    raw_telemetry: Optional[Dict[str, Any]] = None,
    posture: Optional[Dict[str, Any]] = None
) -> str:
    """Renderiza el informe visual ejecutivo enriquecido con telemetría DRPS v2.1."""
    template = Template(HTML_TEMPLATE)
    rendered_html = template.render(
        target=target,
        fecha=datetime.datetime.now().strftime("%d-%m-%Y %H:%M"),
        reporte=report_data,
        telemetria=raw_telemetry,
        posture=posture
    )
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(rendered_html)
    return output_path