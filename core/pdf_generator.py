# core/pdf_generator.py
import datetime
from jinja2 import Template
from typing import Dict, Any, Optional

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>Reporte Ejecutivo EASM & DRPS - SentinelRecon</title>
    <style>
        @page { size: A4; margin: 12mm; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            color: #1e293b;
            background-color: #ffffff;
            margin: 0;
            padding: 20px;
            font-size: 12.5px;
            line-height: 1.5;
        }
        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 2px solid #0f172a;
            padding-bottom: 12px;
            margin-bottom: 18px;
        }
        .logo-title h1 {
            margin: 0;
            font-size: 24px;
            color: #0f172a;
            letter-spacing: -0.5px;
        }
        .logo-title span {
            color: #0284c7;
            font-weight: bold;
        }
        .meta-box {
            text-align: right;
            font-size: 11px;
            color: #64748b;
        }
        .grade-card {
            display: flex;
            background: #f8fafc;
            border: 1px solid #e2e8f0;
            border-radius: 8px;
            padding: 16px;
            margin-bottom: 18px;
            align-items: center;
        }
        .grade-badge {
            font-size: 40px;
            font-weight: 800;
            width: 76px;
            height: 76px;
            line-height: 76px;
            text-align: center;
            border-radius: 8px;
            margin-right: 18px;
            color: #ffffff;
            flex-shrink: 0;
        }
        .grade-A { background-color: #16a34a; }
        .grade-B { background-color: #0284c7; }
        .grade-C { background-color: #eab308; }
        .grade-D { background-color: #f97316; }
        .grade-F { background-color: #dc2626; }
        .grade-info h3 {
            margin: 0 0 4px 0;
            font-size: 16px;
            color: #0f172a;
        }
        .grade-info p {
            margin: 0;
            color: #475569;
            font-size: 12px;
        }
        .section-title {
            font-size: 14px;
            font-weight: 700;
            color: #0f172a;
            border-left: 4px solid #0284c7;
            padding-left: 8px;
            margin: 22px 0 10px 0;
            text-transform: uppercase;
        }
        .summary-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 12px;
            margin-bottom: 16px;
        }
        .summary-card {
            background: #f1f5f9;
            padding: 12px;
            border-radius: 6px;
            border: 1px solid #e2e8f0;
        }
        .summary-card h4 {
            margin: 0 0 4px 0;
            color: #0f172a;
            font-size: 12px;
        }
        .summary-card p {
            margin: 0;
            font-size: 11px;
            color: #334155;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 16px;
        }
        th, td {
            padding: 7px 9px;
            text-align: left;
            border-bottom: 1px solid #e2e8f0;
            font-size: 11px;
            vertical-align: top;
        }
        th {
            background-color: #0f172a;
            color: #ffffff;
            font-weight: 600;
        }
        code {
            background: #e2e8f0;
            padding: 2px 5px;
            border-radius: 4px;
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
            font-size: 10.5px;
            color: #0f172a;
        }
        .cmd-box {
            background: #0f172a;
            color: #38bdf8;
            padding: 6px 8px;
            border-radius: 4px;
            font-family: monospace;
            font-size: 10.5px;
            display: block;
            white-space: pre-wrap;
        }
        .crit-CRÍTICA, .crit-CRITICA, .crit-critical { color: #dc2626; font-weight: bold; }
        .crit-ALTA, .crit-high, .crit-warning { color: #f97316; font-weight: bold; }
        .crit-MEDIA { color: #d97706; font-weight: bold; }
        .crit-BAJA, .crit-clean { color: #16a34a; font-weight: bold; }
        .anci-box {
            background: #fffbeb;
            border: 1px solid #fde68a;
            border-left: 4px solid #d97706;
            padding: 12px;
            border-radius: 6px;
            margin-bottom: 16px;
            font-size: 11px;
        }
        .anci-box h4 {
            margin: 0 0 6px 0;
            color: #92400e;
            font-size: 12px;
        }
        .seal-banner {
            display: flex;
            justify-content: space-between;
            align-items: center;
            background: #f0f9ff;
            border: 1px solid #bae6fd;
            padding: 10px 14px;
            border-radius: 6px;
            margin-top: 14px;
            font-size: 11px;
        }
        .footer-cta {
            background: #0f172a;
            color: #ffffff;
            padding: 16px;
            border-radius: 8px;
            margin-top: 22px;
            text-align: center;
        }
        .footer-cta h3 {
            margin: 0 0 6px 0;
            color: #38bdf8;
            font-size: 15px;
        }
        .footer-cta p {
            margin: 0;
            font-size: 11px;
            color: #cbd5e1;
        }
        @media print {
            body { padding: 0; }
            .no-print { display: none; }
        }
    </style>
</head>
<body>
    <div class="header">
        <div class="logo-title">
            <h1>SENTINEL<span>RECON</span></h1>
            <small>EASM, Digital Risk Protection (DRPS) & Cumplimiento ANCI | Global365</small>
        </div>
        <div class="meta-box">
            <strong>Objetivo Auditado:</strong> {{ target }}<br>
            <strong>Fecha de Emisión:</strong> {{ fecha }}<br>
            <strong>Marco Normativo:</strong> Ley N° 21.663 (ANCI) / Ley N° 21.719 / Ley N° 21.459
        </div>
    </div>

    <div class="grade-card">
        <div class="grade-badge grade-{{ reporte.resumen_ejecutivo.calificacion_postura }}">
            {{ reporte.resumen_ejecutivo.calificacion_postura }}
        </div>
        <div class="grade-info">
            <h3>Puntaje de Postura Perimetral y Riesgo Digital: {{ reporte.resumen_ejecutivo.puntaje_global }} / 100</h3>
            <p>{{ reporte.prescripcion_endpoint_edr.necesidad_defensa_profundidad }}</p>
        </div>
    </div>

    <div class="section-title">1. Impacto de Negocio y Exposición Regulatoria (Chile)</div>
    <div class="summary-grid">
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
                <th>Vector de Amenaza</th>
                <th>Criticidad</th>
                <th>Interfaz / Activo</th>
                <th>Evidencia Técnica</th>
                <th>Explicación de Riesgo</th>
            </tr>
        </thead>
        <tbody>
            {% for h in reporte.hallazgos_prioritarios %}
            <tr>
                <td><strong>{{ h.vector }}</strong></td>
                <td class="crit-{{ h.criticidad }}">{{ h.criticidad }}</td>
                <td>{{ h.puerto_servicio }}</td>
                <td><code>{{ h.evidencia_tecnica }}</code></td>
                <td>{{ h.explicacion_tecnica }}</td>
            </tr>
            {% endfor %}
        </tbody>
    </table>

    {% if reporte.inteligencia_drps_persistencia %}
    <div class="section-title">3. Inteligencia Continua DRPS: Identidades, Marca, Shadow IT y KEV</div>
    <div class="summary-grid">
        <div class="summary-card">
            <h4>Radar de Infostealers y Sesiones Robadas (Equipos Windows)</h4>
            <p>{{ reporte.inteligencia_drps_persistencia.diagnostico_infostealers_identidad }}</p>
            {% if telemetria and telemetria.identidad %}
            <p style="margin-top:6px; font-weight:bold; color:#0f172a;">
                Empleados infectados: {{ telemetria.identidad.compromised_employees }} |
                Usuarios: {{ telemetria.identidad.compromised_users }} |
                Terceros: {{ telemetria.identidad.third_parties }}
            </p>
            {% endif %}
        </div>
        <div class="summary-card">
            <h4>Escudo Anti-Suplantación de Marca y Fraude BEC (Typosquatting)</h4>
            <p>{{ reporte.inteligencia_drps_persistencia.diagnostico_typosquatting_bec }}</p>
            {% if telemetria and telemetria.typosquatting %}
            <p style="margin-top:6px; font-weight:bold; color:#0f172a;">
                Dominios similares activos: {{ telemetria.typosquatting.active_lookalikes_count }}
                (Con servidor de correo MX listo: {{ telemetria.typosquatting.mail_ready_clones_count }})
            </p>
            {% endif %}
        </div>
        <div class="summary-card">
            <h4>Superficie Sombra (CT Logs), Takeover y Vigencia NIC Chile</h4>
            <p>{{ reporte.inteligencia_drps_persistencia.diagnostico_shadow_dns_nic }}</p>
            {% if telemetria and telemetria.shadow_dns and telemetria.shadow_dns.domain_registration_rdap %}
            <p style="margin-top:6px; font-weight:bold; color:#0f172a;">
                Subdominios activos: {{ telemetria.shadow_dns.active_subdomains_count }} |
                Expiración Dominio: {{ telemetria.shadow_dns.domain_registration_rdap.expiration_date or 'N/D' }}
                ({{ telemetria.shadow_dns.domain_registration_rdap.days_until_expiration or '?' }} días)
            </p>
            {% endif %}
        </div>
        <div class="summary-card">
            <h4>Priorización Predictiva (CISA KEV / FIRST EPSS) y Nube</h4>
            <p>{{ reporte.inteligencia_drps_persistencia.diagnostico_kev_epss_cloud }}</p>
            {% if telemetria and telemetria.kev_epss %}
            <p style="margin-top:6px; font-weight:bold; color:#0f172a;">
                Incidentes P0 Mismo Día: {{ telemetria.kev_epss.same_day_p0_incidents_count }} |
                Buckets Públicos Expuestos: {{ telemetria.cloud_leaks.public_leaking_buckets_count if telemetria.cloud_leaks else 0 }}
            </p>
            {% endif %}
        </div>
    </div>

    {% if telemetria and telemetria.typosquatting and telemetria.typosquatting.detected_lookalikes %}
    <table>
        <thead>
            <tr>
                <th>Dominio Similar Detectado (Lookalike)</th>
                <th>Riesgo</th>
                <th>Web Activa (IP)</th>
                <th>Correo MX Activo (Riesgo BEC)</th>
                <th>Clasificación de Amenaza</th>
            </tr>
        </thead>
        <tbody>
            {% for d in telemetria.typosquatting.detected_lookalikes[:8] %}
            <tr>
                <td><strong>{{ d.squatted_domain }}</strong></td>
                <td class="crit-{{ d.risk_level }}">{{ d.risk_level | upper }}</td>
                <td>{{ d.resolved_ips | join(', ') if d.resolved_ips else 'No' }}</td>
                <td><code>{{ d.mx_servers | join(', ') if d.mx_servers else 'Sin MX' }}</code></td>
                <td>{{ d.threat_type }}</td>
            </tr>
            {% endfor %}
        </tbody>
    </table>
    {% endif %}
    {% endif %}

    {% if reporte.comandos_remediacion_ti %}
    <div class="section-title">4. Plan de Remediación Técnica Inmediata (TI / Windows / DNS)</div>
    <table>
        <thead>
            <tr>
                <th style="width: 22%;">Componente</th>
                <th style="width: 33%;">Acción de Mitigación</th>
                <th style="width: 45%;">Comando PowerShell / Configuración Exacta</th>
            </tr>
        </thead>
        <tbody>
            {% for c in reporte.comandos_remediacion_ti %}
            <tr>
                <td><strong>{{ c.componente_afectado }}</strong></td>
                <td>{{ c.accion_inmediata }}</td>
                <td><span class="cmd-box">{{ c.comando_o_script_sugerido }}</span></td>
            </tr>
            {% endfor %}
        </tbody>
    </table>
    {% endif %}

    {% if reporte.gobernanza_anci_ley21663 %}
    <div class="section-title">5. Gobernanza Ley N° 21.663 (ANCI) y Pre-Alerta CSIRT (3 Horas)</div>
    <div class="anci-box">
        <h4>Dictamen de Inventario Continuo (Art. 8) y Cadena de Suministro (TPRM)</h4>
        <p><strong>Cumplimiento Art. 8:</strong> {{ reporte.gobernanza_anci_ley21663.estado_inventario_art8 }}</p>
        <p style="margin-top:4px;"><strong>Directriz Proveedores (TPRM):</strong> {{ reporte.gobernanza_anci_ley21663.directriz_cadena_suministro_tprm }}</p>
        <h4 style="margin-top:10px;">Plantilla Pre-Llenada de Alerta Temprana CSIRT Nacional (Ventana Legal ≤ 3 Horas - Art. 9)</h4>
        <p><code>{{ reporte.gobernanza_anci_ley21663.borrador_alerta_temprana_3h_csirt }}</code></p>
    </div>
    {% endif %}

    <div class="section-title">6. Defensa en Profundidad: Despliegue de SentinelAgent (EDR) en PCs Windows</div>
    <table class="contrast-table">
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

    {% if reporte.inteligencia_drps_persistencia %}
    <div class="seal-banner">
        <div>
            <strong>Vigilancia Perimetral Continua (Drift Engine) & Sello Dinámico B2B:</strong><br>
            {{ reporte.inteligencia_drps_persistencia.justificacion_monitoreo_continuo }}
        </div>
        <div style="text-align:right; font-weight:bold; color:#0284c7; flex-shrink:0; margin-left:12px;">
            MONITOREADO POR<br>SENTINELRECON 24/7
        </div>
    </div>
    {% endif %}

    <div class="footer-cta">
        <h3>Suscripción de Vigilancia Continua SentinelRecon + Piloto SentinelAgent (14 Días)</h3>
        <p>{{ reporte.prescripcion_endpoint_edr.argumentario_cierre_comercial }}</p>
        <p style="margin-top: 8px; font-weight: bold; color: #38bdf8;">Global365 SpA | EASM, DRPS, TPRM & Endpoint Security Intelligence</p>
    </div>
</body>
</html>
"""


def generate_html_report(
    target: str,
    report_data: Dict[str, Any],
    output_path: str = "reporte_ejecutivo.html",
    raw_telemetry: Optional[Dict[str, Any]] = None
) -> str:
    """Renderiza el informe visual ejecutivo enriquecido con telemetría DRPS."""
    template = Template(HTML_TEMPLATE)
    rendered_html = template.render(
        target=target,
        fecha=datetime.datetime.now().strftime("%d-%m-%Y %H:%M"),
        reporte=report_data,
        telemetria=raw_telemetry
    )
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(rendered_html)
    return output_path