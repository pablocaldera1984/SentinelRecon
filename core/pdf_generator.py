import json
import datetime
from jinja2 import Template
from typing import Dict, Any

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>Reporte EASM Ejecutivo - SentinelRecon</title>
    <style>
        @page { size: A4; margin: 15mm; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            color: #1e293b;
            background-color: #ffffff;
            margin: 0;
            padding: 20px;
            font-size: 13px;
            line-height: 1.5;
        }
        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 2px solid #0f172a;
            padding-bottom: 12px;
            margin-bottom: 20px;
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
            margin-bottom: 20px;
            align-items: center;
        }
        .grade-badge {
            font-size: 42px;
            font-weight: 800;
            width: 80px;
            height: 80px;
            line-height: 80px;
            text-align: center;
            border-radius: 8px;
            margin-right: 20px;
            color: #ffffff;
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
        }
        .section-title {
            font-size: 15px;
            font-weight: 700;
            color: #0f172a;
            border-left: 4px solid #0284c7;
            padding-left: 8px;
            margin: 20px 0 10px 0;
            text-transform: uppercase;
        }
        .summary-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 12px;
            margin-bottom: 20px;
        }
        .summary-card {
            background: #f1f5f9;
            padding: 12px;
            border-radius: 6px;
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
            margin-bottom: 20px;
        }
        th, td {
            padding: 8px 10px;
            text-align: left;
            border-bottom: 1px solid #e2e8f0;
            font-size: 11px;
        }
        th {
            background-color: #0f172a;
            color: #ffffff;
            font-weight: 600;
        }
        .crit-CRÍTICA, .crit-CRITICA { color: #dc2626; font-weight: bold; }
        .crit-ALTA { color: #f97316; font-weight: bold; }
        .crit-MEDIA { color: #d97706; font-weight: bold; }
        .contrast-table td {
            vertical-align: top;
        }
        .footer-cta {
            background: #0f172a;
            color: #ffffff;
            padding: 16px;
            border-radius: 8px;
            margin-top: 25px;
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
            <small>External Attack Surface Management | Global365</small>
        </div>
        <div class="meta-box">
            <strong>Objetivo:</strong> {{ target }}<br>
            <strong>Fecha de Auditoría:</strong> {{ fecha }}<br>
            <strong>Cumplimiento:</strong> Ley 21.459 / Ley 21.663 (ANCI)
        </div>
    </div>

    <div class="grade-card">
        <div class="grade-badge grade-{{ reporte.resumen_ejecutivo.calificacion_postura }}">
            {{ reporte.resumen_ejecutivo.calificacion_postura }}
        </div>
        <div class="grade-info">
            <h3>Puntaje de Postura de Seguridad: {{ reporte.resumen_ejecutivo.puntaje_global }} / 100</h3>
            <p>{{ reporte.prescripcion_endpoint_edr.necesidad_defensa_profundidad }}</p>
        </div>
    </div>

    <div class="section-title">Impacto de Negocio y Exposición Regulatoria</div>
    <div class="summary-grid">
        <div class="summary-card">
            <h4>Impacto Financiero Proyectado</h4>
            <p>{{ reporte.resumen_ejecutivo.impacto_financiero_estimado }}</p>
        </div>
        <div class="summary-card">
            <h4>Exposición Legal ANCI (Ley 21.663)</h4>
            <p>{{ reporte.resumen_ejecutivo.exposicion_regulatoria }}</p>
        </div>
    </div>

    <div class="section-title">Hallazgos Perimetrales Prioritarios</div>
    <table>
        <thead>
            <tr>
                <th>Vector de Amenaza</th>
                <th>Criticidad</th>
                <th>Interfaz / Puerto</th>
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

    <div class="section-title">Contención Defensiva: SentinelAgent (EDR) en el Host</div>
    <table class="contrast-table">
        <thead>
            <tr>
                <th style="width: 25%;">Módulo SentinelAgent</th>
                <th style="width: 40%;">Control Compensatorio en el Host</th>
                <th style="width: 35%;">Mitigación de Brecha Perimetral</th>
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

    <div class="footer-cta">
        <h3>Prueba de Concepto (PoC) Preventiva - 14 Días</h3>
        <p>{{ reporte.prescripcion_endpoint_edr.argumentario_cierre_comercial }}</p>
        <p style="margin-top: 8px; font-weight: bold; color: #38bdf8;">Global365 SpA | Ciberseguridad Corporativa & EDR Intelligence</p>
    </div>
</body>
</html>
"""

def generate_html_report(target: str, report_data: Dict[str, Any], output_path: str = "reporte_ejecutivo.html") -> str:
    """Renderiza el informe visual ejecutivo."""
    template = Template(HTML_TEMPLATE)
    rendered_html = template.render(
        target=target,
        fecha=datetime.datetime.now().strftime("%d-%m-%Y %H:%M"),
        reporte=report_data
    )
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(rendered_html)
    return output_path
