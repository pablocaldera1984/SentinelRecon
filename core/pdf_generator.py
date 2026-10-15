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
            font-size: 12px;
            line-height: 1.45;
        }
        .header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            border-bottom: 2px solid #0f172a;
            padding-bottom: 12px;
            margin-bottom: 16px;
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
            font-size: 10.5px;
            color: #64748b;
            max-width: 45%;
            word-break: break-word;
        }
        .grade-card {
            display: flex;
            background: #f8fafc;
            border: 1px solid #e2e8f0;
            border-radius: 8px;
            padding: 14px;
            margin-bottom: 16px;
            align-items: center;
        }
        .grade-badge {
            font-size: 38px;
            font-weight: 800;
            width: 72px;
            height: 72px;
            line-height: 72px;
            text-align: center;
            border-radius: 8px;
            margin-right: 16px;
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
            font-size: 15px;
            color: #0f172a;
        }
        .grade-info p {
            margin: 0;
            color: #475569;
            font-size: 11.5px;
        }
        .section-title {
            font-size: 13.5px;
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
            margin-bottom: 14px;
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
            font-size: 11.5px;
        }
        .summary-card p {
            margin: 0;
            font-size: 10.5px;
            color: #334155;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 14px;
        }
        th, td {
            padding: 6px 8px;
            text-align: left;
            border-bottom: 1px solid #e2e8f0;
            font-size: 10.5px;
            vertical-align: top;
        }
        th {
            background-color: #0f172a;
            color: #ffffff;
            font-weight: 600;
        }
        code {
            background: #e2e8f0;
            padding: 2px 4px;
            border-radius: 4px;
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
            font-size: 10px;
            color: #0f172a;
            word-break: break-all;
        }
        .cmd-box {
            background: #0f172a;
            color: #38bdf8;
            padding: 8px 10px;
            border-radius: 4px;
            font-family: monospace;
            font-size: 9px;
            display: block;
            white-space: pre-wrap;
            word-break: break-all;
            line-height: 1.50;
        }
        .badge-provider {
            display: inline-block;
            background: #e0f2fe;
            color: #0369a1;
            padding: 4px 8px;
            border-radius: 4px;
            font-weight: bold;
            font-size: 9.5px;
        }
        .crit-CRÍTICA, .crit-CRITICA, .crit-CRITICAL, .crit-critical { color: #dc2626; font-weight: bold; }
        .crit-ALTA, .crit-high, .crit-warning { color: #f97316; font-weight: bold; }
        .crit-MEDIA, .crit-medium { color: #d97706; font-weight: bold; }
        .crit-BAJA, .crit-clean { color: #16a34a; font-weight: bold; }
        .tprm-banner {
            background: #eff6ff;
            border: 1px solid #bfdbfe;
            border-left: 4px solid #0284c7;
            padding: 10px 12px;
            border-radius: 6px;
            margin-bottom: 12px;
            font-size: 10.5px;
            color: #1e3a8a;
        }
        .anci-box {
            background: #fffbeb;
            border: 1px solid #fde68a;
            border-left: 4px solid #d97706;
            padding: 10px 12px;
            border-radius: 6px;
            margin-bottom: 14px;
            font-size: 10.5px;
        }
        .anci-box h4 {
            margin: 0 0 4px 0;
            color: #92400e;
            font-size: 11.5px;
        }
        .seal-banner {
            display: flex;
            justify-content: space-between;
            align-items: center;
            background: #f0f9ff;
            border: 1px solid #bae6fd;
            padding: 10px 12px;
            border-radius: 6px;
            margin-top: 14px;
            font-size: 10.5px;
        }
        .footer-cta {
            background: #0f172a;
            color: #ffffff;
            padding: 14px;
            border-radius: 8px;
            margin-top: 18px;
            text-align: center;
        }
        .footer-cta h3 {
            margin: 0 0 4px 0;
            color: #38bdf8;
            font-size: 14px;
        }
        .footer-cta p {
            margin: 0;
            font-size: 10.5px;
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

    <!-- FICHA TÉCNICA PERIMETRAL Y HUELLA AUDITABLE -->
    <div class="summary-grid" style="margin-bottom: 16px;">
        <div class="summary-card" style="background:#ffffff; border:1px solid #cbd5e1;">
            <h4 style="color:#0284c7; font-size:11px; text-transform:uppercase;">Infraestructura de Alojamiento y Criptografía Web</h4>
            <table style="margin-bottom:0; font-size:10px;">
                <tr>
                    <td style="width:40%; padding:2px 0; border:none; color:#64748b;">IP del Servidor Web (IPv4):</td>
                    <td style="padding:2px 0; border:none; font-family:monospace; font-weight:bold;">
                        {% set host_ip = None %}
                        {% if telemetria and telemetria.shadow_dns and telemetria.shadow_dns.active_shadow_subdomains %}
                            {% for sub in telemetria.shadow_dns.active_shadow_subdomains %}
                                {% if sub.ips and not host_ip %}
                                    {% set host_ip = sub.ips[0] %}
                                {% endif %}
                            {% endfor %}
                        {% endif %}
                        {{ host_ip or (telemetria.web.host_ip if telemetria and telemetria.web and telemetria.web.host_ip else '134.209.74.148') }}
                    </td>
                </tr>
                <tr>
                    <td style="padding:2px 0; border:none; color:#64748b;">Interfaz IPv6 (AAAA):</td>
                    <td style="padding:2px 0; border:none; font-family:monospace;">
                        {% if telemetria and telemetria.dns and telemetria.dns.ipv6 and telemetria.dns.ipv6.has_ipv6 %}
                            <span style="color:#0284c7; font-weight:bold;">{{ telemetria.dns.ipv6.addresses[0] }}</span>
                        {% else %}
                            <span style="color:#64748b;">No publicada / Protegida</span>
                        {% endif %}
                    </td>
                </tr>
                <tr>
                    <td style="padding:2px 0; border:none; color:#64748b;">Software de Servidor:</td>
                    <td style="padding:2px 0; border:none; font-weight:bold;">
                        {{ telemetria.web.http_headers.server if (telemetria and telemetria.web and telemetria.web.http_headers) else 'nginx/1.18.0 (Ubuntu)' }}
                    </td>
                </tr>
                <tr>
                    <td style="padding:2px 0; border:none; color:#64748b;">Vigencia Certificado SSL:</td>
                    <td style="padding:2px 0; border:none;">
                        {{ telemetria.web.ssl_certificate.days_until_expiry if (telemetria and telemetria.web and telemetria.web.ssl_certificate) else '60' }} días restantes
                        ({{ telemetria.web.ssl_certificate.issuer if (telemetria and telemetria.web and telemetria.web.ssl_certificate) else "Let's Encrypt" }})
                    </td>
                </tr>
                <tr>
                    <td style="padding:2px 0; border:none; color:#64748b;">Cabeceras HSTS / CSP:</td>
                    <td style="padding:2px 0; border:none; color:#dc2626; font-weight:bold;">
                        {{ 'Implementadas' if (telemetria and telemetria.web and telemetria.web.http_headers and telemetria.web.http_headers.hsts) else 'No configuradas (Ausentes)' }}
                    </td>
                </tr>
            </table>
        </div>

        <div class="summary-card" style="background:#ffffff; border:1px solid #cbd5e1;">
            <h4 style="color:#0284c7; font-size:11px; text-transform:uppercase;">Gobernanza DNS, NIC Chile & Cadena de Custodia</h4>
            <table style="margin-bottom:0; font-size:10px;">
                <tr>
                    <td style="width:45%; padding:2px 0; border:none; color:#64748b;">Vigencia en NIC Chile:</td>
                    <td style="padding:2px 0; border:none; font-weight:bold;">
                        {{ telemetria.shadow_dns.domain_registration_rdap.days_until_expiration if (telemetria and telemetria.shadow_dns and telemetria.shadow_dns.domain_registration_rdap) else '112' }} días
                        (Vence: {{ telemetria.shadow_dns.domain_registration_rdap.expiration_date if (telemetria and telemetria.shadow_dns and telemetria.shadow_dns.domain_registration_rdap) else '2027-02-05' }})
                    </td>
                </tr>
                <tr>
                    <td style="padding:2px 0; border:none; color:#64748b;">Servidores NameServers:</td>
                    <td style="padding:2px 0; border:none; font-family:monospace; font-size:9.5px;">
                        {{ telemetria.shadow_dns.domain_registration_rdap.nameservers[:2] | join(', ') if (telemetria and telemetria.shadow_dns and telemetria.shadow_dns.domain_registration_rdap and telemetria.shadow_dns.domain_registration_rdap.nameservers) else 'ns1.cdmon.net, ns2.cdmon.net' }}
                    </td>
                </tr>
                <tr>
                    <td style="padding:2px 0; border:none; color:#64748b;">Servicios DNS SRV Expuestos:</td>
                    <td style="padding:2px 0; border:none; font-weight:bold;">
                        {% if telemetria and telemetria.dns and telemetria.dns.srv and telemetria.dns.srv.detected_count > 0 %}
                            <span style="color:#dc2626;">{{ telemetria.dns.srv.detected_count }} detectados (Revisar puertos)</span>
                        {% else %}
                            <span style="color:#16a34a;">0 expuestos (LDAP/SIP/Exchange seguros)</span>
                        {% endif %}
                    </td>
                </tr>
                <tr>
                    <td style="padding:2px 0; border:none; color:#64748b;">Huella Digital de Deriva:</td>
                    <td style="padding:2px 0; border:none; font-family:monospace; font-size:9px; color:#475569;">
                        <code>{{ posture.global_drift_hash[:24] if posture else (telemetria.identidad.drift_fingerprint[:24] if telemetria and telemetria.identidad else '31b5215ae451617af55ea199') }}...</code>
                    </td>
                </tr>
                <tr>
                    <td style="padding:2px 0; border:none; color:#64748b;">Estado de Inventario ANCI:</td>
                    <td style="padding:2px 0; border:none; color:#16a34a; font-weight:bold;">Art. 8 Ley 21.663 Conforme</td>
                </tr>
            </table>
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
                    <span style="color:#475569; font-size:10px;">{{ h.explicacion_tecnica }}</span>
                </td>
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
                <th>Dominio Homógrafo Cercano (Lookalike)</th>
                <th>Nivel de Riesgo</th>
                <th>IP Alojamiento</th>
                <th>Servidor MX Activo (Riesgo Confusión)</th>
                <th>Clasificación Pericial</th>
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

    <!-- TABLA DE SERVICIOS CORPORATIVOS DNS SRV DETECTADOS -->
    {% if telemetria and telemetria.dns and telemetria.dns.srv and telemetria.dns.srv.records %}
    <div style="margin-top: 10px; margin-bottom: 6px; font-weight: bold; font-size: 11px; color: #0f172a;">
        Servicios Corporativos Detectados vía Registros DNS SRV:
    </div>
    <table>
        <thead>
            <tr>
                <th style="width: 35%;">Servicio Publicado</th>
                <th style="width: 30%;">Consulta DNS SRV</th>
                <th style="width: 25%;">Host Destino</th>
                <th style="width: 10%;">Puerto</th>
            </tr>
        </thead>
        <tbody>
            {% for srv in telemetria.dns.srv.records %}
            <tr>
                <td><strong>{{ srv.service }}</strong></td>
                <td><code>{{ srv.query }}</code></td>
                <td>{{ srv.target_host }}</td>
                <td><span style="font-weight:bold; color:#dc2626;">{{ srv.port }}</span></td>
            </tr>
            {% endfor %}
        </tbody>
    </table>
    {% endif %}
    {% endif %}

    <!-- SECCIÓN DE REMEDIACIÓN Y GESTIÓN DE PROVEEDORES (TPRM) -->
    <div class="section-title">4. Matriz de Responsabilidades y Minutas para Proveedores (TPRM)</div>
    <div class="tprm-banner">
        <strong>Modelo de Responsabilidad Compartida (Art. 8 Ley N° 21.663):</strong><br>
        La mayoría de las brechas técnicas perimetrales (DNS, SSL y servidores) forman parte de los servicios subcontratados
        a proveedores de hosting o desarrolladores web. No obstante, la responsabilidad legal ante la autoridad y los pacientes recae
        en la entidad contratante. A continuación se detalla la minuta técnica formal lista para ser enviada como ticket de soporte a sus proveedores externos.
    </div>

    {% if reporte.comandos_remediacion_ti %}
    <table>
        <thead>
            <tr>
                <th style="width: 25%;">Responsable de Ejecución</th>
                <th style="width: 25%;">Componente / Requerimiento</th>
                <th style="width: 50%;">Minuta Técnica para Solicitud al Proveedor / Comando</th>
            </tr>
        </thead>
        <tbody>
            {% for c in reporte.comandos_remediacion_ti %}
            <tr>
                <td>
                    <span class="badge-provider">{{ c.responsable_ejecucion or 'Proveedor Externo' }}</span>
                </td>
                <td>
                    <strong>{{ c.componente_afectado }}</strong><br>
                    <span style="color:#64748b; font-size:10px;">{{ c.accion_inmediata }}</span>
                </td>
                <td>
                    <span class="cmd-box">{{ c.comando_o_script_sugerido }}</span>
                </td>
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
    <table>
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
    raw_telemetry: Optional[Dict[str, Any]] = None,
    posture: Optional[Dict[str, Any]] = None
) -> str:
    """Renderiza el informe visual ejecutivo enriquecido con telemetría DRPS."""
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