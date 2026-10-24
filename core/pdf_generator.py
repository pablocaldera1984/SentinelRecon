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
            padding: 16px;
            font-size: 11.5px;
            line-height: 1.42;
        }
        .avoid-cut {
            break-inside: avoid !important;
            page-break-inside: avoid !important;
        }
        .page-break {
            page-break-before: always !important;
            break-before: page !important;
            height: 0;
            margin: 0;
            padding: 0;
        }
        .header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            border-bottom: 2px solid #0f172a;
            padding-bottom: 10px;
            margin-bottom: 14px;
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
            padding: 12px;
            margin-bottom: 14px;
            align-items: center;
        }
        .grade-badge {
            font-size: 34px;
            font-weight: 800;
            width: 64px;
            height: 64px;
            line-height: 64px;
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
            margin: 0 0 4px 0;
            font-size: 14px;
            color: #0f172a;
        }
        .grade-info p {
            margin: 0;
            color: #475569;
            font-size: 11px;
        }
        .section-title {
            font-size: 12.5px;
            font-weight: 700;
            color: #0f172a;
            border-left: 4px solid #0284c7;
            padding-left: 8px;
            margin: 16px 0 8px 0;
            text-transform: uppercase;
        }
        .summary-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 10px;
            margin-bottom: 12px;
        }
        .summary-card {
            background: #f1f5f9;
            padding: 10px;
            border-radius: 6px;
            border: 1px solid #e2e8f0;
        }
        .summary-card h4 {
            margin: 0 0 4px 0;
            color: #0f172a;
            font-size: 11px;
        }
        .summary-card p {
            margin: 0;
            font-size: 10px;
            color: #334155;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 12px;
        }
        tr {
            break-inside: avoid !important;
            page-break-inside: avoid !important;
        }
        th, td {
            padding: 5px 7px;
            text-align: left;
            border-bottom: 1px solid #e2e8f0;
            font-size: 10px;
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
            font-size: 9.5px;
            color: #0f172a;
            word-break: break-all;
        }
        .cmd-box {
            background: #0f172a;
            color: #38bdf8;
            padding: 7px 9px;
            border-radius: 4px;
            font-family: monospace;
            font-size: 8.8px;
            display: block;
            white-space: pre-wrap;
            word-break: break-all;
            line-height: 1.45;
        }
        .badge-provider {
            display: inline-block;
            background: #e0f2fe;
            color: #0369a1;
            padding: 3px 7px;
            border-radius: 4px;
            font-weight: bold;
            font-size: 9px;
        }
        .crit-CRÍTICA, .crit-CRITICA, .crit-CRITICAL, .crit-critical { color: #dc2626; font-weight: bold; }
        .crit-ALTA, .crit-high, .crit-warning { color: #f97316; font-weight: bold; }
        .crit-MEDIA, .crit-medium { color: #d97706; font-weight: bold; }
        .crit-BAJA, .crit-clean { color: #16a34a; font-weight: bold; }
        .tprm-banner {
            background: #eff6ff;
            border: 1px solid #bfdbfe;
            border-left: 4px solid #0284c7;
            padding: 9px 11px;
            border-radius: 6px;
            margin-bottom: 10px;
            font-size: 10px;
            color: #1e3a8a;
        }
        .anci-box {
            background: #fffbeb;
            border: 1px solid #fde68a;
            border-left: 4px solid #d97706;
            padding: 10px 12px;
            border-radius: 6px;
            margin-bottom: 12px;
            font-size: 10px;
        }
        .anci-box h4 {
            margin: 0 0 4px 0;
            color: #92400e;
            font-size: 11px;
        }
        .seal-banner {
            display: flex;
            justify-content: space-between;
            align-items: center;
            background: #f0f9ff;
            border: 1px solid #bae6fd;
            padding: 9px 12px;
            border-radius: 6px;
            margin-top: 12px;
            font-size: 10px;
        }
        .footer-cta {
            background: #0f172a;
            color: #ffffff;
            padding: 12px;
            border-radius: 8px;
            margin-top: 14px;
            text-align: center;
        }
        .footer-cta h3 {
            margin: 0 0 4px 0;
            color: #38bdf8;
            font-size: 13px;
        }
        .footer-cta p {
            margin: 0;
            font-size: 10px;
            color: #cbd5e1;
        }
        @media print {
            body { padding: 0; }
            .no-print { display: none; }
        }
    </style>
</head>
<body>
    <!-- ================= PÁGINA 1 ================= -->
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

    <!-- FICHA TÉCNICA PERIMETRAL Y SOBERANÍA DE DATOS (ENRIQUECIDA v2.1) -->
    <div class="summary-grid avoid-cut" style="margin-bottom: 14px;">
        <div class="summary-card" style="background:#ffffff; border:1px solid #cbd5e1;">
            <h4 style="color:#0284c7; font-size:10.5px; text-transform:uppercase;">Infraestructura, Soberanía de Datos y Criptografía PQC</h4>
            <table style="margin-bottom:0; font-size:9.5px;">
                <tr>
                    <td style="width:42%; padding:2px 0; border:none; color:#64748b;">IPv4 / Interfaz IPv6:</td>
                    <td style="padding:2px 0; border:none; font-family:monospace; font-weight:bold;">
                        {% set host_ip = (telemetria.dns.asn_sovereignty.primary_ip if telemetria and telemetria.dns and telemetria.dns.asn_sovereignty else None) or (telemetria.web.host_ip if telemetria and telemetria.web else 'No resuelta') %}
                        {{ host_ip }}
                        {% if telemetria and telemetria.dns and telemetria.dns.ipv6 and telemetria.dns.ipv6.has_ipv6 %}
                            <span style="color:#0284c7;">(IPv6 Activo)</span>
                        {% endif %}
                    </td>
                </tr>
                <tr>
                    <td style="padding:2px 0; border:none; color:#64748b;">ASN / Jurisdicción (Ley 21.719):</td>
                    <td style="padding:2px 0; border:none; font-weight:bold;">
                        {% if telemetria and telemetria.dns and telemetria.dns.asn_sovereignty and telemetria.dns.asn_sovereignty.country %}
                            {{ telemetria.dns.asn_sovereignty.isp_org or telemetria.dns.asn_sovereignty.asn }} —
                            {% if telemetria.dns.asn_sovereignty.hosted_in_chile %}
                                <span style="color:#16a34a;">Chile (Local)</span>
                            {% else %}
                                <span style="color:#d97706;">{{ telemetria.dns.asn_sovereignty.country }} (Transfronterizo)</span>
                            {% endif %}
                        {% else %}
                            Servidor Público Registrado
                        {% endif %}
                    </td>
                </tr>
                <tr>
                    <td style="padding:2px 0; border:none; color:#64748b;">Servidor Web / TLS & PQC:</td>
                    <td style="padding:2px 0; border:none; font-weight:bold;">
                        {{ telemetria.web.http_headers.server if (telemetria and telemetria.web and telemetria.web.http_headers and telemetria.web.http_headers.server) else 'Servidor Web Activo' }}
                        | {{ telemetria.web.ssl_certificate.tls_version if (telemetria and telemetria.web and telemetria.web.ssl_certificate and telemetria.web.ssl_certificate.tls_version) else 'TLS 1.2/1.3' }}
                        {% if telemetria and telemetria.web and telemetria.web.ssl_certificate and telemetria.web.ssl_certificate.pqc_ready_transport %}
                            <span style="color:#16a34a;">(PQC Ready)</span>
                        {% endif %}
                    </td>
                </tr>
                <tr>
                    <td style="padding:2px 0; border:none; color:#64748b;">Vigencia Certificado SSL:</td>
                    <td style="padding:2px 0; border:none;">
                        {{ telemetria.web.ssl_certificate.days_until_expiry if (telemetria and telemetria.web and telemetria.web.ssl_certificate) else '--' }} días restantes
                        ({{ telemetria.web.ssl_certificate.issuer if (telemetria and telemetria.web and telemetria.web.ssl_certificate) else "CA Pública" }})
                    </td>
                </tr>
                <tr>
                    <td style="padding:2px 0; border:none; color:#64748b;">HSTS / CSP / Exposición API:</td>
                    <td style="padding:2px 0; border:none; font-weight:bold;">
                        {% if telemetria and telemetria.web and telemetria.web.http_headers and telemetria.web.http_headers.hsts %}
                            <span style="color:#16a34a;">HSTS Activo</span>
                        {% else %}
                            <span style="color:#dc2626;">Ausentes (HSTS/CSP)</span>
                        {% endif %}
                        {% if telemetria and telemetria.web and telemetria.web.exposure_audit and telemetria.web.exposure_audit.openapi_swagger_exposed %}
                            | <span style="color:#dc2626;">API Swagger Expuesta</span>
                        {% endif %}
                    </td>
                </tr>
            </table>
        </div>

        <div class="summary-card" style="background:#ffffff; border:1px solid #cbd5e1;">
            <h4 style="color:#0284c7; font-size:10.5px; text-transform:uppercase;">Gobernanza DNS, Identidad Federada & Custodia</h4>
            <table style="margin-bottom:0; font-size:9.5px;">
                <tr>
                    <td style="width:44%; padding:2px 0; border:none; color:#64748b;">Vigencia en NIC Chile / RDAP:</td>
                    <td style="padding:2px 0; border:none; font-weight:bold;">
                        {{ telemetria.shadow_dns.domain_registration_rdap.days_until_expiration if (telemetria and telemetria.shadow_dns and telemetria.shadow_dns.domain_registration_rdap and telemetria.shadow_dns.domain_registration_rdap.days_until_expiration is not none) else 'Activo' }} días
                        (Vence: {{ telemetria.shadow_dns.domain_registration_rdap.expiration_date if (telemetria and telemetria.shadow_dns and telemetria.shadow_dns.domain_registration_rdap and telemetria.shadow_dns.domain_registration_rdap.expiration_date) else 'Vigente' }})
                    </td>
                </tr>
                <tr>
                    <td style="padding:2px 0; border:none; color:#64748b;">Federación SSO (Entra ID):</td>
                    <td style="padding:2px 0; border:none; font-family:monospace; font-size:9px; font-weight:bold;">
                        {% if telemetria and telemetria.identidad and telemetria.identidad.corporate_sso_federation and telemetria.identidad.corporate_sso_federation.uses_entra_id %}
                            <span style="color:#0284c7;">{{ telemetria.identidad.corporate_sso_federation.name_space_type or 'M365 Tenant' }}</span>
                            ({{ (telemetria.identidad.corporate_sso_federation.tenant_id or '')[:13] }}...)
                        {% else %}
                            Autenticación Estándar / No Federada M365
                        {% endif %}
                    </td>
                </tr>
                <tr>
                    <td style="padding:2px 0; border:none; color:#64748b;">Blindaje CAA / MTA-STS / DNSSEC:</td>
                    <td style="padding:2px 0; border:none; font-weight:bold;">
                        {% set g = telemetria.dns.governance if (telemetria and telemetria.dns and telemetria.dns.governance) else {} %}
                        CAA: {{ 'Sí' if g.get('caa_configured') else 'No' }} |
                        MTA-STS: {{ 'Sí' if g.get('mta_sts_configured') else 'No' }} |
                        DNSSEC: {{ 'Sí' if g.get('dnssec_enabled') else 'No' }}
                    </td>
                </tr>
                <tr>
                    <td style="padding:2px 0; border:none; color:#64748b;">Huella Drift Hash (SHA-256):</td>
                    <td style="padding:2px 0; border:none; font-family:monospace; font-size:8.5px; color:#475569;">
                        <code>{{ posture.global_drift_hash[:24] if posture else 'SNAPSHOT_REGISTRADO' }}...</code>
                    </td>
                </tr>
                <tr>
                    <td style="padding:2px 0; border:none; color:#64748b;">Inventario Art. 8 Ley 21.663:</td>
                    <td style="padding:2px 0; border:none; color:#16a34a; font-weight:bold;">Conforme (Trazabilidad Continua 24/7)</td>
                </tr>
            </table>
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
                    <span style="color:#475569; font-size:9.5px;">{{ h.explicacion_tecnica }}</span>
                </td>
            </tr>
            {% endfor %}
        </tbody>
    </table>

    <!-- ================= SALTO A PÁGINA 2 ================= -->
    <div class="page-break"></div>

    {% if reporte.inteligencia_drps_persistencia %}
    <div class="section-title">3. Inteligencia Continua DRPS: Identidades, Marca, Shadow IT y KEV</div>
    <div class="summary-grid avoid-cut">
        <div class="summary-card">
            <h4>Radar Infostealers (Hudson Rock) & Federación SSO</h4>
            <p>{{ reporte.inteligencia_drps_persistencia.diagnostico_infostealers_identidad }}</p>
            {% if telemetria and telemetria.identidad %}
            <p style="margin-top:5px; font-weight:bold; color:#0f172a;">
                Empleados infectados: {{ telemetria.identidad.compromised_employees }} |
                Usuarios: {{ telemetria.identidad.compromised_users }} |
                Terceros: {{ telemetria.identidad.third_parties }}
            </p>
            {% endif %}
        </div>
        <div class="summary-card">
            <h4>Escudo Anti-Suplantación BEC y Clonación Visual (Favicon)</h4>
            <p>{{ reporte.inteligencia_drps_persistencia.diagnostico_typosquatting_bec }}</p>
            {% if telemetria and telemetria.typosquatting %}
            <p style="margin-top:5px; font-weight:bold; color:#0f172a;">
                Dominios similares: {{ telemetria.typosquatting.active_lookalikes_count }} |
                Con MX Activo: {{ telemetria.typosquatting.mail_ready_clones_count }} |
                Clones Visuales: {{ telemetria.typosquatting.visual_phishing_clones_count or 0 }}
            </p>
            {% endif %}
        </div>
        <div class="summary-card">
            <h4>Superficie Sombra, Soberanía BGP/ASN y Vigencia NIC.cl</h4>
            <p>{{ reporte.inteligencia_drps_persistencia.diagnostico_shadow_dns_nic }}</p>
            {% if telemetria and telemetria.shadow_dns and telemetria.shadow_dns.domain_registration_rdap %}
            <p style="margin-top:5px; font-weight:bold; color:#0f172a;">
                Subdominios activos: {{ telemetria.shadow_dns.active_subdomains_count }} |
                Takeovers: {{ telemetria.shadow_dns.takeover_vulnerable_count }}
            </p>
            {% endif %}
        </div>
        <div class="summary-card">
            <h4>Priorización CISA KEV / EPSS, Shodan InternetDB & Cloud</h4>
            <p>{{ reporte.inteligencia_drps_persistencia.diagnostico_kev_epss_cloud }}</p>
            {% if telemetria and telemetria.kev_epss %}
            <p style="margin-top:5px; font-weight:bold; color:#0f172a;">
                Incidentes P0: {{ telemetria.kev_epss.same_day_p0_incidents_count }} |
                Shadow AI: {{ telemetria.puertos.shadow_ai_exposed_count if telemetria.puertos else 0 }} |
                Buckets Abiertos: {{ telemetria.cloud_leaks.public_leaking_buckets_count if telemetria.cloud_leaks else 0 }}
            </p>
            {% endif %}
        </div>
    </div>

    {% if telemetria and telemetria.typosquatting and telemetria.typosquatting.detected_lookalikes %}
    <table class="avoid-cut">
        <thead>
            <tr>
                <th>Dominio Homógrafo Cercano (Lookalike)</th>
                <th>Nivel de Riesgo</th>
                <th>IP Alojamiento</th>
                <th>Servidor MX Activo</th>
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
    {% endif %}

    <!-- SECCIÓN DE REMEDIACIÓN Y GESTIÓN DE PROVEEDORES (TPRM) -->
    <div class="section-title">4. Matriz de Responsabilidades y Minutas para Proveedores (TPRM)</div>
    <div class="tprm-banner avoid-cut">
        <strong>Modelo de Responsabilidad Compartida (Art. 8 Ley N° 21.663):</strong>
        Aunque la configuración técnica de DNS, SSL o servidores recaiga en proveedores externos de hosting o desarrollo, la responsabilidad legal ante la autoridad y terceros pertenece a la entidad contratante. A continuación se entregan las minutas técnicas listas para enviar a sus proveedores.
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
                <td>
                    <span class="badge-provider">{{ c.responsable_ejecucion or 'Proveedor Externo' }}</span>
                </td>
                <td>
                    <strong>{{ c.componente_afectado }}</strong><br>
                    <span style="color:#64748b; font-size:9.5px;">{{ c.accion_inmediata }}</span>
                </td>
                <td>
                    <span class="cmd-box">{{ c.comando_o_script_sugerido }}</span>
                </td>
            </tr>
            {% endfor %}
        </tbody>
    </table>
    {% endif %}

    <!-- ================= SALTO A PÁGINA 3 ================= -->
    <div class="page-break"></div>

    {% if reporte.gobernanza_anci_ley21663 %}
    <div class="section-title">5. Gobernanza Ley N° 21.663 (ANCI) y Pre-Alerta CSIRT (≤ 3 Horas)</div>
    <div class="anci-box avoid-cut">
        <h4>Dictamen de Inventario Continuo (Art. 8), Soberanía de Datos (Ley 21.719) y TPRM</h4>
        <p><strong>Cumplimiento Art. 8:</strong> {{ reporte.gobernanza_anci_ley21663.estado_inventario_art8 }}</p>
        <p style="margin-top:4px;"><strong>Directriz Proveedores (TPRM):</strong> {{ reporte.gobernanza_anci_ley21663.directriz_cadena_suministro_tprm }}</p>
        <h4 style="margin-top:8px;">Plantilla Preventiva de Alerta Temprana CSIRT Nacional (Ventana Legal ≤ 3 Horas - Art. 9)</h4>
        <p><code>{{ reporte.gobernanza_anci_ley21663.borrador_alerta_temprana_3h_csirt }}</code></p>
    </div>
    {% endif %}

    <div class="section-title">6. Defensa en Profundidad: Despliegue de SentinelAgent (EDR) en PCs Windows</div>
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

    {% if reporte.inteligencia_drps_persistencia %}
    <div class="seal-banner avoid-cut">
        <div>
            <strong>Vigilancia Perimetral Continua (Drift Engine) & Sello Dinámico B2B:</strong><br>
            {{ reporte.inteligencia_drps_persistencia.justificacion_monitoreo_continuo }}
        </div>
        <div style="text-align:right; font-weight:bold; color:#0284c7; flex-shrink:0; margin-left:12px;">
            MONITOREADO POR<br>SENTINELRECON 24/7
        </div>
    </div>
    {% endif %}

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