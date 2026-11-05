# core/pdf_generator.py
import datetime
from jinja2 import Template
from typing import Dict, Any, Optional

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>Diagnóstico Ejecutivo de Riesgo Digital y Seguridad Web - {{ target }}</title>
    <style>
        @page { size: letter; margin: 8mm; }
        * { box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            color: #1e293b;
            background-color: #ffffff;
            margin: 0;
            padding: 8px;
            font-size: 10.5px;
            line-height: 1.38;
        }
        .avoid-cut {
            break-inside: avoid !important;
            page-break-inside: avoid !important;
        }
        /* CABECERA */
        .top-banner {
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 2px solid #0f172a;
            padding-bottom: 8px;
            margin-bottom: 10px;
        }
        .top-banner-left .eyebrow {
            font-size: 9px;
            font-weight: 700;
            color: #0284c7;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .top-banner-left h1 {
            margin: 2px 0 0 0;
            font-size: 16px;
            font-weight: 800;
            color: #0f172a;
            letter-spacing: -0.3px;
        }
        .top-banner-right {
            text-align: right;
            background: #f8fafc;
            border: 1px solid #cbd5e1;
            border-radius: 6px;
            padding: 5px 10px;
        }
        .top-banner-right .label {
            font-size: 8.5px;
            color: #64748b;
            font-weight: 700;
            text-transform: uppercase;
        }
        .top-banner-right .domain-title {
            font-size: 13px;
            font-weight: 800;
            color: #0f172a;
        }
        /* 5 KPIS SUPERIORES */
        .kpi-row {
            display: grid;
            grid-template-columns: repeat(5, 1fr);
            gap: 7px;
            margin-bottom: 9px;
        }
        .kpi-card {
            background: #f8fafc;
            border: 1px solid #e2e8f0;
            border-radius: 7px;
            padding: 7px 8px;
        }
        .kpi-card .kpi-title {
            font-size: 8.5px;
            font-weight: 700;
            color: #475569;
            text-transform: uppercase;
            margin-bottom: 3px;
        }
        .kpi-card .kpi-main {
            font-size: 13.5px;
            font-weight: 800;
            color: #0f172a;
            margin-bottom: 2px;
        }
        .kpi-card .kpi-sub {
            font-size: 8.8px;
            color: #475569;
        }
        .text-danger { color: #dc2626 !important; }
        .text-warn { color: #d97706 !important; }
        .text-ok { color: #16a34a !important; }

        /* 3 RECUADROS DE PROPIEDAD E INFRAESTRUCTURA */
        .infra-row {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 8px;
            margin-bottom: 10px;
        }
        .infra-card {
            background: #ffffff;
            border: 1px solid #cbd5e1;
            border-top: 3px solid #0284c7;
            border-radius: 7px;
            padding: 8px 10px;
        }
        .infra-card h4 {
            margin: 0 0 3px 0;
            font-size: 9px;
            font-weight: 800;
            color: #0f172a;
            text-transform: uppercase;
        }
        .infra-card .infra-highlight {
            font-size: 10.5px;
            font-weight: 700;
            color: #0369a1;
            margin-bottom: 3px;
        }
        .infra-card p {
            margin: 0;
            font-size: 9px;
            color: #475569;
        }

        /* BARRA DE LOS 9 BÁSICOS DE LA ANCI */
        .anci-bar {
            background: #f8fafc;
            border: 1px solid #cbd5e1;
            border-radius: 8px;
            padding: 8px 10px;
            margin-bottom: 11px;
        }
        .anci-bar-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 7px;
            border-bottom: 1px solid #e2e8f0;
            padding-bottom: 4px;
        }
        .anci-bar-title {
            font-size: 9.8px;
            font-weight: 800;
            color: #0f172a;
            text-transform: uppercase;
        }
        .anci-bar-legend {
            font-size: 8.5px;
            color: #475569;
            display: flex;
            gap: 8px;
            align-items: center;
        }
        .legend-dot {
            display: inline-block;
            width: 8px;
            height: 8px;
            border-radius: 50%;
            margin-right: 3px;
            vertical-align: middle;
        }
        .anci-circles-grid {
            display: grid;
            grid-template-columns: repeat(9, 1fr);
            gap: 4px;
            text-align: center;
        }
        .anci-item {
            display: flex;
            flex-direction: column;
            align-items: center;
            padding: 3px 2px;
        }
        .anci-circle {
            width: 26px;
            height: 26px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 10.5px;
            font-weight: 800;
            margin-bottom: 3px;
        }
        .circle-VERDE {
            background-color: #16a34a;
            color: #ffffff;
            border: 2px solid #15803d;
        }
        .circle-NARANJA {
            background-color: #f97316;
            color: #ffffff;
            border: 2px solid #c2410c;
        }
        .circle-ROJO {
            background-color: #dc2626;
            color: #ffffff;
            border: 2px solid #b91c1c;
        }
        .circle-GRIS {
            background-color: #f1f5f9;
            color: #64748b;
            border: 1.5px dashed #94a3b8;
        }
        .anci-name {
            font-size: 8px;
            font-weight: 700;
            color: #1e293b;
            line-height: 1.15;
            margin-bottom: 1px;
        }
        .anci-scope {
            font-size: 7.2px;
            color: #64748b;
        }

        /* TÍTULOS DE SECCIÓN */
        .section-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            background: #0f172a;
            color: #ffffff;
            padding: 6px 10px;
            border-radius: 6px;
            margin: 10px 0 8px 0;
        }
        .section-header h2 {
            margin: 0;
            font-size: 11px;
            font-weight: 800;
            text-transform: uppercase;
            letter-spacing: 0.3px;
        }
        .section-header span {
            font-size: 8.8px;
            color: #38bdf8;
            font-weight: 700;
        }

        /* RESUMEN INTEGRADO EN LA RADIOGRAFÍA */
        .integrated-impact-banner {
            background: #f8fafc;
            border: 1px solid #cbd5e1;
            border-left: 4px solid #0284c7;
            border-radius: 6px;
            padding: 7px 10px;
            margin-bottom: 8px;
            font-size: 9.4px;
            color: #334155;
        }
        .integrated-impact-banner strong {
            color: #0f172a;
        }

        /* SEMÁFORO DE 14 PUNTOS */
        .semaforo-grid {
            display: flex;
            flex-direction: column;
            gap: 6px;
            margin-bottom: 10px;
        }
        .point-card {
            width: 100%;
            background: #ffffff;
            border: 1px solid #e2e8f0;
            border-radius: 6px;
            padding: 7px 9px;
        }
        .point-card-crit { border-left: 3.5px solid #dc2626; }
        .point-card-warn { border-left: 3.5px solid #f59e0b; }
        .point-card-ok { border-left: 3.5px solid #16a34a; }
        .point-top {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 3px;
        }
        .point-title {
            font-size: 9.6px;
            font-weight: 800;
            color: #0f172a;
        }
        .pill {
            padding: 1.5px 6px;
            border-radius: 10px;
            font-size: 7.8px;
            font-weight: 800;
            text-transform: uppercase;
            flex-shrink: 0;
        }
        .pill-PELIGRO { background: #fee2e2; color: #991b1b; }
        .pill-ATENCIÓN { background: #fef3c7; color: #92400e; }
        .pill-BIEN { background: #dcfce7; color: #166534; }
        .point-body {
            font-size: 8.9px;
            color: #334155;
            margin: 0;
        }
        .sub-alert {
            margin-top: 4px;
            padding: 4px 6px;
            border-radius: 4px;
            font-size: 8.3px;
            background: #fff1f2;
            color: #881337;
            border: 1px solid #fecdd3;
        }
        .sub-warn {
            margin-top: 4px;
            padding: 4px 6px;
            border-radius: 4px;
            font-size: 8.3px;
            background: #fffbeb;
            color: #78350f;
            border: 1px solid #fde68a;
        }

        /* PLAN DE ACCIÓN SIN FONDO NEGRO */
        .action-card {
            background: #ffffff;
            border: 1px solid #cbd5e1;
            border-radius: 7px;
            padding: 8px 10px;
            margin-bottom: 7px;
        }
        .action-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 4px;
        }
        .badge-provider {
            background: #e0f2fe;
            color: #0369a1;
            padding: 2px 7px;
            border-radius: 4px;
            font-weight: 800;
            font-size: 8.5px;
            text-transform: uppercase;
        }
        .action-comp {
            font-size: 8.8px;
            color: #64748b;
            font-weight: 700;
        }
        .action-title {
            font-size: 9.8px;
            font-weight: 700;
            color: #0f172a;
            margin-bottom: 5px;
        }
        /* CAJA DE MENSAJE CLARA Y LIMPIA (SIN FONDO NEGRO) */
        .msg-box-clean {
            background: #f8fafc;
            color: #1e293b;
            border: 1px solid #cbd5e1;
            border-left: 4px solid #2563eb;
            padding: 7px 9px;
            border-radius: 5px;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            font-size: 9px;
            line-height: 1.42;
            white-space: pre-wrap;
            word-break: break-word;
        }

        /* PIE DE PÁGINA MÍNIMO */
        .clean-footer {
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-top: 1px solid #cbd5e1;
            padding-top: 6px;
            margin-top: 10px;
            font-size: 8.5px;
            color: #64748b;
        }
        .clean-footer strong {
            color: #0f172a;
        }
    </style>
</head>
<body>
    {% set dns = telemetria.dns if telemetria and telemetria.dns else {} %}
    {% set web = telemetria.web if telemetria and telemetria.web else {} %}
    {% set puertos = telemetria.puertos if telemetria and telemetria.puertos else {} %}
    {% set identidad = telemetria.identidad if telemetria and telemetria.identidad else {} %}
    {% set typo = telemetria.typosquatting if telemetria and telemetria.typosquatting else {} %}
    {% set shadow = telemetria.shadow_dns if telemetria and telemetria.shadow_dns else {} %}
    {% set cloud = telemetria.cloud_leaks if telemetria and telemetria.cloud_leaks else {} %}
    {% set asn = dns.asn_sovereignty if dns and dns.asn_sovereignty else {} %}
    {% set hprof = dns.hosting_profile if dns and dns.hosting_profile else {} %}
    {% set rdap = shadow.domain_registration_rdap if shadow and shadow.domain_registration_rdap else {} %}
    {% set ssl = web.ssl_certificate if web and web.ssl_certificate else {} %}
    {% set code_aud = web.code_security_audit if web and web.code_security_audit else {} %}
    {% set sho = puertos.passive_internetdb_intel if puertos and puertos.passive_internetdb_intel else {} %}
    {% set sso = identidad.corporate_sso_federation if identidad and identidad.corporate_sso_federation else {} %}
    {% set open_pages = reporte.resumen_paginas_abiertas if reporte and reporte.resumen_paginas_abiertas else {} %}
    {% set anci9 = reporte.anci_9_basicos if reporte and reporte.anci_9_basicos else {} %}

    <!-- CABECERA EJECUTIVA -->
    <div class="top-banner avoid-cut">
        <div class="top-banner-left">
            <div class="eyebrow">GLOBAL365 SPA | INFORME PARA GERENCIA Y DIRECTORIO | LEY N° 21.663 (ANCI) & LEY N° 21.719</div>
            <h1>DIAGNÓSTICO EJECUTIVO DE RIESGO DIGITAL Y SEGURIDAD WEB</h1>
        </div>
        <div class="top-banner-right">
            <div class="label">EMPRESA EVALUADA ({{ fecha }})</div>
            <div class="domain-title">{{ target }}</div>
        </div>
    </div>

    <!-- 5 KPIS SUPERIORES -->
    {% set score = reporte.resumen_ejecutivo.puntaje_global if reporte and reporte.resumen_ejecutivo else 0 %}
    {% set grade = reporte.resumen_ejecutivo.calificacion_postura if reporte and reporte.resumen_ejecutivo else 'C' %}
    {% set dmarc_ok = dns.dmarc.present if dns and dns.dmarc is mapping else False %}
    {% set clones_count = typo.active_lookalikes_count or typo.mail_ready_clones_count or 0 %}
    {% set cves_count = (sho.vulns or []) | length %}
    {% set leaks_count = (identidad.combolist_intelligence.total_leaks if identidad and identidad.combolist_intelligence else 0) or (identidad.compromised_employees or 0) %}

    <div class="kpi-row avoid-cut">
        <div class="kpi-card">
            <div class="kpi-title">1. Nota de Seguridad</div>
            <div class="kpi-main {{ 'text-danger' if grade in ['D', 'F'] else ('text-warn' if grade == 'C' else 'text-ok') }}">
                {{ score }}% — NOTA {{ grade }}
            </div>
            <div class="kpi-sub">{{ 'Riesgo Crítico' if grade in ['D', 'F'] else ('Riesgo Moderado' if grade == 'C' else 'Postura Saludable') }}</div>
        </div>
        <div class="kpi-card">
            <div class="kpi-title">2. Protección Correos</div>
            <div class="kpi-main {{ 'text-ok' if dmarc_ok else 'text-danger' }}">
                {{ 'PROTEGIDO' if dmarc_ok else 'DESPROTEGIDO' }}
            </div>
            <div class="kpi-sub">{{ 'Filtro anti-suplantación activo' if dmarc_ok else 'Pueden falsificar su correo' }}</div>
        </div>
        <div class="kpi-card">
            <div class="kpi-title">3. Suplantación Marca</div>
            <div class="kpi-main {{ 'text-danger' if clones_count > 0 else 'text-ok' }}">
                {{ clones_count }} {{ 'DOMINIO GEMELO' if clones_count == 1 else 'DOMINIOS GEMELOS' }}
            </div>
            <div class="kpi-sub">{{ 'Riesgo activo de estafa BEC' if clones_count > 0 else 'Sin clones activos detectados' }}</div>
        </div>
        <div class="kpi-card">
            <div class="kpi-title">4. Sitios y Fallas Web</div>
            <div class="kpi-main {{ 'text-danger' if cves_count > 0 else 'text-ok' }}">
                {{ open_pages.get('total_open_web_sites', 1) }} {{ 'SITIO' if open_pages.get('total_open_web_sites', 1) == 1 else 'SITIOS' }} / {{ cves_count }} FALLAS
            </div>
            <div class="kpi-sub">
                {% if (open_pages.get('additional_open_pages_count') or 0) > 0 %}
                    +{{ open_pages.get('additional_open_pages_count') }} páginas anexas abiertas
                {% else %}
                    1 sitio web principal activo
                {% endif %}
            </div>
        </div>
        <div class="kpi-card">
            <div class="kpi-title">5. Claves Filtradas</div>
            <div class="kpi-main {{ 'text-danger' if leaks_count > 0 else 'text-ok' }}">
                {{ leaks_count }} {{ 'FILTRACIONES' if leaks_count != 1 else 'FILTRACIÓN' }}
            </div>
            <div class="kpi-sub">{{ 'Claves expuestas en Dark Web' if leaks_count > 0 else 'Sin claves en Dark Web ni Combolists' }}</div>
        </div>
    </div>

    <!-- 3 RECUADROS DE PROPIEDAD E INFRAESTRUCTURA -->
    <div class="infra-row avoid-cut">
        <div class="infra-card">
            <h4>1. Empresa de Hosting y Ubicación Web</h4>
            <div class="infra-highlight">
                {{ hprof.get('provider_display') or asn.get('isp_org') or 'Proveedor Cloud' }} ({{ asn.get('country') or 'Exterior' }})
            </div>
            <p>
                {% if asn.get('hosted_in_chile') %}
                    Sus servidores operan físicamente en Chile bajo jurisdicción nacional.
                {% else %}
                    Datos alojados físicamente en {{ asn.get('country') or 'el extranjero' }}. La Ley N° 21.719 exige resguardar el flujo internacional de datos.
                {% endif %}
            </p>
        </div>
        <div class="infra-card">
            <h4>2. Propiedad de su Nombre (NIC Chile)</h4>
            <div class="infra-highlight">
                {% if rdap.get('days_until_expiration') is not none %}
                    Al día (Vence en {{ rdap.get('days_until_expiration') }} días: {{ rdap.get('expiration_date') }})
                {% else %}
                    Registro Activo ({{ rdap.get('registry') or 'NIC Chile' }})
                {% endif %}
            </div>
            <p>Es el arriendo oficial del nombre de su empresa en internet. Si vence, terceros pueden inscribirlo y dejarlo sin página web ni correos.</p>
        </div>
        <div class="infra-card">
            <h4>3. Candado de Seguridad Web (SSL)</h4>
            <div class="infra-highlight">
                {{ 'Activo' if ssl.get('valid', True) else 'Inactivo / Riesgo' }}
                ({% if ssl.get('days_until_expiry') is not none %}Vence en {{ ssl.get('days_until_expiry') }} días{% endif %} {{ ssl.get('tls_version') or 'TLS' }})
            </div>
            <p>Es el candado que cifra los datos que ingresan sus clientes. Si caduca, los navegadores bloquean su página con alerta de "Sitio Peligroso".</p>
        </div>
    </div>

    <!-- BARRA DE LOS 9 BÁSICOS DE LA ANCI -->
    {% if anci9 and anci9.get('items') %}
    <div class="anci-bar avoid-cut">
        <div class="anci-bar-header">
            <div class="anci-bar-title">
                Indicador de Cobertura ANCI — Los 9 Básicos de Ciberseguridad ({{ anci9.get('covered_by_recon_count', 4) }}/9 Auditados por SentinelRecon)
            </div>
            <div class="anci-bar-legend">
                <span><i class="legend-dot" style="background:#16a34a;"></i>Cumple</span>
                <span><i class="legend-dot" style="background:#f97316;"></i>Atención</span>
                <span><i class="legend-dot" style="background:#dc2626;"></i>En Riesgo</span>
                <span><i class="legend-dot" style="background:#cbd5e1; border:1px dashed #64748b;"></i>Control Interno PCs (5/9)</span>
            </div>
        </div>
        <div class="anci-circles-grid">
            {% for item in anci9.get('items', []) %}
            <div class="anci-item">
                <div class="anci-circle circle-{{ item.color }}">{{ item.numero }}</div>
                <div class="anci-name">{{ item.nombre_corto }}</div>
                <div class="anci-scope">
                    {% if item.audited_by_recon %}
                        <strong>{{ item.estado }}</strong>
                    {% else %}
                        {{ item.alcance_label }}
                    {% endif %}
                </div>
            </div>
            {% endfor %}
        </div>
    </div>
    {% endif %}

    <!-- SECCIÓN 1: RADIOGRAFÍA PROFUNDA EN 14 PUNTOS (FUSIONADA CON EL IMPACTO DE NEGOCIO Y MARCO LEGAL) -->
    <div class="section-header avoid-cut">
        <h2>1. Radiografía Profunda de su Empresa en 14 Puntos Clave (Infraestructura, Páginas Abiertas, Código y Dark Web)</h2>
        <span>SEMÁFORO EJECUTIVO v2.3</span>
    </div>

    <div class="integrated-impact-banner avoid-cut">
        <strong>Resumen de Impacto Operacional y Marco Legal (Ley N° 21.663 & Ley N° 21.719):</strong>
        {{ reporte.resumen_ejecutivo.impacto_operacional }} {{ reporte.resumen_ejecutivo.exposicion_regulatoria }}
    </div>

    {% set eol_list = code_aud.get('eol_software_detected') or [] %}
    {% set js_list = code_aud.get('outdated_js_libraries') or [] %}
    {% set neighbors_count = (dns.shared_hosting_forensics.neighbor_domains_count if dns and dns.shared_hosting_forensics else 0) %}
    {% set extra_pages_count = open_pages.get('additional_open_pages_count') or 0 %}
    {% set extra_pages_list = open_pages.get('additional_pages') or [] %}

    <div class="semaforo-grid">
        <!-- Punto 1 -->
        <div class="point-card {{ 'point-card-warn' if not asn.get('hosted_in_chile') or neighbors_count > 0 else 'point-card-ok' }} avoid-cut">
            <div class="point-top">
                <span class="point-title">1. ¿Quién aloja su web y en qué país están sus datos?</span>
                <span class="pill {{ 'pill-ATENCIÓN' if not asn.get('hosted_in_chile') or neighbors_count > 0 else 'pill-BIEN' }}">
                    {{ 'ATENCIÓN' if not asn.get('hosted_in_chile') or neighbors_count > 0 else 'BIEN' }}
                </span>
            </div>
            <p class="point-body">
                Administrado vía <strong>{{ hprof.get('provider_display') or asn.get('isp_org') or 'Hosting' }}</strong> con datos físicos en <strong>{{ asn.get('country') or 'Exterior' }}</strong>.
                {% if not asn.get('hosted_in_chile') %}La Ley N° 21.719 exige declarar el flujo internacional de datos.{% endif %}
            </p>
            {% if neighbors_count > 0 %}
            <div class="sub-warn">
                <strong>INFRAESTRUCTURA COMPARTIDA ({{ neighbors_count }} vecinos en la misma IP):</strong> Si un sitio vecino sufre un ataque o cae en listas de Spam, puede afectar la disponibilidad de su empresa.
            </div>
            {% endif %}
        </div>

        <!-- Punto 2 -->
        <div class="point-card {{ 'point-card-ok' if ssl.get('valid', True) else 'point-card-crit' }} avoid-cut">
            <div class="point-top">
                <span class="point-title">2. ¿Es segura la conexión de sus clientes a su web?</span>
                <span class="pill {{ 'pill-BIEN' if ssl.get('valid', True) else 'pill-PELIGRO' }}">{{ 'BIEN' if ssl.get('valid', True) else 'PELIGRO' }}</span>
            </div>
            <p class="point-body">
                Su candado web (SSL) está {{ 'vigente' if ssl.get('valid', True) else 'vencido o inválido' }}
                {% if ssl.get('days_until_expiry') is not none %}por {{ ssl.get('days_until_expiry') }} días{% endif %}
                y usa tecnología <strong>{{ ssl.get('tls_version') or 'TLS' }}</strong>. Protege la navegación de los visitantes.
            </p>
        </div>

        <!-- Punto 3 -->
        <div class="point-card {{ 'point-card-ok' if dmarc_ok else 'point-card-crit' }} avoid-cut">
            <div class="point-top">
                <span class="point-title">3. ¿Pueden falsificar sus correos o su dominio?</span>
                <span class="pill {{ 'pill-BIEN' if dmarc_ok else 'pill-PELIGRO' }}">{{ 'BIEN' if dmarc_ok else 'PELIGRO' }}</span>
            </div>
            <p class="point-body">
                Bloqueo de correos falsos (DMARC): <strong>{{ 'Activo' if dmarc_ok else 'Desactivado' }}</strong>.
                {% if not dmarc_ok %}Hoy terceros pueden enviar correos falsos usando el nombre de su empresa para desviar pagos de facturas (Fraude BEC).{% else %}Sus correos cuentan con validación anti-suplantación.{% endif %}
            </p>
        </div>

        <!-- Punto 4 -->
        <div class="point-card {{ 'point-card-ok' if sso.get('uses_entra_id') else 'point-card-warn' }} avoid-cut">
            <div class="point-top">
                <span class="point-title">4. ¿Cuentan con control centralizado de accesos (MFA)?</span>
                <span class="pill {{ 'pill-BIEN' if sso.get('uses_entra_id') else 'pill-ATENCIÓN' }}">{{ 'BIEN' if sso.get('uses_entra_id') else 'ATENCIÓN' }}</span>
            </div>
            <p class="point-body">
                {% if sso.get('uses_entra_id') %}
                    Cuentan con federación corporativa Microsoft Entra ID / M365 para control centralizado de identidades.
                {% else %}
                    No utilizan acceso corporativo blindado de Microsoft 365; las contraseñas individuales son más vulnerables a robo.
                {% endif %}
            </p>
        </div>

        <!-- Punto 5 -->
        <div class="point-card {{ 'point-card-crit' if cves_count > 0 or (eol_list | length) > 0 else 'point-card-ok' }} avoid-cut">
            <div class="point-top">
                <span class="point-title">5. ¿Su servidor web tiene fallas o tecnología vencida?</span>
                <span class="pill {{ 'pill-PELIGRO' if cves_count > 0 or (eol_list | length) > 0 else 'pill-BIEN' }}">
                    {{ 'PELIGRO' if cves_count > 0 or (eol_list | length) > 0 else 'BIEN' }}
                </span>
            </div>
            <p class="point-body">
                {% if cves_count > 0 %}
                    Su servidor acumula <strong>{{ cves_count }} vulnerabilidades públicas</strong> ({{ (sho.vulns or [])[:3] | join(', ') }}) por falta de actualización, permitiendo atacar o botar el sitio web.
                {% else %}
                    No se detectaron vulnerabilidades públicas (CVEs) expuestas en el servidor principal.
                {% endif %}
            </p>
            {% if (eol_list | length) > 0 %}
            <div class="sub-alert">
                <strong>TECNOLOGÍA VENCIDA:</strong> {{ eol_list[0].get('product', 'Software base') }} {{ eol_list[0].get('version', '') }} cerró su ciclo de soporte ({{ eol_list[0].get('eol_date', 'EOL') }}).
            </div>
            {% endif %}
        </div>

        <!-- Punto 6 -->
        <div class="point-card {{ 'point-card-crit' if clones_count > 0 else 'point-card-ok' }} avoid-cut">
            <div class="point-top">
                <span class="point-title">6. ¿Alguien ha creado un dominio parecido al suyo?</span>
                <span class="pill {{ 'pill-PELIGRO' if clones_count > 0 else 'pill-BIEN' }}">{{ 'PELIGRO' if clones_count > 0 else 'BIEN' }}</span>
            </div>
            <p class="point-body">
                {% if clones_count > 0 %}
                    Existe <strong>{{ clones_count }} dominio casi idéntico activo</strong> registrado en internet, creando alto riesgo de desvío de pagos o estafas a sus clientes o pacientes.
                {% else %}
                    No se detectaron dominios gemelos activos que suplanten el nombre de su empresa.
                {% endif %}
            </p>
        </div>

        <!-- Punto 7 -->
        <div class="point-card {{ 'point-card-crit' if (js_list | length) > 0 else 'point-card-ok' }} avoid-cut">
            <div class="point-top">
                <span class="point-title">7. ¿El código de su web es vulnerable (PHP / Scripts)?</span>
                <span class="pill {{ 'pill-PELIGRO' if (js_list | length) > 0 else 'pill-BIEN' }}">{{ 'PELIGRO' if (js_list | length) > 0 else 'BIEN' }}</span>
            </div>
            <p class="point-body">
                Blindaje contra inyección de código (CSP/HSTS): <strong>{{ 'Activo' if web.get('hsts') else 'Ausente' }}</strong>.
                {% if (js_list | length) > 0 %}
                    Se detectaron librerías web vencidas ({{ js_list[0].get('library', 'JS') }} {{ js_list[0].get('version', '') }}) vulnerables a inyección de código malicioso en formularios.
                {% else %}
                    Sin librerías JavaScript obsoletas críticas detectadas en la portada.
                {% endif %}
            </p>
        </div>

        <!-- Punto 8 -->
        {% set exp_files = (web.exposure_audit.exposed_sensitive_files_count if web and web.exposure_audit else 0) %}
        <div class="point-card {{ 'point-card-crit' if exp_files > 0 else 'point-card-ok' }} avoid-cut">
            <div class="point-top">
                <span class="point-title">8. ¿Hay archivos internos o respaldos a la vista?</span>
                <span class="pill {{ 'pill-PELIGRO' if exp_files > 0 else 'pill-BIEN' }}">{{ 'PELIGRO' if exp_files > 0 else 'BIEN' }}</span>
            </div>
            <p class="point-body">
                Archivos de programación/APIs: <strong>{{ 'Expuestos' if exp_files > 0 else 'Bien ocultos' }}</strong> | Respaldos o claves (<code>.env/.zip</code>): <strong>{{ exp_files }} Expuestos</strong>.
            </p>
        </div>

        <!-- Punto 9 -->
        {% set rbl_listed = dns.rbl_reputation.blacklisted if dns and dns.rbl_reputation else False %}
        <div class="point-card {{ 'point-card-crit' if rbl_listed else 'point-card-ok' }} avoid-cut">
            <div class="point-top">
                <span class="point-title">9. ¿Sus correos caen en Listas Negras de Spam?</span>
                <span class="pill {{ 'pill-PELIGRO' if rbl_listed else 'pill-BIEN' }}">{{ 'PELIGRO' if rbl_listed else 'BIEN' }}</span>
            </div>
            <p class="point-body">
                {{ 'El servidor figura en listas negras de Spam, bloqueando el envío de correos.' if rbl_listed else 'El servidor de su empresa no figura bloqueado en listas negras internacionales de Spam.' }}
            </p>
        </div>

        <!-- Punto 10 -->
        {% set open_buckets = cloud.public_leaking_buckets_count if cloud else 0 %}
        {% set shadow_ai = puertos.shadow_ai_exposed_count if puertos else 0 %}
        <div class="point-card {{ 'point-card-crit' if open_buckets > 0 or shadow_ai > 0 else 'point-card-ok' }} avoid-cut">
            <div class="point-top">
                <span class="point-title">10. ¿Hay bases de datos o IA abiertas por error?</span>
                <span class="pill {{ 'pill-PELIGRO' if open_buckets > 0 or shadow_ai > 0 else 'pill-BIEN' }}">{{ 'PELIGRO' if open_buckets > 0 or shadow_ai > 0 else 'BIEN' }}</span>
            </div>
            <p class="point-body">
                Bases de datos en la nube abiertas: <strong>{{ open_buckets }}</strong> | Sistemas de Inteligencia Artificial sin clave: <strong>{{ shadow_ai }}</strong>.
            </p>
        </div>

        <!-- Punto 11 -->
        {% set gh_leaks = identidad.github_code_leaks.github_leaks_count if identidad and identidad.github_code_leaks else 0 %}
        <div class="point-card {{ 'point-card-crit' if leaks_count > 0 or gh_leaks > 0 else 'point-card-ok' }} avoid-cut">
            <div class="point-top">
                <span class="point-title">11. ¿Hay claves en Combolists o código en GitHub?</span>
                <span class="pill {{ 'pill-PELIGRO' if leaks_count > 0 or gh_leaks > 0 else 'pill-BIEN' }}">{{ 'PELIGRO' if leaks_count > 0 or gh_leaks > 0 else 'BIEN' }}</span>
            </div>
            <p class="point-body">
                Cuentas en Combolists/Dark Web: <strong>{{ leaks_count }}</strong> | Código público en GitHub: <strong>{{ gh_leaks }} coincidencias</strong>.
            </p>
        </div>

        <!-- Punto 12: BUSCADOR DE PÁGINAS ABIERTAS Y PORTALES OLVIDADOS -->
        <div class="point-card {{ 'point-card-warn' if extra_pages_count > 0 else 'point-card-ok' }} avoid-cut">
            <div class="point-top">
                <span class="point-title">12. ¿Cuántas páginas o portales anexos tienen abiertos?</span>
                <span class="pill {{ 'pill-ATENCIÓN' if extra_pages_count > 0 else 'pill-BIEN' }}">{{ open_pages.get('status_badge', 'BIEN') }}</span>
            </div>
            <p class="point-body">
                <strong>{{ open_pages.get('headline', '1 Sitio Web Principal activo — Sin páginas secundarias olvidadas') }}</strong>.
                {% if extra_pages_count > 0 %}
                    Páginas anexas detectadas:
                    {% for p in extra_pages_list[:4] %}
                        <code>{{ p.get('subdomain') }}</code> ({{ p.get('page_title') or p.get('role') }}){% if not loop.last %}, {% endif %}
                    {% endfor %}.
                {% else %}
                    No se detectaron sitios antiguos de campañas, postulaciones ni paneles olvidados expuestos.
                {% endif %}
            </p>
        </div>

        <!-- Punto 13 -->
        {% set magecart = code_aud.ecommerce_magecart_risk.magecart_skimming_risk if code_aud and code_aud.ecommerce_magecart_risk else False %}
        <div class="point-card {{ 'point-card-crit' if magecart else 'point-card-ok' }} avoid-cut">
            <div class="point-top">
                <span class="point-title">13. ¿Sus pagos web o WhatsApp tienen riesgo de fraude?</span>
                <span class="pill {{ 'pill-PELIGRO' if magecart else 'pill-BIEN' }}">{{ 'PELIGRO' if magecart else 'BIEN' }}</span>
            </div>
            <p class="point-body">
                {{ 'Riesgo de interceptación en scripts de pasarela de pago.' if magecart else 'Sin exposición crítica en pasarelas de pago web.' }}
            </p>
        </div>

        <!-- Punto 14 -->
        {% set pdf_authors = (code_aud.public_documents_metadata.exposed_authors_or_users if code_aud and code_aud.public_documents_metadata else []) %}
        <div class="point-card {{ 'point-card-warn' if (pdf_authors | length) > 0 else 'point-card-ok' }} avoid-cut">
            <div class="point-top">
                <span class="point-title">14. ¿Los documentos PDF de su web filtran datos internos?</span>
                <span class="pill {{ 'pill-ATENCIÓN' if (pdf_authors | length) > 0 else 'pill-BIEN' }}">{{ 'ATENCIÓN' if (pdf_authors | length) > 0 else 'BIEN' }}</span>
            </div>
            <p class="point-body">
                {% if (pdf_authors | length) > 0 %}
                    Metadatos expuestos en PDFs públicos: {{ pdf_authors[:3] | join(', ') }}.
                {% else %}
                    Documentos públicos inspeccionados: sin exposición de nombres de usuarios internos en metadatos.
                {% endif %}
            </p>
        </div>
    </div>

        <!-- PIE DE PÁGINA MÍNIMO (SIN PUNTO 6 NI ANEXO TÉCNICO) -->
    <div class="clean-footer avoid-cut">
        <div>
            <strong>CERTIFICACIÓN DE VIGILANCIA DIGITAL GLOBAL365 SPA</strong> — Diagnóstico generado por SentinelRecon v2.3 conforme a los 9 Básicos de la ANCI (Ley N° 21.663) y Ley N° 21.719.
        </div>
        <div><strong>GLOBAL365 SPA</strong></div>
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
    """Renderiza el informe visual ejecutivo enriquecido con telemetría DRPS v2.3."""
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