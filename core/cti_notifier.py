# core/cti_notifier.py
import json
import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Dict, Any, List, Optional
import httpx
from pydantic import BaseModel, Field
from google import genai
from google.genai import types
from config import MODELO_GEMINI


class PatchLinkItem(BaseModel):
    label: str = Field(description="Nombre claro de la fuente oficial (ej. 'Parche Oficial Canonical Ubuntu USN', 'Release Oficial PHP.net / GitHub')")
    url: str = Field(description="URL directa al parche, release o advisory oficial")


class DeveloperZeroHourAdvisory(BaseModel):
    email_subject: str = Field(description="Asunto directo y urgente para el correo, ej: '⚠️ [Alerta Zero-Hour] Vulnerabilidad Crítica en PHP / Next.js (CVE-XXXX) - Parche Disponible'")
    whatsapp_tactical_summary: str = Field(description="Resumen de 2 a 3 líneas máximo para enviar por WhatsApp a Pablo avisando qué se detectó y que el borrador ya está en su Gmail.")
    affected_component_and_versions: str = Field(description="Tecnología del stack afectada y ramas/versiones vulnerables")
    technical_attack_vector: str = Field(description="Explicación técnica directa (de desarrollador a desarrollador) de cómo funciona el exploit (ej. inyección de argumentos CGI, deserialización en RSC, bypass en GoTrue) y qué logra el atacante.")
    immediate_mitigation_steps: List[str] = Field(description="Pasos concretos y rápidos para aplicar el parche o mitigar hoy mismo.")
    cli_patch_command: str = Field(description="Comando exacto de terminal (apt, npm, composer, flutter pub o docker) listo para copiar y pegar.")
    verification_command: str = Field(description="Comando seguro (ej. curl -I, dpkg -l, npm list) para que el desarrollador verifique que el parche quedó bien aplicado.")
    official_patch_links: List[PatchLinkItem]


def generate_developer_advisory_with_gemini(
    alert_item: Dict[str, Any],
    perimeter_profile: Dict[str, Any],
    client_name: str = "Cliente Desarrollador (EE.UU.)"
) -> Dict[str, Any]:
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        raise ValueError("Falta GEMINI_API_KEY en variables de entorno.")

    client = genai.Client(api_key=api_key)
    verified_urls = alert_item.get("patch_urls") or []

    system_instruction = """
    Eres un Principal Security Engineer redactando un advisory técnico para un Desarrollador Senior exigente.
    Stack del cliente: Node.js, React/Next.js, Flutter, PHP, MySQL, Supabase, PostgreSQL y Ubuntu Server.

    REGLAS DE INGENIERÍA ESTRICTAS (CERO ALUCINACIONES):
    1. PROHIBIDO INVENTAR URLs: En `official_patch_links` SOLO puedes utilizar las URLs exactas que vienen en el campo `patch_urls` de la señal de entrada. NUNCA inventes códigos GHSA-xxxx ni URLs de cisa.gov o github.com que no estén explícitamente en `patch_urls`.
    2. CLASIFICACIÓN HONESTA DEL COMPONENTE: Si la vulnerabilidad es del Kernel de Linux o de un paquete base de Ubuntu, clasifícala como 'Ubuntu Server / Linux Kernel' sin inventar que inyecta webshells de PHP a menos que el resumen original lo diga explícitamente.
    3. COMANDOS CLI SEGUROS DE PRODUCCIÓN:
       - PROHIBIDO incluir `&& sudo reboot` encadenado (indica que el reinicio debe programarse en ventana de mantenimiento).
       - PROHIBIDO agregar repositorios de terceros no oficiales como `ppa:ondrej/php`. Usa siempre los gestores estándar (`sudo apt update && sudo apt --only-upgrade install <paquete>`, `npm update`, `composer update`).
    4. VERIFICACIÓN REAL: En `verification_command`, entrega un comando real que inspeccione la versión instalada del paquete o el changelog de seguridad (ej. `dpkg -l | grep <paquete>`, `apt-cache policy <paquete>`, `php -v`, `npm list <paquete>`). PROHIBIDO usar `echo "OK"`.
    """

    prompt = f"""
    Analiza esta vulnerabilidad detectada en Hora Cero y genera el boletín técnico:
    SEÑAL VERIFICADA:
    {json.dumps(alert_item, indent=2, ensure_ascii=False)}

    PERFIL PERIMETRAL:
    {json.dumps(perimeter_profile, indent=2, ensure_ascii=False)}
    """

    response = client.models.generate_content(
        model=MODELO_GEMINI,
        contents=prompt,
        config=types.GenerateContentConfig(
            system_instruction=system_instruction,
            response_mime_type="application/json",
            response_schema=DeveloperZeroHourAdvisory,
            temperature=0.0,
        ),
    )

    advisory = json.loads(response.text or "{}")

    # Blindaje determinista en Python: sobrescribir cualquier link no verificado con las URLs reales de la API
    clean_links = []
    for u in verified_urls:
        label = "Aviso / Parche Oficial Verificado"
        if "git.kernel.org" in u:
            label = "Commit Oficial del Parche (Linux Kernel Git)"
        elif "ubuntu.com/security" in u:
            label = "Ubuntu Security Notice Oficial (Canonical)"
        elif "github.com" in u:
            label = "GitHub Security Advisory / Release Oficial"
        elif "nvd.nist.gov" in u:
            label = "Ficha Técnica Oficial NVD (NIST)"
        elif "osv.dev" in u:
            label = "Registro Oficial Google OSV.dev"
        clean_links.append({"label": label, "url": u})

    advisory["official_patch_links"] = clean_links
    return advisory


def render_advisory_email_html(
    advisory: Dict[str, Any],
    alert_item: Dict[str, Any],
    client_email: str = ""
) -> str:
    """Construye el correo HTML limpio, técnico y con botones directos a la descarga de parches."""
    links_html = "".join([
        f'<li style="margin-bottom:8px;"><a href="{lnk.get("url")}" target="_blank" style="color:#0284c7;font-weight:700;text-decoration:none;">🔗 {lnk.get("label")}</a> <span style="color:#64748b;font-size:11px;">({lnk.get("url")})</span></li>'
        for lnk in (advisory.get("official_patch_links") or [])
    ])

    steps_html = "".join([
        f'<li style="margin-bottom:6px;">{step}</li>'
        for step in (advisory.get("immediate_mitigation_steps") or [])
    ])

    exposed_badge = (
        '<span style="background:#fee2e2;color:#991b1b;padding:3px 8px;border-radius:4px;font-size:11px;font-weight:800;">EXPUESTO EN PERÍMETRO ACTIVO</span>'
        if alert_item.get("perimeter_verified_exposed")
        else '<span style="background:#fef3c7;color:#92400e;padding:3px 8px;border-radius:4px;font-size:11px;font-weight:800;">IMPACTO EN STACK CORE</span>'
    )

    return f"""
    <div style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;max-width:680px;margin:0 auto;color:#0f172a;background:#ffffff;border:1px solid #e2e8f0;border-radius:12px;overflow:hidden;">
        <div style="background:#041329;color:#ffffff;padding:18px 24px;border-bottom:3px solid #ffb786;">
            <div style="font-size:10px;text-transform:uppercase;letter-spacing:1px;color:#ffb786;font-weight:800;">SentinelRecon Zero-Hour Threat Intel</div>
            <h2 style="margin:6px 0 0 0;font-size:18px;font-weight:800;">{advisory.get('email_subject')}</h2>
        </div>
        <div style="padding:24px;font-size:13.5px;line-height:1.55;">
            <div style="display:flex;gap:10px;align-items:center;margin-bottom:16px;background:#f8fafc;padding:12px;border-radius:8px;border:1px solid #cbd5e1;">
                <div style="flex:1;">
                    <strong>ID Vulnerabilidad:</strong> <code>{alert_item.get('vuln_id')}</code> &nbsp;|&nbsp;
                    <strong>Score ZHR:</strong> <strong style="color:#dc2626;">{alert_item.get('zhr_score')}/100 ({alert_item.get('alert_tier')})</strong><br/>
                    <strong>Componente Afectado:</strong> {advisory.get('affected_component_and_versions')}
                </div>
                <div>{exposed_badge}</div>
            </div>

            <h3 style="font-size:14px;text-transform:uppercase;color:#0f172a;border-bottom:1px solid #e2e8f0;padding-bottom:6px;">1. Vector Técnico y Diagnóstico</h3>
            <p style="color:#334155;margin-top:8px;">{advisory.get('technical_attack_vector')}</p>

            <h3 style="font-size:14px;text-transform:uppercase;color:#0f172a;border-bottom:1px solid #e2e8f0;padding-bottom:6px;margin-top:20px;">2. Medidas a Adoptar y Parcheo Rápido</h3>
            <ol style="color:#334155;padding-left:20px;">{steps_html}</ol>

            <div style="background:#0f172a;color:#e2e8f0;padding:12px 16px;border-radius:8px;font-family:monospace;font-size:12px;margin:14px 0;">
                <div style="color:#38bdf8;font-size:10px;text-transform:uppercase;margin-bottom:4px;font-weight:bold;">Comando de Actualización / Mitigación Sugerido:</div>
                <code>{advisory.get('cli_patch_command')}</code>
                <div style="color:#4edea3;font-size:10px;text-transform:uppercase;margin-top:10px;margin-bottom:4px;font-weight:bold;">Verificación Post-Parche:</div>
                <code>{advisory.get('verification_command')}</code>
            </div>

            <h3 style="font-size:14px;text-transform:uppercase;color:#0f172a;border-bottom:1px solid #e2e8f0;padding-bottom:6px;margin-top:20px;">3. Enlaces Oficiales de Descarga de Parches</h3>
            <ul style="list-style:none;padding-left:0;margin-top:10px;">{links_html}</ul>

            <hr style="border:none;border-top:1px solid #e2e8f0;margin:20px 0;"/>
            <p style="font-size:11px;color:#64748b;margin:0;">
                Alerta temprana generada por <strong>Global365 SentinelRecon CTI</strong>. Fuente primaria: {alert_item.get('source')}.
            </p>
        </div>
    </div>
    """


async def dispatch_email_and_whatsapp_alert(
    advisory: Dict[str, Any],
    alert_item: Dict[str, Any],
    admin_email: str = "pablocaldera1984@gmail.com",
    client_email: str = ""
) -> Dict[str, Any]:
    """
    1. Envía el correo técnico con asunto limpio a pablocaldera1984@gmail.com.
    2. Dispara el aviso inmediato por WhatsApp al teléfono de Pablo.
    """
    status_report = {"email_dispatched": False, "whatsapp_dispatched": False, "errors": []}
    html_body = render_advisory_email_html(advisory, alert_item, client_email)

    # Asunto 100% limpio sin [REVISAR Y ENVIAR A CLIENTE]
    subject = advisory.get("email_subject") or f"⚠️ [Alerta Zero-Hour] {alert_item.get('vuln_id')} - Parche Disponible"

    smtp_user = os.getenv("GMAIL_USER", admin_email).strip()
    smtp_pass = os.getenv("GMAIL_APP_PASSWORD", "").strip()

    if smtp_pass:
        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"] = f"Global365 Security <{smtp_user}>"
            msg["To"] = admin_email
            msg.attach(MIMEText(html_body, "html", "utf-8"))

            with smtplib.SMTP_SSL("smtp.gmail.com", 465, timeout=10) as server:
                server.login(smtp_user, smtp_pass)
                server.sendmail(smtp_user, [admin_email], msg.as_string())
            status_report["email_dispatched"] = True
        except Exception as e:
            status_report["errors"].append(f"SMTP Error: {str(e)}")

    wa_message = (
        f"🚨 *SENTINEL ZERO-HOUR ALERT*\n"
        f"• *CVE/ID:* {alert_item.get('vuln_id')} ({alert_item.get('alert_tier')})\n"
        f"• *Stack:* {', '.join(alert_item.get('matched_technologies', []))}\n"
        f"• *Detalle:* {advisory.get('whatsapp_tactical_summary')}\n\n"
        f"📩 *Correo listo en tu bandeja ({admin_email}) con asunto: {subject}*"
    )

    wa_webhook_url = os.getenv(
        "SENTINEL_WHATSAPP_ENDPOINT",
        "https://enviar-alerta-sentinel-369266483091.us-central1.run.app/api/notificar-whatsapp"
    )
    admin_phone = os.getenv("ADMIN_WHATSAPP_PHONE", "").strip()

    try:
        async with httpx.AsyncClient(timeout=6.0) as client:
            resp = await client.post(
                wa_webhook_url,
                json={
                    "telefono": admin_phone,
                    "mensaje": wa_message,
                    "email_destino": admin_email,
                    "asunto_email": subject,
                    "html_email": html_body,
                    "cve_id": alert_item.get("vuln_id"),
                    "origen": "SENTINEL_ZERO_HOUR_CTI"
                }
            )
            if resp.status_code in (200, 201, 202):
                status_report["whatsapp_dispatched"] = True
    except Exception as e:
        status_report["errors"].append(f"WhatsApp Bridge Warning: {str(e)}")

    return {
        **status_report,
        "rendered_email_html": html_body,
        "whatsapp_preview": wa_message
    }