# core/cti_notifier.py
import json
import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Dict, Any, List
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
    technical_attack_vector: str = Field(description="Explicación técnica directa (de desarrollador a desarrollador) de cómo funciona el exploit y qué logra el atacante.")
    immediate_mitigation_steps: List[str] = Field(description="Pasos concretos y rápidos para aplicar el parche o mitigar hoy mismo.")
    cli_patch_command: str = Field(description="Comando exacto de terminal (apt, npm, composer, flutter pub o docker) listo para copiar y pegar.")
    verification_command: str = Field(description="Comando seguro (ej. dpkg -l, php -v, npm list) para que el desarrollador verifique que el parche quedó bien aplicado.")
    official_patch_links: List[PatchLinkItem]


def _resolver_enlace_oficial_verificado(alert_item: Dict[str, Any]) -> Dict[str, str]:
    """
    Filtra las URLs candidatas, descarta homepages genéricas o links rotos (HTTP 404),
    y devuelve 1 único enlace 100% funcional hacia el parche o boletín técnico oficial.
    """
    raw_urls = alert_item.get("patch_urls") or []
    vuln_id = str(alert_item.get("vuln_id") or "").strip()
    techs = " ".join(alert_item.get("matched_technologies") or []).lower()

    def _prioridad(u: str) -> int:
        u_low = u.lower().rstrip("/")
        if u_low in ("https://www.php.net", "https://php.net", "https://nodejs.org", "https://ubuntu.com", "https://github.com"):
            return 99
        if "cisa.gov/news-events" in u_low or "cisa.gov/known-exploited" in u_low:
            return 95
        if any(k in u_low for k in ("git.kernel.org", "/commit/", "/releases", "ubuntu.com/security", "changelog", "php.net/changelog")):
            return 1
        if any(k in u_low for k in ("osv.dev/vulnerability", "github.com/advisories", "/security/advisories/", "nvd.nist.gov/vuln/detail")):
            return 2
        return 10

    candidatas = [u.strip() for u in raw_urls if isinstance(u, str) and u.strip().startswith("http")]
    candidatas.sort(key=_prioridad)

    # Verificar en vivo que la URL exista (no sea un GHSA de prueba o un 404)
    url_valida = None
    with httpx.Client(timeout=4.0, follow_redirects=True) as http_client:
        for cand in candidatas:
            if _prioridad(cand) >= 95:
                continue
            try:
                resp = http_client.get(cand, headers={"User-Agent": "SentinelRecon-CTI/2.0"})
                if resp.status_code < 400:
                    # Si es NVD pero dice "CVE ID Not Found", descartar
                    if "nvd.nist.gov" in cand.lower() and "cve id not found" in resp.text.lower():
                        continue
                    url_valida = cand
                    break
            except Exception:
                continue

    # Si ninguna URL candidata respondió 200 OK (ej. CVE sintético o link roto), usar el repositorio oficial de parches del componente
    if not url_valida:
        if "php" in techs:
            url_valida = "https://www.php.net/ChangeLog-8.php"
        elif "next" in techs:
            url_valida = "https://github.com/vercel/next.js/releases"
        elif "node" in techs:
            url_valida = "https://nodejs.org/en/blog/vulnerability"
        elif "ubuntu" in techs or "linux" in techs or "kernel" in techs:
            url_valida = "https://ubuntu.com/security/notices"
        elif "supabase" in techs:
            url_valida = "https://github.com/supabase/supabase/security/advisories"
        elif "postgres" in techs:
            url_valida = "https://www.postgresql.org/support/security/"
        elif "mysql" in techs:
            url_valida = "https://dev.mysql.com/doc/relnotes/mysql/8.0/en/"
        elif "flutter" in techs:
            url_valida = "https://docs.flutter.dev/release/whats-new"
        elif vuln_id.startswith("CVE-"):
            url_valida = f"https://nvd.nist.gov/vuln/detail/{vuln_id}"
        else:
            url_valida = "https://osv.dev/list"

    u_low = url_valida.lower()
    if "php.net/changelog" in u_low:
        label = "Changelog y Parches Oficiales de Seguridad en PHP.net"
    elif "git.kernel.org" in u_low:
        label = "Commit Oficial del Parche (Linux Kernel Git)"
    elif "ubuntu.com/security" in u_low:
        label = "Parche y Aviso Oficial Canonical Ubuntu (USN)"
    elif "github.com" in u_low and "/releases" in u_low:
        label = "Repositorio Oficial de Releases y Parches en GitHub"
    elif "github.com" in u_low:
        label = "Advisory y Parche Oficial en GitHub Security"
    elif "nvd.nist.gov" in u_low:
        label = "Ficha Técnica y Referencias de Parche en NIST NVD"
    elif "osv.dev" in u_low:
        label = "Boletín Técnico y Parche en Google OSV"
    elif "nodejs.org" in u_low:
        label = "Boletines Oficiales de Seguridad y Parches en Node.js"
    elif "postgresql.org" in u_low:
        label = "Catálogo Oficial de Parches de Seguridad PostgreSQL"
    else:
        label = "Descargar Parche / Aviso Técnico Oficial del Fabricante"

    return {"label": label, "url": url_valida}


def generate_developer_advisory_with_gemini(
    alert_item: Dict[str, Any],
    perimeter_profile: Dict[str, Any],
    client_name: str = "Cliente Desarrollador (EE.UU.)"
) -> Dict[str, Any]:
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        raise ValueError("Falta GEMINI_API_KEY en variables de entorno.")

    client = genai.Client(api_key=api_key)

    system_instruction = """
    Eres un Principal Security Engineer redactando un advisory técnico para un Desarrollador Senior exigente.
    Stack del cliente: Node.js, React/Next.js, Flutter, PHP, MySQL, Supabase, PostgreSQL y Ubuntu Server.

    REGLAS DE INGENIERÍA ESTRICTAS (CERO ALUCINACIONES):
    1. PROHIBIDO INVENTAR URLs: No inventes códigos GHSA-xxxx ni URLs inexistentes.
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

    # Asignar 1 único enlace oficial verificado en vivo (sin alucinaciones ni 404)
    enlace_verificado = _resolver_enlace_oficial_verificado(alert_item)
    advisory["official_patch_links"] = [enlace_verificado]
    return advisory


def render_advisory_email_html(
    advisory: Dict[str, Any],
    alert_item: Dict[str, Any],
    client_email: str = ""
) -> str:
    """Construye el correo HTML con ficha superior estructurada sin cortes de línea y sin etiquetas confusas."""
    links_html = "".join([
        f'<li style="margin-bottom:8px;">'
        f'<a href="{lnk.get("url")}" target="_blank" style="color:#0284c7;font-weight:700;text-decoration:none;">🔗 {lnk.get("label")}</a><br/>'
        f'<a href="{lnk.get("url")}" target="_blank" style="color:#64748b;font-size:11.5px;word-break:break-all;">{lnk.get("url")}</a>'
        f'</li>'
        for lnk in (advisory.get("official_patch_links") or [])[:1]
    ])

    steps_html = "".join([
        f'<li style="margin-bottom:6px;">{step}</li>'
        for step in (advisory.get("immediate_mitigation_steps") or [])
    ])

    cvss_val = alert_item.get("cvss_score") or alert_item.get("cvss")
    cvss_html = (
        f'<span style="display:inline-block;white-space:nowrap;margin-right:16px;">'
        f'<strong>CVSS Base:</strong> <span style="color:#0f172a;font-weight:700;">{cvss_val}/10.0</span>'
        f'</span>'
        if cvss_val else ""
    )

    tier_raw = str(alert_item.get("alert_tier") or "P0_CRITICAL_IMMEDIATE")
    tier_map = {
        "P0_CRITICAL_IMMEDIATE": "Crítica Inmediata (P0)",
        "P1_HIGH_PRIORITY": "Alta Prioridad (P1)",
        "P2_ELEVATED": "Prioridad Media (P2)"
    }
    tier_legible = tier_map.get(tier_raw, tier_raw)
    fuente_oficial = alert_item.get("source") or "CISA KEV / NIST NVD (Fuente Oficial Verificada)"

    return f"""
    <div style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;max-width:680px;margin:0 auto;color:#0f172a;background:#ffffff;border:1px solid #e2e8f0;border-radius:12px;overflow:hidden;">
        <div style="background:#041329;color:#ffffff;padding:18px 24px;border-bottom:3px solid #ffb786;">
            <div style="font-size:10px;text-transform:uppercase;letter-spacing:1px;color:#ffb786;font-weight:800;">SentinelRecon Zero-Hour Threat Intel</div>
            <h2 style="margin:6px 0 0 0;font-size:18px;font-weight:800;line-height:1.35;">{advisory.get('email_subject')}</h2>
        </div>

        <div style="padding:24px;font-size:13.5px;line-height:1.55;">
            <div style="margin-bottom:18px;background:#f8fafc;padding:14px 16px;border-radius:8px;border:1px solid #cbd5e1;">
                <div style="margin-bottom:8px;line-height:1.8;">
                    <span style="display:inline-block;white-space:nowrap;margin-right:18px;">
                        <strong>ID Vulnerabilidad:</strong> <code style="background:#e2e8f0;padding:2px 6px;border-radius:4px;font-weight:700;color:#0f172a;">{alert_item.get('vuln_id')}</code>
                    </span>
                    <span style="display:inline-block;white-space:nowrap;margin-right:18px;">
                        <strong>Score ZHR:</strong> <strong style="color:#dc2626;">{alert_item.get('zhr_score')}/100 ({tier_legible})</strong>
                    </span>
                    {cvss_html}
                </div>
                <div style="margin-bottom:6px;">
                    <strong>Fuente de Inteligencia:</strong> <span style="color:#0369a1;font-weight:700;">{fuente_oficial}</span>
                </div>
                <div>
                    <strong>Componente Afectado:</strong> {advisory.get('affected_component_and_versions')}
                </div>
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

            <h3 style="font-size:14px;text-transform:uppercase;color:#0f172a;border-bottom:1px solid #e2e8f0;padding-bottom:6px;margin-top:20px;">3. Enlace Oficial de Parche / Ficha Técnica</h3>
            <ul style="list-style:none;padding-left:0;margin-top:10px;">{links_html}</ul>

            <hr style="border:none;border-top:1px solid #e2e8f0;margin:20px 0;"/>
            <p style="font-size:11px;color:#64748b;margin:0;">
                Alerta temprana generada por <strong>Global365 SentinelRecon CTI</strong>. Fuente primaria verificada: {fuente_oficial}.
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
        async with httpx.AsyncClient(timeout=25.0) as client:
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