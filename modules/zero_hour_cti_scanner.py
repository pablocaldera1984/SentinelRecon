# modules/zero_hour_cti_scanner.py
import asyncio
import hashlib
import json
import math
import os
import re
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, Any, List, Optional, Tuple
import httpx

# =====================================================================
# 1. DEFINICIÓN DEL STACK DEL CLIENTE Y ENDPOINTS DE HORA CERO (PRE-NVD)
# =====================================================================

CLIENT_TECH_STACK = [
    "node", "react", "nextjs", "flutter", "dart",
    "php", "mysql", "supabase", "gotrue", "postgrest",
    "postgresql", "postgres", "ubuntu", "openssh", "nginx"
]

# Paquetes ancla representativos para consulta masiva HTTP/2 en OSV.dev
OSV_WATCHLIST_QUERIES = [
    {"package": {"name": "next", "ecosystem": "npm"}},
    {"package": {"name": "react", "ecosystem": "npm"}},
    {"package": {"name": "express", "ecosystem": "npm"}},
    {"package": {"name": "@supabase/supabase-js", "ecosystem": "npm"}},
    {"package": {"name": "@supabase/auth-js", "ecosystem": "npm"}},
    {"package": {"name": "laravel/framework", "ecosystem": "Packagist"}},
    {"package": {"name": "symfony/symfony", "ecosystem": "Packagist"}},
    {"package": {"name": "guzzlehttp/psr7", "ecosystem": "Packagist"}},
    {"package": {"name": "http", "ecosystem": "Pub"}},
    {"package": {"name": "supabase_flutter", "ecosystem": "Pub"}},
]

# Repositorios Upstream donde los creadores publican parches en el Minuto Uno
GITHUB_UPSTREAM_ADVISORY_REPOS = [
    ("php/php-src", "PHP Core"),
    ("facebook/react", "React"),
    ("vercel/next.js", "Next.js / React Server Components"),
    ("nodejs/node", "Node.js Runtime"),
    ("supabase/auth", "Supabase Auth (GoTrue)"),
    ("supabase/supabase", "Supabase Platform / Studio"),
    ("PostgREST/postgrest", "Supabase PostgREST"),
    ("supabase/realtime", "Supabase Realtime"),
    ("dart-lang/sdk", "Flutter / Dart SDK")
]


class ExposureLevel(Enum):
    INTERNET_EXPOSED = 1.25      # Expuesto en puerto 443/22/3306 o ruta pública activa
    SUPPLY_CHAIN_MALWARE = 1.15  # Paquete malicioso npm/Pub/Composer (MAL-*)
    PRODUCTION_INTERNAL = 1.00   # Componente core del stack en producción
    TRANSITIVE_MITIGATED = 0.35  # No alcanzable directamente
    DEV_DEPENDENCY = 0.08        # Solo entorno local de desarrollo


# =====================================================================
# 2. MOTOR MATEMÁTICO DE PRIORIZACIÓN ANTI-FATIGA (ZHR SCORE)
# =====================================================================

class ZeroHourPrioritizer:
    """
    Calcula el Índice de Riesgo de Hora Cero (ZHR 0-100) con Compuertas de Sobrescritura.
    Evita que un Zero-Day con EPSS=0.0004 o sin CVSS en NVD pase desapercibido.
    """
    RCE_AUTH_REGEX = re.compile(
        r"\b(rce|remote code execution|unauthenticated|command injection|"
        r"os command|auth(?:entication)? bypass|deserialization|"
        r"sql injection|sqli|arbitrary code|php2shell|react2shell|zero-day|0-day)\b",
        re.IGNORECASE
    )

    HIGH_IMPACT_REGEX = re.compile(
        r"\b(ssrf|server-side request forgery|path traversal|directory traversal|"
        r"local file inclusion|lfi|privilege escalation|xxe)\b",
        re.IGNORECASE
    )

    @classmethod
    def infer_severity(cls, vuln_id: str, summary: str, cvss_score: Optional[float]) -> float:
        if vuln_id.upper().startswith("MAL-"):
            return 0.98
        if cvss_score is not None and cvss_score > 0:
            return min(1.0, float(cvss_score) / 10.0)
        if cls.RCE_AUTH_REGEX.search(summary or ""):
            return 0.98
        if cls.HIGH_IMPACT_REGEX.search(summary or ""):
            return 0.75
        return 0.55

    @classmethod
    def calculate_zhr(
        cls,
        vuln_id: str,
        summary: str,
        cvss_score: Optional[float] = None,
        epss_current: float = 0.0,
        epss_24h_ago: float = 0.0,
        has_nuclei_or_poc: bool = False,
        is_malicious_pkg: bool = False,
        social_velocity: float = 0.0,
        in_kev_or_exploited: bool = False,
        exposure: ExposureLevel = ExposureLevel.PRODUCTION_INTERNAL
    ) -> Tuple[float, str]:
        i_sev = cls.infer_severity(vuln_id, summary, cvss_score)

        delta_epss = max(0.0, epss_current - epss_24h_ago)
        p_epss = min(1.0, math.sqrt(max(0.0, epss_current)) + (3.5 * delta_epss))

        w_poc = min(
            1.0,
            (0.85 if has_nuclei_or_poc else 0.0)
            + (0.95 if is_malicious_pkg else 0.0)
            + (0.35 * min(1.0, social_velocity))
        )

        a_wild = 1.00 if in_kev_or_exploited else 0.0
        s_pond = (0.20 * i_sev) + (0.25 * p_epss) + (0.25 * w_poc) + (0.30 * a_wild)

        # Compuerta de Hora Cero: si está explotada in-the-wild o tiene PoC + RCE
        if a_wild >= 0.85:
            g_crit = 1.00
        elif (w_poc >= 0.75 or i_sev >= 0.90) and cls.RCE_AUTH_REGEX.search(summary or ""):
            g_crit = 0.90
        else:
            g_crit = 0.00

        eff_exp = ExposureLevel.SUPPLY_CHAIN_MALWARE.value if is_malicious_pkg else exposure.value
        zhr = min(100.0, round(eff_exp * (100.0 * max(g_crit, s_pond)), 2))

        if zhr >= 85.0:
            tier = "P0_CRITICAL_IMMEDIATE"
        elif zhr >= 68.0:
            tier = "P1_HIGH_URGENT"
        elif zhr >= 40.0:
            tier = "P2_SCHEDULED"
        else:
            tier = "P3_SUPPRESSED"

        return zhr, tier


# =====================================================================
# 3. FINGERPRINTING PERIMETRAL NO INTRUSIVO DEL STACK DEL CLIENTE (EE.UU.)
# =====================================================================

async def fingerprint_client_perimeter_stack(target_domain_or_ip: Optional[str]) -> Dict[str, Any]:
    """
    Inspecciona desde el exterior (sin agentes) qué tecnologías de las 8 del cliente
    están directamente expuestas al perímetro público para ajustar el multiplicador E_exp.
    """
    profile = {
        "target": target_domain_or_ip,
        "exposed_technologies": [],
        "detected_versions": {},
        "react_rsc_enabled": False,
        "supabase_endpoints_detected": False,
        "flutter_web_detected": False,
        "php_exposed": False,
        "ubuntu_ssh_banner": None,
        "shodan_cpes": [],
        "shodan_vulns": []
    }
    if not target_domain_or_ip:
        return profile

    clean_target = target_domain_or_ip.replace("https://", "").replace("http://", "").split("/")[0].strip().lower()
    headers = {"User-Agent": "Mozilla/5.0 SentinelRecon-ZeroHour/2.4"}

    async with httpx.AsyncClient(verify=False, timeout=3.5, headers=headers, follow_redirects=True) as client:
        # 1. Sonda principal HTTP/HTTPS (Cabeceras Node, PHP, React/Next.js RSC, Supabase)
        try:
            resp = await client.get(f"https://{clean_target}")
            h_map = {k.lower(): v for k, v in resp.headers.items()}
            html_body = resp.text[:40000] if resp.text else ""

            srv = h_map.get("server", "")
            x_pow = h_map.get("x-powered-by", "")
            vary = h_map.get("vary", "")

            if "php" in x_pow.lower() or "php" in srv.lower() or ".php" in html_body.lower():
                profile["php_exposed"] = True
                profile["exposed_technologies"].append("php")
                profile["detected_versions"]["php"] = x_pow or srv

            if "express" in x_pow.lower() or "next" in x_pow.lower() or "_next/static" in html_body:
                profile["exposed_technologies"].extend(["node", "react", "nextjs"])

            if "rsc" in vary.lower() or "next-router-state-tree" in vary.lower():
                profile["react_rsc_enabled"] = True
                if "react" not in profile["exposed_technologies"]:
                    profile["exposed_technologies"].append("react")

            if "ubuntu" in srv.lower():
                profile["exposed_technologies"].append("ubuntu")
                profile["detected_versions"]["ubuntu_web"] = srv

            # Detección de constantes Supabase en el bundle JS/HTML
            supa_match = re.search(r'https://([a-z0-9]{12,30})\.supabase\.co', html_body, re.I)
            if supa_match or "/rest/v1" in html_body or "/auth/v1" in html_body:
                profile["supabase_endpoints_detected"] = True
                profile["exposed_technologies"].extend(["supabase", "postgres"])
        except Exception:
            pass

        # 2. Sonda pasiva Flutter Web (/version.json)
        try:
            r_fl = await client.get(f"https://{clean_target}/version.json", timeout=2.0)
            if r_fl.status_code == 200 and "app_name" in r_fl.text:
                profile["flutter_web_detected"] = True
                profile["exposed_technologies"].append("flutter")
                profile["detected_versions"]["flutter_web"] = r_fl.json().get("version", "detected")
        except Exception:
            pass

        # 3. Sonda pasiva Supabase Self-Hosted GoTrue (/auth/v1/health)
        try:
            r_sb = await client.get(f"https://{clean_target}/auth/v1/health", timeout=2.0)
            if r_sb.status_code == 200 and ("gotrue" in r_sb.text.lower() or "version" in r_sb.text.lower()):
                profile["supabase_endpoints_detected"] = True
                profile["exposed_technologies"].extend(["supabase", "postgres"])
                profile["detected_versions"]["supabase_gotrue"] = r_sb.json().get("version")
        except Exception:
            pass

        # 4. Sonda pasiva Shodan InternetDB (Puertos 22, 3306, 5432 y CPEs sin tocar el firewall del cliente)
        try:
            import socket
            ip_addr = socket.gethostbyname(clean_target)
            r_sho = await client.get(f"https://internetdb.shodan.io/{ip_addr}", timeout=2.5)
            if r_sho.status_code == 200:
                s_data = r_sho.json()
                ports = s_data.get("ports", [])
                cpes = s_data.get("cpes", [])
                profile["shodan_cpes"] = cpes
                profile["shodan_vulns"] = s_data.get("vulns", [])
                if 22 in ports:
                    profile["exposed_technologies"].append("ubuntu")
                if 3306 in ports:
                    profile["exposed_technologies"].append("mysql")
                if 5432 in ports:
                    profile["exposed_technologies"].append("postgres")
                for cpe in cpes:
                    cpe_low = cpe.lower()
                    for tech in CLIENT_TECH_STACK:
                        if tech in cpe_low and tech not in profile["exposed_technologies"]:
                            profile["exposed_technologies"].append(tech)
        except Exception:
            pass

    profile["exposed_technologies"] = sorted(list(set(profile["exposed_technologies"])))
    return profile


# =====================================================================
# 4. RECOLECTORES ASÍNCRONOS DE HORA CERO (OSV, EUVD, USN, GHSA, CISA, HN)
# =====================================================================

def _matches_client_stack(text: str, keywords: Optional[List[str]] = None) -> List[str]:
    """Verifica qué tecnologías del stack del cliente están mencionadas en el aviso."""
    target_kws = keywords or CLIENT_TECH_STACK
    t_low = (text or "").lower()
    matched = []
    for kw in target_kws:
        if re.search(rf"\b{re.escape(kw.lower())}\b", t_low):
            matched.append(kw.upper())
    return sorted(list(set(matched)))


async def _fetch_euvd_zero_hour(client: httpx.AsyncClient) -> List[Dict[str, Any]]:
    """
    Consulta ENISA EUVD (/api/exploitedvulnerabilities y /api/criticalvulnerabilities).
    Sin API key, incluye anomalías tempranas de Shadowserver y EU/CISA KEV.
    """
    findings = []
    endpoints = [
        ("https://euvdservices.enisa.europa.eu/api/exploitedvulnerabilities", True),
        ("https://euvdservices.enisa.europa.eu/api/criticalvulnerabilities", False)
    ]
    for url, is_exploited in endpoints:
        try:
            resp = await client.get(url, timeout=6.0)
            if resp.status_code == 200:
                items = resp.json() if isinstance(resp.json(), list) else []
                for item in items:
                    desc = f"{item.get('id', '')} {item.get('description', '')} {json.dumps(item.get('enisaIdProduct', []))}"
                    matched_techs = _matches_client_stack(desc)
                    if not matched_techs:
                        continue

                    aliases = item.get("aliases", "") or ""
                    cve_match = re.search(r"CVE-\d{4}-\d{4,7}", f"{item.get('id', '')} {aliases}")
                    vuln_id = cve_match.group(0) if cve_match else item.get("id", "EUVD-ZERO-HOUR")

                    base_score = item.get("baseScore")
                    epss_raw = float(item.get("epss", 0.0) or 0.0)
                    # EUVD a veces entrega EPSS en porcentaje (0-100) o proporción (0-1)
                    epss_norm = epss_raw / 100.0 if epss_raw > 1.0 else epss_raw

                    refs_raw = item.get("references", "") or ""
                    ref_links = [r.strip() for r in refs_raw.splitlines() if r.strip().startswith("http")]

                    findings.append({
                        "vuln_id": vuln_id,
                        "source": "ENISA EUVD / Shadowserver",
                        "matched_technologies": matched_techs,
                        "summary": (item.get("description") or "Vulnerabilidad crítica detectada en EUVD")[:600],
                        "cvss_score": float(base_score) if base_score is not None else None,
                        "epss_score": epss_norm,
                        "in_kev_or_exploited": is_exploited,
                        "has_poc": is_exploited,
                        "patch_urls": ref_links[:5],
                        "published_at": item.get("datePublished") or datetime.now(timezone.utc).isoformat()
                    })
        except Exception:
            pass
    return findings


async def _fetch_ubuntu_usn_safe(client: httpx.AsyncClient) -> List[Dict[str, Any]]:
    """
    Consulta Ubuntu Security Notices (USN) con ?limit=10&offset=0 estricto
    para evitar el bug documentado de Timeouts 503/504 en Canonical.
    """
    findings = []
    try:
        resp = await client.get(
            "https://ubuntu.com/security/notices.json",
            params={"limit": 10, "offset": 0},
            timeout=6.0
        )
        if resp.status_code == 200:
            notices = resp.json().get("notices", [])
            for n in notices:
                title_desc = f"{n.get('title', '')} {n.get('summary', '')} {n.get('description', '')}"
                matched_techs = _matches_client_stack(title_desc)
                # En Ubuntu nos interesan especialmente avisos de kernel, openssh, php, mysql, postgresql, nginx o RCE
                if not matched_techs and "ubuntu" not in title_desc.lower():
                    continue
                if not matched_techs:
                    matched_techs = ["UBUNTU"]

                cves = n.get("cves_ids", []) or []
                primary_id = cves[0] if cves else n.get("id", "USN-NOTICE")
                usn_id = n.get("id", "")
                usn_url = f"https://ubuntu.com/security/notices/{usn_id}" if usn_id else "https://ubuntu.com/security/notices"

                findings.append({
                    "vuln_id": primary_id,
                    "source": f"Canonical Ubuntu ({usn_id})",
                    "matched_technologies": matched_techs,
                    "summary": f"[{n.get('title', usn_id)}] {(n.get('description') or n.get('summary') or '')[:500]}",
                    "cvss_score": None,
                    "epss_score": 0.0,
                    "in_kev_or_exploited": False,
                    "has_poc": False,
                    "patch_urls": [usn_url],
                    "published_at": n.get("published") or datetime.now(timezone.utc).isoformat()
                })
    except Exception:
        pass
    return findings


async def _fetch_github_upstream_advisories(client: httpx.AsyncClient) -> List[Dict[str, Any]]:
    """
    Monitorea directamente la pestaña Security Advisories de los repositorios oficiales
    de PHP, React, Next.js, Node.js, Supabase (GoTrue/PostgREST) y Flutter.
    """
    findings = []
    gh_headers = {"Accept": "application/vnd.github+json"}
    gh_token = os.getenv("GITHUB_TOKEN", "").strip()
    if gh_token:
        gh_headers["Authorization"] = f"Bearer {gh_token}"

    async def probe_repo(repo_slug: str, tech_label: str):
        url = f"https://api.github.com/repos/{repo_slug}/security-advisories?state=published&per_page=3"
        try:
            r = await client.get(url, headers=gh_headers, timeout=4.5)
            if r.status_code == 200 and isinstance(r.json(), list):
                for adv in r.json():
                    cve_id = adv.get("cve_id") or adv.get("ghsa_id")
                    sev = str(adv.get("severity") or "").lower()
                    cvss_val = adv.get("cvss", {}).get("score")
                    if not cvss_val:
                        cvss_val = 9.2 if sev == "critical" else (7.8 if sev == "high" else 5.0)

                    html_url = adv.get("html_url") or f"https://github.com/{repo_slug}/security/advisories"
                    findings.append({
                        "vuln_id": cve_id,
                        "source": f"GitHub Upstream ({repo_slug})",
                        "matched_technologies": [tech_label.upper()],
                        "summary": f"{adv.get('summary', '')} - {(adv.get('description') or '')[:450]}",
                        "cvss_score": float(cvss_val),
                        "epss_score": 0.0,
                        "in_kev_or_exploited": False,
                        "has_poc": True if sev == "critical" else False,
                        "patch_urls": [html_url],
                        "published_at": adv.get("published_at") or datetime.now(timezone.utc).isoformat()
                    })
        except Exception:
            pass

    await asyncio.gather(*(probe_repo(r, lbl) for r, lbl in GITHUB_UPSTREAM_ADVISORY_REPOS))
    return findings


async def _fetch_osv_batch_signals(client: httpx.AsyncClient) -> List[Dict[str, Any]]:
    """
    Consulta por lote (/v1/querybatch sobre HTTP/2) en OSV.dev de Google
    para paquetes clave de Node, React, Next.js, Supabase, PHP/Composer y Flutter/Pub.
    """
    findings = []
    try:
        resp = await client.post(
            "https://api.osv.dev/v1/querybatch",
            json={"queries": OSV_WATCHLIST_QUERIES},
            timeout=6.0
        )
        if resp.status_code == 200:
            results = resp.json().get("results", [])
            top_vuln_ids = []
            for idx, res in enumerate(results):
                vulns = res.get("vulns", []) or []
                pkg_name = OSV_WATCHLIST_QUERIES[idx]["package"]["name"]
                # Tomar solo el último aviso más reciente de cada paquete ancla
                if vulns:
                    latest_v = vulns[-1]
                    top_vuln_ids.append((latest_v.get("id"), pkg_name))

            async def fetch_osv_detail(v_id: str, pkg: str):
                try:
                    r_det = await client.get(f"https://api.osv.dev/v1/vulns/{v_id}", timeout=4.0)
                    if r_det.status_code == 200:
                        v_data = r_det.json()
                        aliases = v_data.get("aliases", []) or []
                        cve_alias = next((a for a in aliases if a.startswith("CVE-")), v_id)
                        summary = f"[{pkg}] {v_data.get('summary', '')} {(v_data.get('details') or '')[:400]}"
                        refs = [ref.get("url") for ref in (v_data.get("references") or []) if ref.get("url")]

                        is_mal = v_id.startswith("MAL-")
                        findings.append({
                            "vuln_id": cve_alias,
                            "source": f"Google OSV.dev ({v_id})",
                            "matched_technologies": _matches_client_stack(f"{pkg} {summary}") or [pkg.upper()],
                            "summary": summary,
                            "cvss_score": 9.8 if is_mal else None,
                            "epss_score": 0.0,
                            "in_kev_or_exploited": is_mal,
                            "has_poc": is_mal,
                            "is_malicious_pkg": is_mal,
                            "patch_urls": refs[:5] or [f"https://osv.dev/vulnerability/{v_id}"],
                            "published_at": v_data.get("published") or datetime.now(timezone.utc).isoformat()
                        })
                except Exception:
                    pass

            await asyncio.gather(*(fetch_osv_detail(vid, p) for vid, p in top_vuln_ids[:8] if vid))
    except Exception:
        pass
    return findings


async def _fetch_hackernews_social_signals(client: httpx.AsyncClient) -> Dict[str, float]:
    """
    Detecta ruido social temprano en Hacker News Algolia API sobre CVEs o 0-days
    para alimentar la variable S_social del motor ZHR.
    """
    social_scores: Dict[str, float] = {}
    try:
        resp = await client.get(
            "https://hn.algolia.com/api/v1/search_by_date",
            params={"query": "CVE OR 0day OR RCE OR vulnerability", "tags": "story", "hitsPerPage": 20},
            timeout=4.0
        )
        if resp.status_code == 200:
            for hit in resp.json().get("hits", []):
                title = hit.get("title", "") or ""
                points = int(hit.get("points", 0) or 0)
                comments = int(hit.get("num_comments", 0) or 0)
                velocity = min(1.0, (points + (comments * 2)) / 150.0)
                for cve_m in re.findall(r"CVE-\d{4}-\d{4,7}", title, re.I):
                    social_scores[cve_m.upper()] = max(social_scores.get(cve_m.upper(), 0.0), velocity)
    except Exception:
        pass
    return social_scores


async def _fetch_cisa_kev_recent_stack(client: httpx.AsyncClient) -> List[Dict[str, Any]]:
    """
    Extrae las últimas vulnerabilidades agregadas a CISA KEV que impacten las 8 tecnologías del cliente.
    """
    findings = []
    try:
        resp = await client.get(
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            timeout=7.0
        )
        if resp.status_code == 200:
            vulns = resp.json().get("vulnerabilities", []) or []
            # Ordenar por fecha agregada descendente y revisar las 45 más recientes
            vulns_sorted = sorted(vulns, key=lambda x: x.get("dateAdded", ""), reverse=True)[:45]
            for v in vulns_sorted:
                blob = f"{v.get('vendorProject', '')} {v.get('product', '')} {v.get('vulnerabilityName', '')} {v.get('shortDescription', '')}"
                matched_techs = _matches_client_stack(blob)
                if not matched_techs:
                    continue

                cve_id = v.get("cveID")
                notes_raw = v.get("notes", "") or ""
                urls = [u.strip() for u in re.findall(r"https?://[^\s;]+", notes_raw)]
                urls.append(f"https://nvd.nist.gov/vuln/detail/{cve_id}")

                findings.append({
                    "vuln_id": cve_id,
                    "source": "CISA KEV (Explotación Activa Confirmada)",
                    "matched_technologies": matched_techs,
                    "summary": f"{v.get('vulnerabilityName')}: {v.get('shortDescription')} Acción requerida: {v.get('requiredAction')}",
                    "cvss_score": 9.5,
                    "epss_score": 0.85,
                    "in_kev_or_exploited": True,
                    "has_poc": True,
                    "patch_urls": urls[:5],
                    "published_at": v.get("dateAdded")
                })
    except Exception:
        pass
    return findings


# =====================================================================
# 5. ORQUESTADOR PRINCIPAL DE BARRIDO ZERO-HOUR CTI
# =====================================================================

async def run_zero_hour_cti_sweep(
    client_domain_or_ip: Optional[str] = None,
    custom_keywords: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Ejecuta en paralelo todos los sensores de Hora Cero, cruza con la exposición perimetral
    del cliente (EASM) y aplica el motor matemático ZHR para retornar alertas P0/P1.
    """
    # HTTP/2 activado para cumplir requerimiento de OSV.dev (evita tope de 32 MiB)
    async with httpx.AsyncClient(
        http2=True,
        verify=False,
        timeout=httpx.Timeout(10.0, connect=4.0),
        headers={"User-Agent": "SentinelRecon-ZeroHour-CTI/2.4"}
    ) as client:
        (
            perimeter_profile,
            euvd_list,
            usn_list,
            ghsa_list,
            osv_list,
            kev_list,
            hn_social_map
        ) = await asyncio.gather(
            fingerprint_client_perimeter_stack(client_domain_or_ip),
            _fetch_euvd_zero_hour(client),
            _fetch_ubuntu_usn_safe(client),
            _fetch_github_upstream_advisories(client),
            _fetch_osv_batch_signals(client),
            _fetch_cisa_kev_recent_stack(client),
            _fetch_hackernews_social_signals(client)
        )

    raw_candidates = kev_list + euvd_list + ghsa_list + osv_list + usn_list
    exposed_techs_upper = {t.upper() for t in perimeter_profile.get("exposed_technologies", [])}

    dedup_map: Dict[str, Dict[str, Any]] = {}
    for item in raw_candidates:
        vid = (item.get("vuln_id") or "").strip().upper()
        if not vid:
            continue

        if vid not in dedup_map:
            dedup_map[vid] = item
        else:
            existing = dedup_map[vid]
            existing["in_kev_or_exploited"] = existing["in_kev_or_exploited"] or item.get("in_kev_or_exploited", False)
            existing["has_poc"] = existing["has_poc"] or item.get("has_poc", False)
            existing["matched_technologies"] = sorted(list(set(existing["matched_technologies"] + item.get("matched_technologies", []))))
            existing["patch_urls"] = list(dict.fromkeys(existing["patch_urls"] + item.get("patch_urls", [])))[:6]

    prioritized_alerts: List[Dict[str, Any]] = []
    for vid, cand in dedup_map.items():
        techs_matched = set(cand.get("matched_technologies", []))
        is_perimeter_exposed = bool(techs_matched.intersection(exposed_techs_upper))

        exposure_level = (
            ExposureLevel.INTERNET_EXPOSED if is_perimeter_exposed
            else ExposureLevel.PRODUCTION_INTERNAL
        )

        zhr_score, alert_tier = ZeroHourPrioritizer.calculate_zhr(
            vuln_id=vid,
            summary=cand.get("summary", ""),
            cvss_score=cand.get("cvss_score"),
            epss_current=float(cand.get("epss_score") or 0.0),
            has_nuclei_or_poc=bool(cand.get("has_poc")),
            is_malicious_pkg=bool(cand.get("is_malicious_pkg")),
            social_velocity=hn_social_map.get(vid, 0.0),
            in_kev_or_exploited=bool(cand.get("in_kev_or_exploited")),
            exposure=exposure_level
        )

        # Huella única de estado (si un CVE sube a KEV después, cambia su state_hash y dispara nueva alerta)
        state_payload = f"{vid}|KEV:{cand.get('in_kev_or_exploited')}|TIER:{alert_tier}"
        state_hash = hashlib.sha256(state_payload.encode("utf-8")).hexdigest()[:16]

        cand_enriched = {
            **cand,
            "zhr_score": zhr_score,
            "alert_tier": alert_tier,
            "perimeter_verified_exposed": is_perimeter_exposed,
            "state_hash": state_hash
        }
        prioritized_alerts.append(cand_enriched)

    # Ordenar por puntaje ZHR de mayor a menor
    prioritized_alerts.sort(key=lambda x: x["zhr_score"], reverse=True)

    p0_p1_actionable = [
        a for a in prioritized_alerts
        if a["alert_tier"] in ("P0_CRITICAL_IMMEDIATE", "P1_HIGH_URGENT")
    ]

    return {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "client_perimeter_profile": perimeter_profile,
        "total_evaluated": len(prioritized_alerts),
        "actionable_p0_p1_count": len(p0_p1_actionable),
        "actionable_alerts": p0_p1_actionable[:10],
        "all_ranked_signals": prioritized_alerts[:25]
    }