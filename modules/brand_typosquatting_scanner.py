# modules/brand_typosquatting_scanner.py
import asyncio
import base64
import hashlib
import json
import socket
import httpx
import mmh3
import dns.asyncresolver
from typing import Dict, Any, List, Optional

BEC_KEYWORDS = [
    "pagos", "facturacion", "cobranza", "portal", "clientes", 
    "soporte", "seguridad", "acceso", "intranet", "proveedores"
]

VISUAL_SWAPS = {
    "l": "1", "i": "1", "o": "0", "e": "3", "a": "4", "s": "5",
    "1": "l", "0": "o"
}


def generate_domain_permutations(domain: str, max_variants: int = 60) -> List[str]:
    """
    Genera permutaciones de typosquatting y fraude BEC priorizando los vectores más probables.
    """
    clean = domain.strip().lower()
    parts = clean.split(".")
    if len(parts) < 2:
        return []

    name = parts[0]
    tld = ".".join(parts[1:])
    ordered_variants: List[str] = []

    def _add(candidate: str):
        if candidate != clean and candidate not in ordered_variants:
            ordered_variants.append(candidate)

    # Prioridad 1: Cambio de TLD común (.cl <-> .com / .net / .org)
    for alt_tld in ["com", "cl", "net", "org"]:
        if tld != alt_tld:
            _add(f"{name}.{alt_tld}")

    # Prioridad 2: Sustitución visual de caracteres (Homoglyphs: l->1, o->0, etc.)
    for idx, char in enumerate(name):
        if char in VISUAL_SWAPS:
            swapped = name[:idx] + VISUAL_SWAPS[char] + name[idx+1:]
            _add(f"{swapped}.{tld}")

    # Prioridad 3: Omisión de una letra (Typo frecuente al teclear rápido)
    if len(name) > 4:
        for idx in range(len(name)):
            omitted = name[:idx] + name[idx+1:]
            _add(f"{omitted}.{tld}")

    # Prioridad 4: Duplicación de letra
    for idx, char in enumerate(name):
        if char.isalpha():
            doubled = name[:idx] + char + char + name[idx+1:]
            _add(f"{doubled}.{tld}")

    # Prioridad 5: Señuelos de Fraude BEC / Phishing corporativo
    for kw in BEC_KEYWORDS:
        _add(f"{name}-{kw}.{tld}")
        _add(f"{kw}-{name}.{tld}")

    return ordered_variants[:max_variants]


async def _check_single_permutation(
    perm_domain: str,
    resolver: dns.asyncresolver.Resolver,
    sem: asyncio.Semaphore,
    original_favicon_mmh3: Optional[int] = None,
    http_client: Optional[httpx.AsyncClient] = None
) -> Dict[str, Any]:
    """
    Verifica de forma asíncrona si un dominio permutado tiene resolución IP (Web), registros MX (Correo)
    o si clona visualmente el Favicon de la organización (Visual Phishing Match).
    """
    async with sem:
        has_a = False
        has_mx = False
        visual_clone_match = False
        ips: List[str] = []
        mx_hosts: List[str] = []
        loop = asyncio.get_running_loop()

        # 1. Resolución IP nativa del SO
        try:
            addr_info = await asyncio.wait_for(
                loop.getaddrinfo(perm_domain, None, family=socket.AF_INET),
                timeout=2.0
            )
            ips = sorted(list({item[4][0] for item in addr_info if item[4]}))
            has_a = len(ips) > 0
        except Exception:
            pass

        # 2. Consulta Registro MX (Servidor de correo activo -> Riesgo BEC/Phishing)
        try:
            ans_mx = await resolver.resolve(perm_domain, "MX")
            mx_hosts = sorted([str(r.exchange).rstrip(".") for r in ans_mx])
            has_mx = len(mx_hosts) > 0
        except Exception:
            pass

        # 3. Verificación de Clonación Visual por Hash de Favicon (si tiene web activa y conocemos el hash original)
        if has_a and original_favicon_mmh3 is not None and http_client is not None:
            try:
                fav_resp = await http_client.get(f"https://{perm_domain}/favicon.ico", timeout=1.5)
                if fav_resp.status_code == 200 and fav_resp.content:
                    clone_hash = mmh3.hash(base64.encodebytes(fav_resp.content))
                    if clone_hash == original_favicon_mmh3:
                        visual_clone_match = True
            except Exception:
                pass

        if has_a or has_mx:
            if visual_clone_match:
                risk_level = "critical"
                threat_type = "VISUAL_PHISHING_CLONE_CONFIRMED (Favicon Match)"
            elif has_mx:
                risk_level = "critical"
                threat_type = "BEC / Phishing Mail Ready"
            else:
                risk_level = "high"
                threat_type = "Web Clone / Brand Squatting"

            return {
                "squatted_domain": perm_domain,
                "active_web": has_a,
                "active_mail_mx": has_mx,
                "visual_favicon_match": visual_clone_match,
                "resolved_ips": ips[:3],
                "mx_servers": mx_hosts[:3],
                "risk_level": risk_level,
                "threat_type": threat_type
            }
        return {}


async def scan_brand_typosquatting(
    domain: str,
    timeout: float = 2.0,
    original_favicon_mmh3: Optional[int] = None
) -> Dict[str, Any]:
    """
    Módulo de Persistencia: Escudo Anti-Suplantación de Marca, BEC y Clonación Visual.
    """
    clean_domain = domain.strip().lower()
    permutations = generate_domain_permutations(clean_domain)

    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout

    sem = asyncio.Semaphore(15)

    async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=1.5) as http_client:
        tasks = [
            _check_single_permutation(perm, resolver, sem, original_favicon_mmh3, http_client)
            for perm in permutations
        ]
        raw_results = await asyncio.gather(*tasks, return_exceptions=True)

    detected_clones = [
        res for res in raw_results
        if isinstance(res, dict) and res.get("squatted_domain")
    ]

    # Ordenar primero clones visuales confirmados, luego aquellos con servidor de correo activo
    detected_clones.sort(
        key=lambda x: (not x.get("visual_favicon_match", False), not x["active_mail_mx"], x["squatted_domain"])
    )

    high_risk_mx_count = sum(1 for d in detected_clones if d["active_mail_mx"])
    visual_clones_count = sum(1 for d in detected_clones if d.get("visual_favicon_match", False))

    status = "clean"
    if visual_clones_count > 0 or high_risk_mx_count > 0:
        status = "critical"
    elif len(detected_clones) > 0:
        status = "warning"

    drift_payload = [
        {
            "d": d["squatted_domain"],
            "mx": d["active_mail_mx"],
            "a": d["active_web"],
            "vis": d.get("visual_favicon_match", False)
        }
        for d in detected_clones
    ]
    drift_hash = hashlib.sha256(
        json.dumps(drift_payload, sort_keys=True).encode("utf-8")
    ).hexdigest()

    return {
        "module": "brand_typosquatting_shield",
        "domain": clean_domain,
        "status": status,
        "permutations_checked": len(permutations),
        "active_lookalikes_count": len(detected_clones),
        "mail_ready_clones_count": high_risk_mx_count,
        "visual_phishing_clones_count": visual_clones_count,
        "detected_lookalikes": detected_clones,
        "drift_fingerprint": drift_hash
    }