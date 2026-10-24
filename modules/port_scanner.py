# modules/port_scanner.py
import asyncio
import socket
import httpx
from typing import Dict, Any, List
from config import TARGET_PORTS, TCP_TIMEOUT

# Lista expandida de puertos críticos y motores de IA / Bases de datos
EXTENDED_CRITICAL_PORTS = sorted(list(set(list(TARGET_PORTS) + [
    21,     # FTP
    22,     # SSH
    80,     # HTTP
    135,    # Windows RPC
    443,    # HTTPS
    445,    # SMB
    3306,   # MySQL / MariaDB
    3389,   # RDP
    5432,   # PostgreSQL
    6333,   # Qdrant Vector DB (Shadow AI)
    6379,   # Redis
    8000,   # vLLM / OpenAI-Compatible AI Server
    8080,   # HTTP Proxy / Admin
    8443,   # HTTPS Admin Alt
    11434,  # Ollama LLM Server (Shadow AI)
    27017   # MongoDB
])))


async def probe_port(ip_or_host: str, port: int) -> Dict[str, Any]:
    """Realiza un sondeo TCP rápido y no invasivo sobre un puerto específico."""
    result = {
        "port": port,
        "is_open": False,
        "service": None,
        "banner": None,
        "details": None
    }
    
    service_names = {
        21: "FTP",
        22: "SSH",
        80: "HTTP",
        135: "RPC Endpoint Mapper",
        443: "HTTPS",
        445: "SMB",
        3306: "MySQL Database",
        3389: "RDP (Remote Desktop)",
        5432: "PostgreSQL Database",
        6333: "Qdrant Vector DB (Shadow AI)",
        6379: "Redis In-Memory DB",
        8000: "vLLM / AI Inference API",
        8080: "HTTP-Proxy/Alt",
        8443: "HTTPS-Admin/Alt",
        11434: "Ollama (Shadow AI)",
        27017: "MongoDB NoSQL"
    }
    result["service"] = service_names.get(port, "Unknown")

    try:
        conn = asyncio.open_connection(ip_or_host, port)
        reader, writer = await asyncio.wait_for(conn, timeout=TCP_TIMEOUT)
        result["is_open"] = True

        if port in [21, 22, 3306]:
            try:
                banner_bytes = await asyncio.wait_for(reader.read(256), timeout=1.0)
                result["banner"] = banner_bytes.decode('utf-8', errors='ignore').strip()
            except Exception:
                pass

        elif port == 11434:
            try:
                async with httpx.AsyncClient(timeout=1.5) as client:
                    resp = await client.get(f"http://{ip_or_host}:11434/api/version")
                    if resp.status_code == 200:
                        result["details"] = {"shadow_ai_confirmed": True, "engine": "Ollama", **resp.json()}
            except Exception:
                pass

        elif port == 8000:
            try:
                async with httpx.AsyncClient(timeout=1.5) as client:
                    resp = await client.get(f"http://{ip_or_host}:8000/v1/models")
                    if resp.status_code == 200 and "data" in resp.text:
                        result["details"] = {"shadow_ai_confirmed": True, "engine": "vLLM / OpenAI-Compatible API"}
            except Exception:
                pass

        writer.close()
        await writer.wait_closed()

    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        result["is_open"] = False
    except Exception as e:
        result["error"] = str(e)

    return result


async def query_shodan_internetdb(target_host: str) -> Dict[str, Any]:
    """
    Enriquecimiento pasivo sin costo ni API Key vía Shodan InternetDB.
    Retorna CPEs, CVEs pasivos, hostnames y puertos adicionales observados en Internet.
    """
    intel = {
        "resolved_ip": None,
        "shodan_ports": [],
        "cpes": [],
        "vulns": [],
        "tags": [],
        "hostnames": []
    }
    try:
        ip = socket.gethostbyname(target_host)
        intel["resolved_ip"] = ip
        async with httpx.AsyncClient(timeout=2.5) as client:
            resp = await client.get(f"https://internetdb.shodan.io/{ip}")
            if resp.status_code == 200:
                data = resp.json()
                intel["shodan_ports"] = data.get("ports", [])
                intel["cpes"] = data.get("cpes", [])
                intel["vulns"] = data.get("vulns", [])
                intel["tags"] = data.get("tags", [])
                intel["hostnames"] = data.get("hostnames", [])
    except Exception:
        pass
    return intel


async def scan_critical_ports(target_host: str) -> Dict[str, Any]:
    """Escanea los puertos críticos en paralelo y fusiona con inteligencia pasiva Shodan InternetDB."""
    probe_tasks = [probe_port(target_host, port) for port in EXTENDED_CRITICAL_PORTS]
    shodan_task = query_shodan_internetdb(target_host)

    results = await asyncio.gather(*probe_tasks, shodan_task)
    port_results = results[:-1]
    shodan_intel = results[-1]

    open_ports = [r for r in port_results if r.get("is_open")]
    shadow_ai_instances = [p for p in open_ports if p.get("port") in [11434, 6333] or (p.get("details") and p["details"].get("shadow_ai_confirmed"))]

    return {
        "target": target_host,
        "resolved_ip": shodan_intel.get("resolved_ip"),
        "total_ports_probed": len(EXTENDED_CRITICAL_PORTS),
        "open_ports_count": len(open_ports),
        "open_ports": open_ports,
        "shadow_ai_exposed_count": len(shadow_ai_instances),
        "passive_internetdb_intel": shodan_intel
    }