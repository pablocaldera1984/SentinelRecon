import asyncio
import socket
import httpx
from typing import Dict, Any, List
from config import TARGET_PORTS, TCP_TIMEOUT

async def probe_port(ip_or_host: str, port: int) -> Dict[str, Any]:
    """Realiza un sondeo TCP rápido y no invasivo sobre un puerto específico."""
    result = {
        "port": port,
        "is_open": False,
        "service": None,
        "banner": None,
        "details": None
    }
    
    # Mapeo de nombres convencionales
    service_names = {
        22: "SSH",
        80: "HTTP",
        135: "RPC Endpoint Mapper",
        443: "HTTPS",
        445: "SMB",
        3389: "RDP",
        8080: "HTTP-Proxy/Alt",
        11434: "Ollama (Shadow AI)"
    }
    result["service"] = service_names.get(port, "Unknown")

    try:
        # Intento de conexión TCP con timeout estricto
        conn = asyncio.open_connection(ip_or_host, port)
        reader, writer = await asyncio.wait_for(conn, timeout=TCP_TIMEOUT)
        result["is_open"] = True

        # Inspección no invasiva según el puerto
        if port == 22:
            try:
                # Banner pasivo de SSH (RFC 4253)
                banner_bytes = await asyncio.wait_for(reader.read(256), timeout=1.0)
                result["banner"] = banner_bytes.decode('utf-8', errors='ignore').strip()
            except Exception:
                pass

        elif port == 11434:
            # Comprobación de API expuesta de Ollama sin autenticación
            try:
                async with httpx.AsyncClient(timeout=1.5) as client:
                    resp = await client.get(f"http://{ip_or_host}:11434/api/version")
                    if resp.status_code == 200:
                        result["details"] = resp.json()
            except Exception:
                pass

        # Cierre ordenado inmediato de la conexión
        writer.close()
        await writer.wait_closed()

    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        result["is_open"] = False
    except Exception as e:
        result["error"] = str(e)

    return result

async def scan_critical_ports(target_host: str) -> Dict[str, Any]:
    """Escanea la lista selecta de 8 puertos en paralelo respetando los límites de tiempo."""
    tasks = [probe_port(target_host, port) for port in TARGET_PORTS]
    results = await asyncio.gather(*tasks)

    open_ports = [r for r in results if r.get("is_open")]

    return {
        "target": target_host,
        "total_ports_probed": len(TARGET_PORTS),
        "open_ports_count": len(open_ports),
        "open_ports": open_ports
    }
