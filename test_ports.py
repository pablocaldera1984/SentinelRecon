import asyncio
import json
from modules.port_scanner import scan_critical_ports

async def main():
    target = "google.com"
    print(f"[*] Escaneando puertos críticos en: {target}...")
    resultado = await scan_critical_ports(target)
    print(json.dumps(resultado, indent=2))

if __name__ == "__main__":
    asyncio.run(main())
