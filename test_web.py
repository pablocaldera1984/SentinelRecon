import asyncio
import json
from modules.web_scanner import scan_web_crypto

async def main():
    target = "google.com"
    print(f"[*] Analizando SSL/TLS y encabezados web para: {target}...")
    resultado = await scan_web_crypto(target)
    print(json.dumps(resultado, indent=2))

if __name__ == "__main__":
    asyncio.run(main())
