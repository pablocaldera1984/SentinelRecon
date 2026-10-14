# test_identity.py
import asyncio
import sys
import json
from modules.identity_scanner import scan_identity_exposure

async def main():
    # Si escribes el dominio en el comando lo usa; si no, te lo pregunta en pantalla
    if len(sys.argv) > 1:
        target = sys.argv[1].strip()
    else:
        target = input("Ingresa el dominio de la empresa a auditar (ej. falabella.com): ").strip()

    print(f"\n[*] Consultando Radar de Infostealers (Hudson Rock OSINT) para: {target}...")
    resultado = await scan_identity_exposure(target)
    print(json.dumps(resultado, indent=2, ensure_ascii=False))

if __name__ == "__main__":
    asyncio.run(main())