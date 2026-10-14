# test_typosquatting.py
import asyncio
import json
from modules.brand_typosquatting_scanner import scan_brand_typosquatting

async def main():
    for target in ["global365.cl", "bancoestado.cl"]:
        print(f"\n[*] Escaneando permutaciones de Typosquatting y Fraude BEC para: {target}...")
        res = await scan_brand_typosquatting(target)
        print(json.dumps(res, indent=2, ensure_ascii=False))

if __name__ == "__main__":
    asyncio.run(main())