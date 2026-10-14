# test_shadow_dns.py
import asyncio
import sys
import json
from modules.shadow_dns_scanner import scan_shadow_dns_and_takeover

async def main():
    targets = [sys.argv[1].strip()] if len(sys.argv) > 1 else ["global365.cl"]
    for target in targets:
        print(f"\n[*] Escaneando Subdominios Sombra (CT Logs), Takeover y RDAP NIC Chile para: {target}...")
        res = await scan_shadow_dns_and_takeover(target)
        print(json.dumps(res, indent=2, ensure_ascii=False))

if __name__ == "__main__":
    asyncio.run(main())