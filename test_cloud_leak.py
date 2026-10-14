# test_cloud_leak.py
import asyncio
import sys
import json
from modules.cloud_leak_scanner import scan_cloud_storage_leaks

async def main():
    target = sys.argv[1].strip() if len(sys.argv) > 1 else "global365.cl"
    print(f"\n[*] Escaneando exposición de Buckets Multinube (AWS S3, GCP, Azure) para: {target}...")
    res = await scan_cloud_storage_leaks(target)
    print(json.dumps(res, indent=2, ensure_ascii=False))

if __name__ == "__main__":
    asyncio.run(main())