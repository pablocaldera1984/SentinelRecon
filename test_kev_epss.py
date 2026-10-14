# test_kev_epss.py
import asyncio
import json
from modules.port_scanner import scan_critical_ports
from modules.kev_epss_scanner import scan_kev_epss_prioritization

async def main():
    target = "global365.cl"
    print(f"\n[*] 1. Evaluando KEV-EPSS real en {target}...")
    real_ports = await scan_critical_ports(target)
    res_real = await scan_kev_epss_prioritization(target, open_ports_data=real_ports)
    print(json.dumps(res_real, indent=2, ensure_ascii=False))

    print("\n[*] 2. Simulando empresa cliente con PC/Servidor Windows exponiendo RDP (3389) y SSH (22)...")
    simulated_ports = {"open_ports": [{"port": 80}, {"port": 443}, {"port": 3389}, {"port": 22}]}
    res_sim = await scan_kev_epss_prioritization("empresa-vulnerable.cl", open_ports_data=simulated_ports)
    print(json.dumps(res_sim, indent=2, ensure_ascii=False))

if __name__ == "__main__":
    asyncio.run(main())