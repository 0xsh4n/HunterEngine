import asyncio
import logging
from recon.dns_resolver import DNSResolver
from recon.live_prober import LiveProber

logging.basicConfig(level=logging.INFO)

async def main():
    print("Testing DNSResolver...")
    r = DNSResolver()
    print('has_dnsx:', r._has_dnsx)
    res = await r.resolve_bulk(['api.infomaniak.com', 'test.infomaniak.com'])
    print(res)

    print("\nTesting LiveProber...")
    p = LiveProber()
    print('httpx_bin:', p._httpx_bin)
    res = await p.probe_hosts(['api.infomaniak.com'])
    print(res)

if __name__ == '__main__':
    asyncio.run(main())
