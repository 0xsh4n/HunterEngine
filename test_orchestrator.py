import asyncio
import logging
from core.scope_loader import ScopeLoader
from recon.subdomain_enum import SubdomainEnumerator
from recon.dns_resolver import DNSResolver
from recon.live_prober import LiveProber

logging.basicConfig(level=logging.INFO)

async def main():
    print("--- Scope ---")
    scope = ScopeLoader("config/scope.yaml")
    scope.load()
    print("Roots:", scope.get_root_domains())
    
    print("\n--- Subdomain Enum ---")
    sub_enum = SubdomainEnumerator()
    subs = await sub_enum.enumerate("infomaniak.com")
    print(f"Total subs: {len(subs)}")
    if subs:
        print("Sample:", subs[:5])
        
    print("\n--- Filter Scope ---")
    in_scope_subs = scope.filter_in_scope(subs)
    print(f"In scope: {len(in_scope_subs)}")
    if in_scope_subs:
        print("Sample:", in_scope_subs[:5])
        
    print("\n--- DNS Resolve ---")
    dns_res = DNSResolver()
    resolved = await dns_res.resolve_bulk(in_scope_subs[:50] if in_scope_subs else ['api.infomaniak.com'])
    resolved_hosts = [r["hostname"] for r in resolved if r.get("resolved")]
    print(f"Resolved: {len(resolved_hosts)}")
    if resolved_hosts:
        print("Sample:", resolved_hosts[:5])
        
    print("\n--- Live Probe ---")
    prober = LiveProber()
    live_hosts = await prober.probe_hosts(resolved_hosts)
    print(f"Live hosts: {len(live_hosts)}")
    if live_hosts:
        print("Sample:", live_hosts[:5])

if __name__ == "__main__":
    asyncio.run(main())
