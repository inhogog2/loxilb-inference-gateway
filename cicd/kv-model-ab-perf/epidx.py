#!/usr/bin/env python3
"""epidx.py <rules.json> <vip> <port> <model> <endpoint address>

Print the gateway's endpoint index of one address in one rule, read from the gateway's own listing of its
rules (GET config/loadbalancer/all). The gateway orders a rule's endpoints itself; its per-endpoint counters
carry that index, so the index must come from the gateway and not from the order the rule was posted in.
Exit 1, with the reason on stdout, when the rule or the address is not in the listing.
"""
import json
import sys


def endpoint_index(listing, vip, port, model, address):
    for rule in listing.get("lbAttr") or []:
        sa = rule.get("serviceArguments") or {}
        if sa.get("externalIP") == vip and int(sa.get("port", -1)) == int(port) and sa.get("model_name", "") == model:
            ips = [e.get("endpointIP") for e in rule.get("endpoints") or []]
            if address not in ips:
                raise LookupError(f"{address} is not an endpoint of the rule ({' '.join(map(str, ips))})")
            return ips.index(address)
    raise LookupError(f"no rule {vip}:{port} for model {model} in the listing")


def main():
    path, vip, port, model, address = sys.argv[1:]
    try:
        print(endpoint_index(json.load(open(path)), vip, port, model, address))
    except (LookupError, ValueError, OSError) as exc:
        print(exc)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
