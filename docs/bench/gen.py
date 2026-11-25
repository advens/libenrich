#!/usr/bin/env python3
"""Generate the benchmark indicator set and query streams.

Deterministic for a given seed. Writes into OUT:
  feed.csv         libenrich CSV feed: every indicator
  ip_nets.txt      IPv4 indicators, one CIDR per line (/32 for an address)
  strings.txt      string indicators (domains, URLs, SHA-256), one per line
  q_ip_<p>.txt     IPv4 queries, hit ratio p
  q_str_<p>.txt    string queries, hit ratio p
  expect.txt       expected hit count per query file

Every address is public (no RFC 1918, loopback, link-local, multicast,
documentation or reserved range), so a reader that skips private
addresses does not change the counts.

Copyright 2026 Advens.
Licensed under the Apache License, Version 2.0. See LICENSE.
"""
import ipaddress
import random
import sys

def main() -> None:
    out = sys.argv[1]
    n_ip = int(sys.argv[2]) if len(sys.argv) > 2 else 1_000_000
    n_net = int(sys.argv[3]) if len(sys.argv) > 3 else 50_000
    n_str = int(sys.argv[4]) if len(sys.argv) > 4 else 2_000_000
    n_q = int(sys.argv[5]) if len(sys.argv) > 5 else 1_000_000
    rng = random.Random(20261124)

    def public_ip() -> int:
        while True:
            v = rng.getrandbits(32)
            a = ipaddress.IPv4Address(v)
            if a.is_global and not a.is_multicast:
                return v

    nets: list[ipaddress.IPv4Network] = []
    seen_net: set[ipaddress.IPv4Network] = set()
    while len(nets) < n_net:
        plen = rng.choice([16, 20, 22, 24, 24, 24, 26, 28])
        n = ipaddress.IPv4Network((public_ip(), plen), strict=False)
        if n.is_global and n not in seen_net:
            seen_net.add(n)
            nets.append(n)
    ips: set[int] = set()
    while len(ips) < n_ip:
        ips.add(public_ip())
    ip_list = sorted(ips)

    tlds = ["com", "net", "org", "io", "ru", "cn", "xyz", "top", "info", "biz"]
    letters = "abcdefghijklmnopqrstuvwxyz0123456789"

    def domain() -> str:
        n = rng.randint(6, 16)
        return "".join(rng.choice(letters) for _ in range(n)) + "." + rng.choice(tlds)

    strs: set[str] = set()
    n_dom, n_url = n_str // 2, n_str // 4
    while len(strs) < n_dom:
        strs.add(domain())
    while len(strs) < n_dom + n_url:
        strs.add("https://" + domain() + "/" + "".join(rng.choice(letters) for _ in range(rng.randint(4, 30))))
    while len(strs) < n_str:
        strs.add("%064x" % rng.getrandbits(256))
    str_list = sorted(strs)

    with open(f"{out}/feed.csv", "w") as f:
        for v in ip_list:
            f.write(f"ip,{ipaddress.IPv4Address(v)},80,c2,bench,green\n")
        for n in nets:
            f.write(f"ip,{n},60,scanner,bench,green\n")
        for s in str_list:
            f.write(f"domain,{s},70,malware,bench,amber\n")
    with open(f"{out}/ip_nets.txt", "w") as f:
        for v in ip_list:
            f.write(f"{ipaddress.IPv4Address(v)}/32\n")
        for n in nets:
            f.write(f"{n}\n")
    with open(f"{out}/strings.txt", "w") as f:
        for s in str_list:
            f.write(s + "\n")

    # Membership for misses: an address is a hit if it is listed or inside
    # a listed network.
    net_ranges = sorted((int(n.network_address), int(n.broadcast_address)) for n in nets)
    import bisect
    starts = [a for a, _ in net_ranges]

    def ip_hit(v: int) -> bool:
        if v in ips:
            return True
        i = bisect.bisect_right(starts, v)
        # Networks may nest; scan back while a range can still cover v.
        j = i - 1
        while j >= 0 and j >= i - 64:
            a, b = net_ranges[j]
            if a <= v <= b:
                return True
            j -= 1
        return False

    expect = []
    for p in ("0.001", "1"):
        ratio = float(p)
        hits = 0
        with open(f"{out}/q_ip_{p}.txt", "w") as f:
            for _ in range(n_q):
                if rng.random() < ratio:
                    if rng.random() < 0.8:
                        v = rng.choice(ip_list)
                    else:
                        n = rng.choice(nets)
                        v = int(n.network_address) + rng.randrange(n.num_addresses)
                else:
                    v = public_ip()
                    while ip_hit(v):
                        v = public_ip()
                hits += ip_hit(v)
                f.write(f"{ipaddress.IPv4Address(v)}\n")
        expect.append(f"q_ip_{p}.txt {hits}")
        hits = 0
        with open(f"{out}/q_str_{p}.txt", "w") as f:
            for _ in range(n_q):
                if rng.random() < ratio:
                    s = rng.choice(str_list)
                else:
                    k = rng.random()
                    if k < 0.5:
                        s = domain()
                    elif k < 0.75:
                        s = "https://" + domain() + "/x" + "".join(rng.choice(letters) for _ in range(8))
                    else:
                        s = "%064x" % rng.getrandbits(256)
                    if s in strs:
                        s = s + "z"
                hits += s in strs
                f.write(s + "\n")
        expect.append(f"q_str_{p}.txt {hits}")
    with open(f"{out}/expect.txt", "w") as f:
        f.write("\n".join(expect) + "\n")

if __name__ == "__main__":
    main()
