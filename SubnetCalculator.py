#!/usr/bin/env python3
"""
SubnetCalc — Advanced IPv4/IPv6 Subnet Calculator
Usage: python subnet_calc.py --help
"""

import ipaddress
import argparse
import json
import csv
import sys
import math
from typing import Union


# ─── Helpers ──────────────────────────────────────────────────────────────────

def parse_network(raw: str) -> Union[ipaddress.IPv4Network, ipaddress.IPv6Network]:
    """Parse CIDR, dotted-mask, or wildcard notation."""
    raw = raw.strip()
    try:
        return ipaddress.ip_network(raw, strict=False)
    except ValueError:
        pass

    # Try "addr/dotted-mask" e.g. 192.168.1.0/255.255.255.0
    if "/" in raw:
        addr_part, mask_part = raw.split("/", 1)
        try:
            mask_int = int(ipaddress.IPv4Address(mask_part))
            prefix = bin(mask_int).count("1")
            return ipaddress.ip_network(f"{addr_part}/{prefix}", strict=False)
        except Exception:
            pass

        # Wildcard mask (inverted), e.g. 192.168.1.0/0.0.0.255
        try:
            wild_int = int(ipaddress.IPv4Address(mask_part))
            mask_int = 0xFFFFFFFF ^ wild_int
            prefix = bin(mask_int).count("1")
            return ipaddress.ip_network(f"{addr_part}/{prefix}", strict=False)
        except Exception:
            pass

    raise ValueError(f"Cannot parse network: {raw!r}")


def prefix_to_wildcard(prefix: int) -> str:
    mask = (0xFFFFFFFF >> (32 - prefix)) ^ 0xFFFFFFFF
    wildcard = 0xFFFFFFFF ^ mask
    return str(ipaddress.IPv4Address(wildcard))


def int_to_dotted(n: int) -> str:
    return str(ipaddress.IPv4Address(n))


# ─── Core info ────────────────────────────────────────────────────────────────

def network_info(net: Union[ipaddress.IPv4Network, ipaddress.IPv6Network]) -> dict:
    is4 = isinstance(net, ipaddress.IPv4Network)
    total_hosts = net.num_addresses
    usable = max(total_hosts - 2, 0) if is4 and net.prefixlen < 31 else (
        total_hosts if net.prefixlen >= 31 else total_hosts
    )

    info = {
        "network":        str(net.network_address),
        "prefix_length":  net.prefixlen,
        "cidr":           str(net),
        "total_addresses": total_hosts,
        "usable_hosts":   usable,
        "ip_version":     net.version,
    }

    if is4:
        info["broadcast"]      = str(net.broadcast_address)
        info["subnet_mask"]    = str(net.netmask)
        info["wildcard_mask"]  = str(net.hostmask)
        info["first_host"]     = str(net.network_address + 1) if net.prefixlen < 31 else str(net.network_address)
        info["last_host"]      = str(net.broadcast_address - 1) if net.prefixlen < 31 else str(net.broadcast_address)
        info["network_class"]  = _ipv4_class(net)
        info["is_private"]     = net.is_private
        info["is_loopback"]    = net.is_loopback
        info["is_multicast"]   = net.is_multicast
        info["is_link_local"]  = net.is_link_local
        info["binary_mask"]    = format(int(net.netmask), "032b")
        info["hex_network"]    = f"0x{int(net.network_address):08X}"
    else:
        info["first_host"]     = str(net.network_address + 1)
        info["last_host"]      = str(net.broadcast_address - 1)
        info["is_private"]     = net.is_private
        info["is_loopback"]    = net.is_loopback
        info["is_multicast"]   = net.is_multicast
        info["expanded"]       = net.network_address.exploded
        info["compressed"]     = net.network_address.compressed

    return info


def _ipv4_class(net: ipaddress.IPv4Network) -> str:
    first_octet = int(net.network_address) >> 24
    if first_octet < 128:   return "A"
    if first_octet < 192:   return "B"
    if first_octet < 224:   return "C"
    if first_octet < 240:   return "D (Multicast)"
    return "E (Reserved)"


# ─── Subnetting ───────────────────────────────────────────────────────────────

def subnet_by_count(net: ipaddress.IPv4Network, n: int) -> list[dict]:
    """Divide net into n equal subnets."""
    bits_needed = math.ceil(math.log2(n))
    new_prefix = net.prefixlen + bits_needed
    if new_prefix > 32:
        raise ValueError(f"Cannot create {n} subnets from /{net.prefixlen}")
    subnets = list(net.subnets(new_prefix=new_prefix))[:n]
    return [network_info(s) for s in subnets]


def subnet_by_hosts(net: ipaddress.IPv4Network, hosts_needed: int) -> list[dict]:
    """Divide net into subnets each supporting at least hosts_needed hosts."""
    host_bits = math.ceil(math.log2(hosts_needed + 2))
    new_prefix = 32 - host_bits
    if new_prefix < net.prefixlen:
        raise ValueError(f"/{new_prefix} is larger than the parent /{net.prefixlen}")
    subnets = list(net.subnets(new_prefix=new_prefix))
    return [network_info(s) for s in subnets]


# ─── VLSM ─────────────────────────────────────────────────────────────────────

def vlsm(net: ipaddress.IPv4Network, requirements: list[tuple[str, int]]) -> list[dict]:
    """
    Variable-Length Subnet Masking.
    requirements: list of (name, host_count) sorted descending automatically.
    Returns allocated subnets in order.
    """
    reqs = sorted(requirements, key=lambda x: x[1], reverse=True)
    results = []
    current = int(net.network_address)
    net_end = int(net.broadcast_address)

    for name, hosts in reqs:
        host_bits = math.ceil(math.log2(hosts + 2))
        prefix = 32 - host_bits
        block_size = 2 ** host_bits

        # Align to block boundary
        if current % block_size != 0:
            current = ((current // block_size) + 1) * block_size

        if current + block_size - 1 > net_end:
            raise ValueError(f"Not enough space for '{name}' needing {hosts} hosts")

        subnet = ipaddress.IPv4Network(f"{int_to_dotted(current)}/{prefix}", strict=True)
        info = network_info(subnet)
        info["vlsm_label"] = name
        info["hosts_required"] = hosts
        results.append(info)
        current += block_size

    return results


# ─── Supernet / Summary ───────────────────────────────────────────────────────

def summarize_networks(networks: list[str]) -> list[str]:
    """Return the minimal list of supernets covering all given networks."""
    parsed = [parse_network(n) for n in networks]
    collapsed = list(ipaddress.collapse_addresses(parsed))
    return [str(n) for n in collapsed]


# ─── IP Range ─────────────────────────────────────────────────────────────────

def range_to_cidrs(start_ip: str, end_ip: str) -> list[str]:
    """Convert an IP range to a list of CIDR blocks."""
    start = ipaddress.ip_address(start_ip)
    end   = ipaddress.ip_address(end_ip)
    return [str(n) for n in ipaddress.summarize_address_range(start, end)]


# ─── Output formatters ────────────────────────────────────────────────────────

def _flatten(d: dict, prefix="") -> dict:
    out = {}
    for k, v in d.items():
        out[prefix + k] = v
    return out


def print_info_table(info: dict):
    width = 22
    print()
    print("┌" + "─" * (width + 32) + "┐")
    print(f"│  {'SubnetCalc — Network Details':^{width + 29}}│")
    print("├" + "─" * width + "┬" + "─" * 31 + "┤")
    for k, v in info.items():
        label = k.replace("_", " ").title()
        print(f"│ {label:<{width-1}}│ {str(v):<30}│")
    print("└" + "─" * width + "┴" + "─" * 31 + "┘")
    print()


def print_subnet_table(subnets: list[dict], show_vlsm=False):
    cols = ["cidr", "first_host", "last_host", "broadcast", "usable_hosts"]
    if show_vlsm:
        cols = ["vlsm_label", "hosts_required"] + cols

    headers = [c.replace("_", " ").title() for c in cols]
    widths  = [max(len(h), max((len(str(s.get(c, ""))) for s in subnets), default=0)) for h, c in zip(headers, cols)]

    sep = "┼".join("─" * (w + 2) for w in widths)
    row_fmt = "│".join(f" {{:<{w}}} " for w in widths)

    print()
    print("┌" + "┬".join("─" * (w + 2) for w in widths) + "┐")
    print("│" + row_fmt.format(*headers) + "│")
    print("├" + sep + "┤")
    for s in subnets:
        vals = [str(s.get(c, "")) for c in cols]
        print("│" + row_fmt.format(*vals) + "│")
    print("└" + "┴".join("─" * (w + 2) for w in widths) + "┘")
    print()


def output_json(data):
    print(json.dumps(data, indent=2, default=str))


def output_csv(data: list[dict]):
    if not data:
        return
    writer = csv.DictWriter(sys.stdout, fieldnames=data[0].keys())
    writer.writeheader()
    writer.writerows(data)


# ─── CLI ──────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="subnet_calc",
        description="SubnetCalc — Advanced IPv4/IPv6 Subnet Calculator",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  python subnet_calc.py info 192.168.1.0/24
  python subnet_calc.py info 10.0.0.0/255.0.0.0
  python subnet_calc.py info 10.0.0.0/0.255.255.255   # wildcard
  python subnet_calc.py subnet 192.168.1.0/24 --count 4
  python subnet_calc.py subnet 10.0.0.0/8 --hosts 500
  python subnet_calc.py vlsm 10.0.0.0/16 Eng:50 HR:20 IT:100 Mgmt:10
  python subnet_calc.py summarize 192.168.1.0/25 192.168.1.128/25
  python subnet_calc.py range 10.0.0.1 10.0.0.254
  python subnet_calc.py info 2001:db8::/32        # IPv6
  python subnet_calc.py info 192.168.1.0/24 --output json
  python subnet_calc.py subnet 10.0.0.0/16 --count 8 --output csv
"""
    )

    sub = p.add_subparsers(dest="command", required=True)

    # info
    info_p = sub.add_parser("info", help="Show full details for a network")
    info_p.add_argument("network", help="Network in CIDR, dotted-mask, or wildcard notation")
    info_p.add_argument("--output", choices=["table", "json", "csv"], default="table")

    # subnet
    sub_p = sub.add_parser("subnet", help="Divide a network into subnets")
    sub_p.add_argument("network")
    grp = sub_p.add_mutually_exclusive_group(required=True)
    grp.add_argument("--count",  type=int, help="Number of equal subnets")
    grp.add_argument("--hosts",  type=int, help="Minimum hosts per subnet")
    sub_p.add_argument("--output", choices=["table", "json", "csv"], default="table")

    # vlsm
    vlsm_p = sub.add_parser("vlsm", help="Variable-Length Subnet Masking allocation")
    vlsm_p.add_argument("network", help="Parent network in CIDR")
    vlsm_p.add_argument("requirements", nargs="+",
                         help="Name:hosts pairs, e.g. Eng:50 HR:20")
    vlsm_p.add_argument("--output", choices=["table", "json", "csv"], default="table")

    # summarize
    sum_p = sub.add_parser("summarize", help="Collapse/summarize a list of networks into supernets")
    sum_p.add_argument("networks", nargs="+", help="Networks in CIDR notation")
    sum_p.add_argument("--output", choices=["table", "json"], default="table")

    # range
    rng_p = sub.add_parser("range", help="Convert IP range to CIDR blocks")
    rng_p.add_argument("start", help="Start IP address")
    rng_p.add_argument("end",   help="End IP address")
    rng_p.add_argument("--output", choices=["table", "json"], default="table")

    return p


def main():
    parser = build_parser()
    args = parser.parse_args()

    # ── info ──────────────────────────────────────────────────────────────────
    if args.command == "info":
        net  = parse_network(args.network)
        info = network_info(net)
        if args.output == "json":
            output_json(info)
        elif args.output == "csv":
            output_csv([info])
        else:
            print_info_table(info)

    # ── subnet ────────────────────────────────────────────────────────────────
    elif args.command == "subnet":
        net = parse_network(args.network)
        if not isinstance(net, ipaddress.IPv4Network):
            sys.exit("Subnetting command currently supports IPv4 only.")
        if args.count:
            subnets = subnet_by_count(net, args.count)
        else:
            subnets = subnet_by_hosts(net, args.hosts)

        if args.output == "json":
            output_json(subnets)
        elif args.output == "csv":
            output_csv(subnets)
        else:
            print(f"\n  Subnets of {net}  ({len(subnets)} total)\n")
            print_subnet_table(subnets)

    # ── vlsm ──────────────────────────────────────────────────────────────────
    elif args.command == "vlsm":
        net = parse_network(args.network)
        reqs = []
        for r in args.requirements:
            if ":" not in r:
                sys.exit(f"Bad format for requirement {r!r} — use Name:hosts")
            name, hosts = r.split(":", 1)
            reqs.append((name, int(hosts)))

        result = vlsm(net, reqs)

        if args.output == "json":
            output_json(result)
        elif args.output == "csv":
            output_csv(result)
        else:
            print(f"\n  VLSM allocation inside {net}\n")
            print_subnet_table(result, show_vlsm=True)

    # ── summarize ─────────────────────────────────────────────────────────────
    elif args.command == "summarize":
        summaries = summarize_networks(args.networks)
        if args.output == "json":
            output_json(summaries)
        else:
            print("\n  Summarized networks:\n")
            for s in summaries:
                print(f"    {s}")
            print()

    # ── range ─────────────────────────────────────────────────────────────────
    elif args.command == "range":
        cidrs = range_to_cidrs(args.start, args.end)
        if args.output == "json":
            output_json(cidrs)
        else:
            print(f"\n  CIDRs covering {args.start} → {args.end}:\n")
            for c in cidrs:
                print(f"    {c}")
            print()


if __name__ == "__main__":
    main()