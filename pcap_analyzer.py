from __future__ import annotations

import argparse
import csv
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from scapy.all import DNS, DNSQR, IP, IPv6, TCP, UDP, rdpcap


COMMON_PORTS = {
    20,
    21,
    22,
    23,
    25,
    53,
    67,
    68,
    80,
    110,
    123,
    135,
    137,
    138,
    139,
    143,
    161,
    389,
    443,
    445,
    465,
    514,
    587,
    636,
    993,
    995,
    1433,
    3306,
    3389,
    5432,
    8080,
}


def get_ip_addresses(packet: Any) -> tuple[str | None, str | None]:
    if packet.haslayer(IP):
        return packet[IP].src, packet[IP].dst

    if packet.haslayer(IPv6):
        return packet[IPv6].src, packet[IPv6].dst

    return None, None


def get_transport_details(packet: Any) -> tuple[str, int | None, int | None]:
    if packet.haslayer(TCP):
        return "TCP", int(packet[TCP].sport), int(packet[TCP].dport)

    if packet.haslayer(UDP):
        return "UDP", int(packet[UDP].sport), int(packet[UDP].dport)

    return "Other", None, None


def extract_dns_query(packet: Any) -> str | None:
    if packet.haslayer(DNS) and packet.haslayer(DNSQR):
        query = packet[DNSQR].qname

        if isinstance(query, bytes):
            return query.decode("utf-8", errors="replace").rstrip(".")

        return str(query).rstrip(".")

    return None


def analyze_pcap(pcap_path: Path) -> dict[str, Any]:
    packets = rdpcap(str(pcap_path))

    protocol_counts: Counter[str] = Counter()
    source_ips: Counter[str] = Counter()
    destination_ips: Counter[str] = Counter()
    destination_ports: Counter[int] = Counter()
    dns_queries: Counter[str] = Counter()
    scan_targets: dict[str, set[int]] = defaultdict(set)
    packet_rows: list[dict[str, Any]] = []

    for number, packet in enumerate(packets, start=1):
        source_ip, destination_ip = get_ip_addresses(packet)
        protocol, source_port, destination_port = get_transport_details(packet)
        dns_query = extract_dns_query(packet)

        protocol_counts[protocol] += 1

        if source_ip:
            source_ips[source_ip] += 1

        if destination_ip:
            destination_ips[destination_ip] += 1

        if destination_port is not None:
            destination_ports[destination_port] += 1

        if source_ip and destination_ip and destination_port is not None:
            scan_targets[source_ip].add(destination_port)

        if dns_query:
            dns_queries[dns_query] += 1

        suspicious_port = (
            destination_port is not None
            and destination_port not in COMMON_PORTS
            and destination_port < 49152
        )

        packet_rows.append(
            {
                "PacketNumber": number,
                "SourceIP": source_ip or "",
                "DestinationIP": destination_ip or "",
                "Protocol": protocol,
                "SourcePort": source_port or "",
                "DestinationPort": destination_port or "",
                "DNSQuery": dns_query or "",
                "SuspiciousPort": suspicious_port,
                "PacketLength": len(packet),
            }
        )

    possible_scanners = {
        source_ip: sorted(ports)
        for source_ip, ports in scan_targets.items()
        if len(ports) >= 20
    }

    return {
        "packet_count": len(packets),
        "protocol_counts": protocol_counts,
        "source_ips": source_ips,
        "destination_ips": destination_ips,
        "destination_ports": destination_ports,
        "dns_queries": dns_queries,
        "possible_scanners": possible_scanners,
        "packet_rows": packet_rows,
    }


def write_counter_csv(
    output_path: Path,
    first_column: str,
    counter: Counter[Any],
) -> None:
    with output_path.open("w", newline="", encoding="utf-8") as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow([first_column, "Count"])

        for item, count in counter.most_common():
            writer.writerow([item, count])


def export_results(results: dict[str, Any], output_directory: Path) -> None:
    output_directory.mkdir(parents=True, exist_ok=True)

    packet_output = output_directory / "packet_details.csv"

    with packet_output.open("w", newline="", encoding="utf-8") as csv_file:
        fieldnames = [
            "PacketNumber",
            "SourceIP",
            "DestinationIP",
            "Protocol",
            "SourcePort",
            "DestinationPort",
            "DNSQuery",
            "SuspiciousPort",
            "PacketLength",
        ]

        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results["packet_rows"])

    write_counter_csv(
        output_directory / "source_ips.csv",
        "SourceIP",
        results["source_ips"],
    )

    write_counter_csv(
        output_directory / "destination_ips.csv",
        "DestinationIP",
        results["destination_ips"],
    )

    write_counter_csv(
        output_directory / "destination_ports.csv",
        "DestinationPort",
        results["destination_ports"],
    )

    write_counter_csv(
        output_directory / "dns_queries.csv",
        "DNSQuery",
        results["dns_queries"],
    )

    scanner_output = output_directory / "possible_port_scans.csv"

    with scanner_output.open("w", newline="", encoding="utf-8") as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(["SourceIP", "UniqueDestinationPorts", "Ports"])

        for source_ip, ports in results["possible_scanners"].items():
            writer.writerow([source_ip, len(ports), ", ".join(map(str, ports))])


def print_summary(results: dict[str, Any]) -> None:
    print("\nNetwork Traffic Analysis Summary")
    print("--------------------------------")
    print(f"Total packets: {results['packet_count']}")

    print("\nProtocol counts:")
    for protocol, count in results["protocol_counts"].most_common():
        print(f"  {protocol}: {count}")

    print("\nTop source IP addresses:")
    for address, count in results["source_ips"].most_common(5):
        print(f"  {address}: {count}")

    print("\nTop destination IP addresses:")
    for address, count in results["destination_ips"].most_common(5):
        print(f"  {address}: {count}")

    print("\nTop destination ports:")
    for port, count in results["destination_ports"].most_common(10):
        print(f"  {port}: {count}")

    print("\nTop DNS queries:")
    if results["dns_queries"]:
        for query, count in results["dns_queries"].most_common(10):
            print(f"  {query}: {count}")
    else:
        print("  No DNS queries found.")

    print("\nPossible port scans:")
    if results["possible_scanners"]:
        for source_ip, ports in results["possible_scanners"].items():
            print(f"  {source_ip}: contacted {len(ports)} unique ports")
    else:
        print("  No possible port scans detected.")


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Analyze a PCAP file for network-security indicators."
    )

    parser.add_argument(
        "pcap_file",
        type=Path,
        help="Path to a .pcap or .pcapng file",
    )

    parser.add_argument(
        "--output",
        type=Path,
        default=Path("analysis_results"),
        help="Directory used for exported CSV reports",
    )

    return parser.parse_args()


def main() -> None:
    arguments = parse_arguments()

    if not arguments.pcap_file.exists():
        raise SystemExit(f"PCAP file not found: {arguments.pcap_file}")

    try:
        results = analyze_pcap(arguments.pcap_file)
    except Exception as error:
        raise SystemExit(f"Unable to analyze PCAP file: {error}") from error

    print_summary(results)
    export_results(results, arguments.output)

    print(f"\nReports exported to: {arguments.output.resolve()}")


if __name__ == "__main__":
    main()
