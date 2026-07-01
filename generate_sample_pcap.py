from scapy.all import DNS, DNSQR, Ether, IP, TCP, UDP, wrpcap


def create_sample_packets():
    packets = []

    # Normal DNS request
    packets.append(
        Ether()
        / IP(src="192.168.1.10", dst="8.8.8.8")
        / UDP(sport=53000, dport=53)
        / DNS(rd=1, qd=DNSQR(qname="example.com"))
    )

    # Normal web traffic
    packets.append(
        Ether()
        / IP(src="192.168.1.10", dst="93.184.216.34")
        / TCP(sport=51000, dport=80, flags="S")
    )

    packets.append(
        Ether()
        / IP(src="192.168.1.10", dst="93.184.216.34")
        / TCP(sport=51001, dport=443, flags="S")
    )

    # Traffic to unusual ports
    packets.append(
        Ether()
        / IP(src="192.168.1.25", dst="10.0.0.20")
        / TCP(sport=52000, dport=4444, flags="S")
    )

    packets.append(
        Ether()
        / IP(src="192.168.1.25", dst="10.0.0.20")
        / TCP(sport=52001, dport=1337, flags="S")
    )

    # Simulated port scan
    for destination_port in range(20, 45):
        packets.append(
            Ether()
            / IP(src="192.168.1.50", dst="10.0.0.30")
            / TCP(
                sport=55000 + destination_port,
                dport=destination_port,
                flags="S",
            )
        )

    return packets


def main():
    output_file = "sample_traffic.pcap"
    packets = create_sample_packets()
    wrpcap(output_file, packets)

    print(f"Created {output_file}")
    print(f"Packets written: {len(packets)}")


if __name__ == "__main__":
    main()
