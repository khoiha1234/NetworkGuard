from scapy.all import *
import argparse
from collections import Counter

ip_counter = Counter()
port_counter = Counter()

def analyze_packet(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        ip_counter[src_ip] += 1
        if packet.haslayer(TCP):
            port_counter[packet[TCP].dport] += 1
        elif packet.haslayer(UDP):
            port_counter[packet[UDP].dport] += 1

def print_stats():
    print("\n=== Traffic Statistics ===")
    print("Top 5 Source IPs:")
    for ip, count in ip_counter.most_common(5):
        print(f"IP: {ip}, Packets: {count}")
    print("\nTop 5 Destination Ports:")
    for port, count in port_counter.most_common(5):
        print(f"Port: {port}, Packets: {count}")

def main():
    parser = argparse.ArgumentParser(description="NetworkGuard: Basic Network Traffic Analyzer")
    parser.add_argument("--file", help="PCAP file to analyze")
    parser.add_argument("--interface", help="Network interface to monitor")
    args = parser.parse_args()

    try:
        if args.file:
            print(f"Analyzing PCAP: {args.file}")
            packets = rdpcap(args.file)
            for pkt in packets:
                analyze_packet(pkt)
        elif args.interface:
            print(f"Monitoring interface: {args.interface}")
            sniff(iface=args.interface, prn=analyze_packet, count=100)
        else:
            print("Please provide a PCAP file with --file or interface with --interface")
        print_stats()
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
