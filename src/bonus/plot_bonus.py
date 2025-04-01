import pyshark
import matplotlib.pyplot as plt
from collections import Counter

# File to analyze
pcap_file = 'filtered_spotify_and_emails.pcap'


def load_pcap(filename):
    # Load a packet capture file
    return pyshark.FileCapture(filename, use_json=True)


def extract_packet_sizes(cap):
    sizes = []
    for pkt in cap:
        if 'IP' in pkt:  # Make sure packet has IP layer
            sizes.append(int(pkt.length))
    return sizes


def calc_time_deltas(cap):
    # Get timestamps and calculate time differences
    timestamps = []
    for pkt in cap:
        if 'IP' in pkt:
            timestamps.append(float(pkt.sniff_time.timestamp()))

    # Calculate deltas between packets
    deltas = []
    for i in range(1, len(timestamps)):
        deltas.append(timestamps[i] - timestamps[i - 1])
    return deltas


def track_flow_bytes(cap):
    # Track bytes per flow
    flow_bytes = Counter()
    for pkt in cap:
        if 'IP' in pkt and 'TCP' in pkt:
            # Flow ID is a tuple : src IP/port + dst IP/port
            flow = (pkt.ip.src, pkt.ip.dst,
                    int(pkt.tcp.srcport), int(pkt.tcp.dstport))
            flow_bytes[flow] += int(pkt.length)
    return flow_bytes


def track_flow_packets(cap):
    # Track packets per flow
    flow_packets = Counter()
    for pkt in cap:
        if 'IP' in pkt and 'TCP' in pkt:
            # Flow ID: (source IP, dest IP, source port, dest port)
            flow = (pkt.ip.src, pkt.ip.dst,
                    int(pkt.tcp.srcport), int(pkt.tcp.dstport))
            flow_packets[flow] += 1
    return flow_packets


def count_dst_ips(cap):
    # Count destination IPs
    ips = Counter()
    for pkt in cap:
        if 'IP' in pkt:
            ips[pkt.ip.dst] += 1
    return ips


def show_packet_sizes(sizes):
    # Plot packet size distribution
    plt.hist(sizes, bins=30, color='skyblue', edgecolor='black')
    plt.title('Packet Size Distribution')
    plt.xlabel('Packet Size (Bytes)')
    plt.ylabel('Frequency')
    plt.show()


def show_time_deltas(deltas):
    # Plot inter-arrival times
    plt.hist(deltas, bins=30, color='lightgreen', edgecolor='black')
    plt.title('Packet Inter-Arrival Times')
    plt.xlabel('Time Between Packets (Seconds)')
    plt.ylabel('Frequency')
    plt.show()


def show_flow_bytes(flow_bytes):
    # Plot flow volume
    labels = [f"Flow {i}" for i in range(len(flow_bytes))]
    values = list(flow_bytes.values())
    plt.bar(labels, values, color='lightskyblue')
    plt.title('Flow Volume (Bytes per Flow)')
    plt.xlabel('Flow ID')
    plt.ylabel('Bytes Transmitted')
    plt.xticks(rotation=90)
    plt.show()


def show_flow_packets(flow_packets):
    # Plot flow size
    labels = [f"Flow {i}" for i in range(len(flow_packets))]
    values = list(flow_packets.values())
    plt.bar(labels, values, color='lightcoral')
    plt.title('Flow Size (Number of Packets per Flow)')
    plt.xlabel('Flow ID')
    plt.ylabel('Number of Packets')
    plt.xticks(rotation=90)
    plt.show()


def show_top_dst_ips(ips, limit=15):
    # Plot top destination IPs
    top = ips.most_common(limit)
    labels = [ip for ip, _ in top]
    values = [count for _, count in top]
    plt.bar(labels, values, color='mediumseagreen', edgecolor='black')
    plt.title(f'Top {limit} Destination IPs')
    plt.xlabel('Destination IP')
    plt.ylabel('Number of Packets')
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.show()


def main():
    print(f"Loading capture file: {pcap_file}")

    # Load the capture
    cap = load_pcap(pcap_file)

    # Analyze and display packet sizes
    print("Graph #1: Analyzing packet sizes...")
    sizes = extract_packet_sizes(cap)
    show_packet_sizes(sizes)

    # Analyze and display packet timing
    print("Graph #2: Analyzing packet timing...")
    deltas = calc_time_deltas(cap)
    show_time_deltas(deltas)

    # Analyze and display flow statistics
    print("Graph #3: Analyzing flow volumes...")
    flow_bytes = track_flow_bytes(cap)
    show_flow_bytes(flow_bytes)

    print("Graph #4: Analyzing flow sizes...")
    flow_packets = track_flow_packets(cap)
    show_flow_packets(flow_packets)

    # Analyze and display destination IPs
    print("Graph #5: Analyzing destination IPs...")
    dst_ips = count_dst_ips(cap)
    show_top_dst_ips(dst_ips)

    print("Analysis complete!")


if __name__ == '__main__':
    main()