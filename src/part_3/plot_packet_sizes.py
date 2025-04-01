import pandas as pd
import matplotlib.pyplot as plt
import pyshark
import numpy as np
from collections import defaultdict

# Applications
apps = {
    "filtered_chrome.pcap": "Chrome",
    "filtered_firefox.pcap": "Firefox",
    "filtered_spotify.pcap": "Spotify",
    "filtered_youtube.pcap": "YouTube",
    "filtered_zoom.pcap": "Zoom"
}

# Colors and markers
colors = ["blue", "orange", "green", "red", "purple"]
markers = ["o", "s", "d", "*", "x"]

# Function to plot packet sizes in a specific range
def plot_packet_size_range(title, display_filter):
    plt.figure(figsize=(12, 6))

    # Loop through each application and plot its data
    for idx, (pcap_file, app_label) in enumerate(apps.items()):
        try:
            print(f"Loading capture file: {pcap_file}")

            # Read PCAP with pyshark using the display filter
            capture = pyshark.FileCapture(pcap_file, display_filter=display_filter, keep_packets=False)
            
            # Use defaultdict for grouping
            time_groups = defaultdict(list)
            
            # Process each packet while grouping by rounded time
            for packet in capture:
                rounded_time = round(float(packet.frame_info.time_relative))
                time_groups[rounded_time].append(int(packet.length))
            
            # Close the capture
            capture.close()
            
            # Skip if no packets found
            if not time_groups:
                # Add empty plot
                plt.plot([], [], label=app_label, color=colors[idx % len(colors)],
                        marker=markers[idx % len(markers)])
                continue
            
            # Calculate averages
            times = list(time_groups.keys())
            avg_sizes = [np.mean(sizes) for sizes in time_groups.values()]
            
            # Sort by time for correct plotting
            sorted_data = sorted(zip(times, avg_sizes))
            times, avg_sizes = zip(*sorted_data) if sorted_data else ([], [])
            
            # Line plot
            plt.plot(times, avg_sizes, 
                    label=app_label, color=colors[idx % len(colors)], 
                    alpha=0.7, marker=markers[idx % len(markers)])
            
        except Exception as e:
            print(f"Error processing '{pcap_file}': {e}")
            # Add empty plot
            plt.plot([], [], label=app_label, color=colors[idx % len(colors)],
                    marker=markers[idx % len(markers)])
    
    # Graph
    plt.xlabel("Time (sec)")
    plt.ylabel("Average Packet Size (Bytes)")
    plt.title(title)
    plt.legend()
    plt.grid()

    # Show the plot
    plt.show()


def main():
    # Generate three graphs for small, medium and large packets
    plot_packet_size_range("Small Packets (< 200 Bytes)", "frame.len < 200")
    plot_packet_size_range("Medium Packets (200 - 1000 Bytes)","frame.len >= 200 && frame.len <= 1000")
    plot_packet_size_range("Large Packets (> 1000 Bytes)", "frame.len > 1000")
    print("Analysis complete!")


if __name__ == '__main__':
    main()