import pandas as pd
import matplotlib.pyplot as plt
import pyshark
import numpy as np

# Applications
apps = {
    "filtered_chrome.pcap": "Chrome",
    "filtered_firefox.pcap": "Firefox",
    "filtered_spotify.pcap": "Spotify",
    "filtered_youtube.pcap": "YouTube",
    "filtered_zoom.pcap": "Zoom"
}

# Header types and their display filters
headers = {
    "IP": "frame && ip",
    "TCP": "tcp",
    "TLS": "tls"
}

# Process each header type
for header_name, display_filter in headers.items():
    # Create a figure
    plt.figure(figsize=(12, 6))
    
    # Loop through each application and plot its data
    for pcap_file, app_label in apps.items():
        try:
            print(f"Loading capture file: {pcap_file}")

            # Read PCAP with pyshark using the display filter
            capture = pyshark.FileCapture(pcap_file, display_filter=display_filter)
            
            # List to store packet timestamps
            times = []
            
            # Process each packet
            for packet in capture:
                # Get relative time
                times.append(float(packet.frame_info.time_relative))
            
            # Close the capture
            capture.close()
            
            # Convert to DataFrame
            if times:
                # Create time bins (1-second intervals)
                min_time = min(times)
                max_time = max(times)
                bins = np.arange(np.floor(min_time), np.ceil(max_time) + 1, 1.0)
                
                # Count packets in each 1-second bin
                packet_counts, bin_edges = np.histogram(times, bins=bins)
                
                # Get the bin centers for plotting
                bin_centers = (bin_edges[:-1] + bin_edges[1:]) / 2
                
                # Create DataFrame
                df = pd.DataFrame({"Time": bin_centers, "Packets": packet_counts})
            else:
                # Create empty DataFrame with zero packets if no data
                df = pd.DataFrame({"Time": [0], "Packets": [0]})
            
            # Plot
            plt.plot(df["Time"], df["Packets"], label=app_label)
            
        except Exception as e:
            print(f"Error processing '{pcap_file}': {e}")
            # Plot a zero line to ensure the app still appears
            plt.plot([0], [0], label=app_label)
    
    # Graph
    plt.xlabel("Time (sec)")
    plt.ylabel("Packets/1 sec")
    plt.title(f"Network Traffic Comparison - {header_name} Header")
    plt.legend()
    plt.grid()
    
    # Show the plot
    plt.show()

print("Analysis complete!")