
# Communication Networks - Final Project

## Project Description

In this project, we focused on analyzing and comparing network traffic from several common applications.
Our goal was to understand traffic characteristics across multiple layers and determine how patterns can be distinguished between different applications.

The analysis included:
- Capturing traffic using Wireshark.
- Decoding traffic using saved TLS keys.
- Comparing packet amount and sizes.
- Drawing conclusions regarding an attacker's ability to identify the application the user accessed, based on hash of the 4-tuple flow ID availability.

Please take a look at the [attached PDF](https://github.com/Raz99/CN_final_project/blob/17f36f38d3614cab28ee11abfe2f55ec64a8c5ab/Communication%20Networks%20-%20Final%20Project.pdf).

## Installation
### Prerequisites
Before running the scripts, ensure you have the following installed:

1. **Python Version:** Python 3.13.1 (or similiar)
2. **TShark Installation** (Required for `pyshark`):
   - **Linux:** Run `sudo apt install tshark`
   - **Windows:** Install Wireshark and ensure `tshark` is in the system `PATH`.

### Cloning the Repository
If you haven't already, clone the repository:
```bash
git clone https://github.com/Raz99/CN_final_project.git
cd CN_final_project
```

### Setting Up the Environment
1. **Ensure `pip` is Installed** (For some Python versions):
   ```bash
   python -m ensurepip --default-pip
   ```
2. **Create and Activate a Virtual Environment (Recommended):**
   ```bash
   python -m venv venv
   source venv/bin/activate  # Linux/Mac
   venv\Scripts\activate     # Windows
   ```
3. **Install Required Libraries:**
   ```bash
   pip install pandas matplotlib pyshark numpy
   ```
   These libraries are used as follows:
   - `pandas` for data manipulation.
   - `matplotlib.pyplot` for generating graphs.
   - `pyshark` for reading network traffic from PCAP files.
   - `numpy` for numerical operations.
   - `collections.Counter` for counting occurrences of elements in datasets.

## Scripts

### plot_network_traffic.py
This script analyzes the recorded network traffic (PCAP file) by extracting relevant information and presenting it graphically. It performs three types of analyses:
- IP header fields
- TCP header fields
- TLS header fields

### plot_packet_sizes.py
This script analyzes the recorded network traffic (PCAP file) by extracting relevant information and presenting it graphically. It performs a unique analysis based on packet sizes and generates graphs for:
- Small packets (size < 200 bytes)
- Medium packets (200 bytes <= size <= 1000 bytes)
- Large packets (size > 1000 bytes)

Both scripts use the `pyshark` library to read the recorded files and `matplotlib` to generate graphs.
To run the scripts, make sure to input the path and filenames of the recordings under the `apps` dict defined at the beginning of each script. Current structure:
```python
apps = {
    "filtered_chrome.pcap": "Chrome",
    "filtered_firefox.pcap": "Firefox",
    "filtered_spotify.pcap": "Spotify",
    "filtered_youtube.pcap": "YouTube",
    "filtered_zoom.pcap": "Zoom"
}
```
**Note:** The scripts `plot_network_traffic.py` and `plot_packet_sizes.py` process PCAP files, which may take some time depending on the file size. Running them on some recordings could result in longer execution times.


### plots_bonus.py
This script analyzes the recorded network traffic (PCAP file) by extracting relevant information and presenting it graphically. It performs five types of analyses:
- Packet size distribution
- Time differences between packets
- Flow volume (Bytes per flow)
- Flow size (Number of packets per flow)
- Common destination IP addresses

The script uses the `pyshark` library to read the recorded file and `matplotlib` to generate graphs.
To run the script, make sure to input the path and filename of the recording under the `pcap_file` variable defined at the beginning of the script. Current structure:
```python
pcap_file = 'filtered_spotify_and_emails.pcap'
```

## Review of the first two parts
### Part 1:
This section discusses core challenges in transport and network layers, such as diagnosing slow file transfers, handling TCP flow control, optimizing routing decisions, improving performance with MPTCP, and identifying sources of packet loss.

### Part 2:
This section summarizes three research papers that present advanced methods for classifying encrypted internet traffic.
- The first study introduces FlowPic, which converts flow data into images and uses CNNs for accurate traffic classification.
- The second study presents hRFTC, a hybrid method combining TLS handshake features with flow statistics for early classification.
- The third study shows how machine learning can infer OS, browser, and application from traffic patterns without accessing payload content.

**For the remaining parts (Part 3 & Bonus), there is a detailed explanation below.**

## Recordings

### Part 3:
#### Chrome & Firefox
For browser recordings, we performed the following actions:
- Opened the applications and reached the homepage.
- Searched for "Ariel University" and accessed the university's website.

#### Spotify
- Accessed the Spotify website via Chrome and played a podcast (audio only).

#### YouTube
- Accessed the YouTube website via Chrome and played a video (with both video and audio).

#### Zoom
- Opened the Zoom desktop application and conducted a video call between two computers (including camera, microphone and chat).

### Bonus:
#### Spotify & Gmail
- Accessed the Spotify website via Chrome and played a podcast (audio only).
- Simultaneously, we opened Gmail in Chrome and occasionally sent emails.

## Graphs
### Part 3:
#### Graph A: IP Header Fields
- Shows the number of packets per second at the IP layer.
- Provides insight into the volume of data transmitted in each application per second.

#### Graph B: TCP Header Fields
- Displays the number of packets per second at the TCP layer.
- Shows the number of connections established and the amount of traffic generated per second.

#### Graph C: TLS Header Fields
- Displays the number of packets per second at the TLS layer.
- Shows the number of encrypted packets per second.

#### Graph D: Packet Size
Displays three different graphs:

1. Small packets
2. Medium packets
3. Large packets

These graphs are useful for understanding the frequency and size of packets in each application.

### Bonus:
Displays five different graphs:
1. Packet size distribution
2. Time differences between packets
3. Flow volume (Bytes per flow)
4. Flow size (Number of packets per flow)
5. Common destination IP addresses

## Sources
- YouTube
- ChatGPT
- Wikipedia

The full and detailed list is included in the attached PDF (link above).

## Authors
- Raz Cohen - [GitHub](https://github.com/Raz99), [LinkedIn](https://www.linkedin.com/in/raz-cohen-p)
- Ronen Chereshnya - [GitHub](https://github.com/ronench20), [LinkedIn](https://www.linkedin.com/in/ronen-chereshnya-7566b41b2)
- Shir Bismuth - [GitHub](https://github.com/shirbismuth)
- Clara Franco - [GitHub](https://github.com/francoclara)

## Acknowledgments
Course Lecturer: Professor Amit Zeev Dvir
