# Network Traffic Monitoring & Analysis System Using Wireshark

Educational Computer Networks project. Capture your own authorized traffic in Wireshark and analyze a PCAP/PCAPNG file in a Streamlit dashboard.

## Quick start (Windows PowerShell, VS Code)

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m streamlit run app.py
```

If activation is blocked, skip activation and use:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m streamlit run app.py
```

## Capture instructions
1. Install Wireshark from https://www.wireshark.org/download.html (Windows installer includes Npcap option).
2. Open Wireshark, select active Wi-Fi/Ethernet interface and start capture.
3. Generate a small amount of your own traffic (open a website), stop capture after ~30 seconds.
4. File > Save As > `capture.pcapng`.
5. Open the Streamlit dashboard (typically http://localhost:8501), upload the capture.

## Features
- Packet counts, byte totals, IP addresses and ports
- DNS, TCP, UDP, HTTP, and inferred HTTPS/QUIC categories
- Protocol pie chart, top destination ports, packets-over-time line chart, source IP ranking
- Simple rule-based alerts: >=1000 packets from one source; >=100 TCP SYN packets from one source
- Filters and CSV export

## Scope and limitations
- Analyze only traffic you are authorized to capture.
- The app reads saved capture files; it does not sniff live traffic.
- Port-based labels are approximations; HTTPS is not decrypted.
- Threshold alerts do not establish malicious activity.
- Processing is capped at the first 200,000 packets per upload.
