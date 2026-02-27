# Network Traffic Analyzer

A lightweight web application for real-time network packet capture and analysis, inspired by Wireshark.

## Features

- **Live packet capture** – start/stop capture on any available network interface
- **BPF filter support** – narrow captures with standard Berkeley Packet Filter expressions (e.g. `tcp port 80`)
- **Real-time table** – scrolling packet list with columns for Time, Source, Destination, Protocol, Length, and Info
- **Protocol highlighting** – colour-coded rows for TCP, UDP, HTTP, HTTPS, DNS, ICMP, ARP, SSH, FTP, SMTP, IPv6
- **Statistics bar** – total packet count and per-protocol breakdown updated on every packet
- **Packet detail pane** – click any row to inspect its fields

## Requirements

- Python 3.9+
- Root / Administrator privileges (required for raw packet capture)

## Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run the app (root required for packet capture)
sudo python app.py
```

Then open **http://localhost:5000** in your browser.

## Usage

1. Select a network interface from the dropdown (or use `any`).
2. Optionally enter a BPF filter expression.
3. Click **▶ Start** – packets appear in the table in real time.
4. Click **▐▐ Stop** to pause capture.
5. Click any row to view packet details in the panel below.
6. Click **🗑 Clear** to reset the table.

## Tech Stack

| Layer    | Technology                        |
|----------|-----------------------------------|
| Backend  | Python · Flask · Flask-SocketIO   |
| Capture  | Scapy                             |
| Frontend | HTML · CSS · Vanilla JavaScript   |
| Realtime | Socket.IO (WebSocket)             |