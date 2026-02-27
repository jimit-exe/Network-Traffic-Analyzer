import os
import threading
from datetime import datetime

from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit

from scapy.all import (
    sniff, get_if_list, IP, IPv6, TCP, UDP, ICMP, DNS, ARP, Raw
)

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", os.urandom(24))
socketio = SocketIO(app, async_mode="threading")

# Shared state
_capture_thread = None
_stop_event = threading.Event()
_packet_count = 0
_stats = {}
_lock = threading.Lock()


def _get_protocol(pkt):
    """Return a human-readable protocol name for a packet."""
    if pkt.haslayer(DNS):
        return "DNS"
    if pkt.haslayer(TCP):
        sport, dport = pkt[TCP].sport, pkt[TCP].dport
        if 80 in (sport, dport):
            return "HTTP"
        if 443 in (sport, dport):
            return "HTTPS"
        if 22 in (sport, dport):
            return "SSH"
        if 21 in (sport, dport):
            return "FTP"
        if 25 in (sport, dport) or 587 in (sport, dport):
            return "SMTP"
        return "TCP"
    if pkt.haslayer(UDP):
        return "UDP"
    if pkt.haslayer(ICMP):
        return "ICMP"
    if pkt.haslayer(ARP):
        return "ARP"
    if pkt.haslayer(IPv6):
        return "IPv6"
    if pkt.haslayer(IP):
        return "IP"
    return "Other"


def _get_info(pkt):
    """Return a short description of the packet."""
    if pkt.haslayer(DNS):
        dns = pkt[DNS]
        try:
            if dns.qr == 0 and dns.qdcount > 0 and dns.qd:
                return f"Query: {dns.qd.qname.decode(errors='replace')}"
            if dns.qr == 1 and dns.ancount > 0 and dns.an:
                return f"Response: {dns.an.rdata}"
        except Exception:
            pass
        return "DNS"
    if pkt.haslayer(TCP):
        flags = pkt[TCP].sprintf("%TCP.flags%")
        return f"{pkt[TCP].sport} → {pkt[TCP].dport} [{flags}]"
    if pkt.haslayer(UDP):
        return f"{pkt[UDP].sport} → {pkt[UDP].dport}"
    if pkt.haslayer(ICMP):
        types = {0: "Echo Reply", 3: "Destination Unreachable", 8: "Echo Request",
                 11: "Time Exceeded"}
        return types.get(pkt[ICMP].type, f"Type={pkt[ICMP].type}")
    if pkt.haslayer(ARP):
        op = "Request" if pkt[ARP].op == 1 else "Reply"
        return f"ARP {op}: {pkt[ARP].psrc} → {pkt[ARP].pdst}"
    return ""


def _packet_handler(pkt):
    global _packet_count
    if _stop_event.is_set():
        return

    protocol = _get_protocol(pkt)
    src = pkt[IP].src if pkt.haslayer(IP) else (
        pkt[IPv6].src if pkt.haslayer(IPv6) else (
            pkt[ARP].psrc if pkt.haslayer(ARP) else "N/A"
        )
    )
    dst = pkt[IP].dst if pkt.haslayer(IP) else (
        pkt[IPv6].dst if pkt.haslayer(IPv6) else (
            pkt[ARP].pdst if pkt.haslayer(ARP) else "N/A"
        )
    )

    with _lock:
        _packet_count += 1
        count = _packet_count
        _stats[protocol] = _stats.get(protocol, 0) + 1
        stats_snapshot = dict(_stats)

    data = {
        "id": count,
        "time": datetime.now().strftime("%H:%M:%S.%f")[:-3],
        "src": src,
        "dst": dst,
        "protocol": protocol,
        "length": len(pkt),
        "info": _get_info(pkt),
        "stats": stats_snapshot,
    }
    socketio.emit("packet", data)


def _capture_worker(iface, bpf_filter):
    try:
        sniff(
            iface=iface if iface != "any" else None,
            filter=bpf_filter or None,
            prn=_packet_handler,
            store=False,
            stop_filter=lambda _: _stop_event.is_set(),
        )
    except Exception as e:
        socketio.emit("error", {"message": str(e)})


# ── Routes ──────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/interfaces")
def interfaces():
    ifaces = ["any"] + get_if_list()
    return jsonify(ifaces)


@app.route("/api/start", methods=["POST"])
def start_capture():
    global _capture_thread, _packet_count, _stats

    if _capture_thread and _capture_thread.is_alive():
        return jsonify({"status": "already running"}), 200

    iface = request.json.get("interface", "any")
    bpf_filter = request.json.get("filter", "")

    _stop_event.clear()
    with _lock:
        _packet_count = 0
        _stats = {}

    _capture_thread = threading.Thread(
        target=_capture_worker, args=(iface, bpf_filter), daemon=True
    )
    _capture_thread.start()
    return jsonify({"status": "started"})


@app.route("/api/stop", methods=["POST"])
def stop_capture():
    _stop_event.set()
    return jsonify({"status": "stopped"})


@app.route("/api/stats")
def stats():
    with _lock:
        return jsonify({"total": _packet_count, "protocols": dict(_stats)})


if __name__ == "__main__":
    socketio.run(app, host="127.0.0.1", port=5000, debug=False, allow_unsafe_werkzeug=True)
