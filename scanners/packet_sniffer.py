from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, DNS
from datetime import datetime
import threading
import logging
import sys

LOG_FILE = "captured_packets.log"

# Setup logging
logging.basicConfig(
    filename=LOG_FILE, level=logging.INFO, format="%asctime)s | %(message)s"
)
console = logging.StreamHandler()
console.setLevel(logging.INFO)
formatter = logging.Formatter("%(asctime)s | %(message)s")
console.setFormatter(formatter)
logging.getLogger("").addHandler(console)

# Thread-safe pring and logging
log_back = threading.Lock()


def log_packet(entry):
    with log_back:
        logging.info(entry)


def packet_callback(packet):
    try:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if packet.haslayer(ARP):
            entry = f"ARP Request: {packet.psrc} is asking about {packet.pdst}"
        elif packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = "UNKNOWN"
            src_port = "-"
            dst_port = "-"

            if packet.haslayer(TCP):
                protocol = "TCP"
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
            elif packet.haslayer(UDP):
                protocol = "UDP"
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
            elif packet.haslayer(ICMP):
                protocol = "ICMP"
            elif packet.haslayer(DNS):
                protocol = "DNS Query" if packet[DNS].qr == 0 else "DNS Response"

            entry = f"{protocol} | Src: {src_ip}: {src_port} | Dst: {dst_ip}:{dst_port}"
        else:
            entry = f"Unknown Protocol Detected: {packet.summary()}"

        log_packet(entry)
    except Exception as e:
        log_packet(f"Error processing packet: {e}")
        sys.exit(1)


def start_sniffing(interface=None):
    try:
        print("Starting network sniffer.....Press Ctrl+C to stop.")
        sniff(prn=packet_callback, store=False, iface=interface)
    except KeyboardInterrupt:
        print("\nSniffing stopped. Packets saved to log file.")

    except Exception as e:
        print(f"Critical error: {e}")
        sys.exit(1)
    finally:
        print("Exiting sniffer.....")
        sys.exit(0)


if __name__ == "__main__":
    iface = sys.argv[1] if len(sys.argv) > 1 else None
    start_sniffing(interface=iface)
