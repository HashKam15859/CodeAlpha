from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, DNS, Raw # Import Scapy modules to 
from datetime import datetime # Import datetime for timestamping packets

LOG_FILE = "captured_packets.log" # Log file to store the captured pacekt details


def packet_callback(packet):

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S") # Timestamp
    
    if packet.haslayer(ARP): # Checks for ARP packets
        log_entry = f"{timestamp} | ARP Request: {packet.psrc} is asking about {packet.pdst}" 
    elif packet.haslayer(IP): # Checks for IPv4 packets
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = "UNKNOWN"
        src_port, dst_port = "-", "-"
        
        if packet.haslayer(TCP): # Checks if the protocol is TCP
            protocol = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif packet.haslayer(UDP): # Checks if the protocol is UDP
            protocol = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        elif packet.haslayer(ICMP): # Checks if the protocol is ICMP
            protocol = "ICMP"
        elif packet.haslayer(DNS): # Checks if the protocol is DNS (Query or Response)
            if packet[DNS].qr == 0:
                protocol = "DNS Query"
            else:
                protocol = "DNS Request"
        log_entry = f"{timestamp} | {protocol} | Src: {src_ip}:{src_port} -> Dst: {dst_ip}:{dst_port}"
    else: # Takes any other protocol packets and labels them with Unknown protocol 
        log_entry = f"{timestamp} | Unknown Protocol Detected"
    print(log_entry) # Displays the captured details in the terminal
    
    # Appends the captured packet details to log file
    with open(LOG_FILE, "a") as log_file:
        log_file.write(log_entry + "\n")
        
# Sniff packets
print("Starting network sniffer.....Press Ctrl+C to stop.")
try: 
    sniff(prn=packet_callback, store="False")
except KeyboardInterrupt: 
    print("\nSniffing stopped. Check the log_file: ", LOG_FILE)



# Start sniffing network packets
print("Starting network sniffer.... Press Ctrl+C to stop.") 
try:
    sniff(prn=packet_callback, store="False")  # Capture packets and call packet_callback for each one
except KeyboardInterrupt: # Used to stop the network sniffer
    print("\nSniffing stopped. Saving captured packets to file....")

