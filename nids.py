import argparse
from scanners import port_scanner
from scanners import packet_sniffer
import threading


def run_sniffer(interface=None):
    packet_sniffer.run_sniffing(interface)


def run_scanner(target, start_port, end_port):
    ports = port_scanner.run_port_scan(target, (start_port, end_port))
    print(f"\n[+] Final Open Ports: {ports}")


def main():
    parser = argparse.ArgumentParser(
        description="Modular Network Intrusion Detection System"
    )
    parser.add_argument(
        "-s", "--sniff", action="store_true", help="Start packet sniffer"
    )
    parser.add_argument(
        "-p",
        "--portscan",
        metavar="TARGET",
        help="Start port scanner for the target IP",
    )
    parser.add_argument("--iface", help="Specify network interface for sniffing")
    parser.add_argument(
        "--start", type=int, default=1, help="Start port for scanning (default=1)"
    )
    parser.add_argument(
        "--end", type=int, default=1024, help="End port for scanning (deefault=1024)"
    )

    args = parser.parse_args()
    threads = []

    if args.sniff:
        sniff_thread = threading.Thread(target=run_sniffer, args=(args.iface,))
        sniff_thread.start()
        threads.append(sniff_thread)

    if args.portscan:
        scan_thread = threading.Thread(
            target=run_scanner, args=(args.portscan, args.start, args.end)
        )
        scan_thread.start()
        threads.append(scan_thread)

    if not args.sniff and not args.portscan:
        parser.print_help()

    for thread in threads:
        thread.join()


if __name__ == "__main__":
    main()
