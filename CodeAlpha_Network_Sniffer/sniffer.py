import argparse
import csv
import os
import sys
from datetime import datetime

from scapy.all import sniff, get_if_list, IP, IPv6, TCP, UDP, ICMP, DNS, Raw


class NetworkSniffer:
    def __init__(self, interface=None, output="packets.csv", limit=0):
        self.interface = interface
        self.output = output
        self.limit = limit
        self.packet_count = 0
        self.file_handle = None
        self.csv_writer = None

    def list_interfaces(self):
        interfaces = get_if_list()

        print("\nAvailable Network Interfaces")
        print("=" * 65)

        for index, interface in enumerate(interfaces, start=1):
            print(f"{index}. {interface}")

        print("=" * 65)

    def open_report(self):
        file_exists = os.path.isfile(self.output)
        needs_header = (
            not file_exists
            or os.path.getsize(self.output) == 0
        )

        self.file_handle = open(
            self.output,
            "a",
            newline="",
            encoding="utf-8"
        )

        self.csv_writer = csv.writer(self.file_handle)

        if needs_header:
            self.csv_writer.writerow([
                "Timestamp",
                "Protocol",
                "Source IP",
                "Source Port",
                "Destination IP",
                "Destination Port",
                "Packet Length",
                "Payload Preview"
            ])

    def identify_protocol(self, packet):
        if DNS in packet:
            return "DNS"

        if TCP in packet:
            return "TCP"

        if UDP in packet:
            return "UDP"

        if ICMP in packet:
            return "ICMP"

        if IPv6 in packet:
            return "IPv6"

        if IP in packet:
            return "IP"

        return "OTHER"

    def extract_packet_data(self, packet):
        source_ip = "N/A"
        destination_ip = "N/A"
        source_port = "N/A"
        destination_port = "N/A"

        if IP in packet:
            source_ip = packet[IP].src
            destination_ip = packet[IP].dst

        elif IPv6 in packet:
            source_ip = packet[IPv6].src
            destination_ip = packet[IPv6].dst

        if TCP in packet:
            source_port = packet[TCP].sport
            destination_port = packet[TCP].dport

        elif UDP in packet:
            source_port = packet[UDP].sport
            destination_port = packet[UDP].dport

        payload_preview = ""

        if Raw in packet:
            payload_preview = (
                bytes(packet[Raw].load)[:32]
                .hex(" ")
            )

        return (
            source_ip,
            source_port,
            destination_ip,
            destination_port,
            payload_preview
        )

    def process_packet(self, packet):
        self.packet_count += 1

        timestamp = datetime.now().astimezone().isoformat(
            timespec="seconds"
        )

        protocol = self.identify_protocol(packet)

        (
            source_ip,
            source_port,
            destination_ip,
            destination_port,
            payload_preview
        ) = self.extract_packet_data(packet)

        packet_length = len(packet)

        print("\n" + "=" * 65)
        print(f"Packet Number      : {self.packet_count}")
        print(f"Timestamp          : {timestamp}")
        print(f"Protocol           : {protocol}")
        print(f"Source IP          : {source_ip}")
        print(f"Source Port        : {source_port}")
        print(f"Destination IP     : {destination_ip}")
        print(f"Destination Port   : {destination_port}")
        print(f"Packet Length      : {packet_length} bytes")
        print(f"Payload Preview    : {payload_preview or 'No raw payload'}")

        self.csv_writer.writerow([
            timestamp,
            protocol,
            source_ip,
            source_port,
            destination_ip,
            destination_port,
            packet_length,
            payload_preview
        ])

        self.file_handle.flush()

    def start(self):
        self.open_report()

        print("\nCODEALPHA NETWORK SNIFFER")
        print("=" * 65)
        print(f"Interface : {self.interface or 'Default interface'}")
        print(f"Report    : {os.path.abspath(self.output)}")
        print(f"Packet Limit: {self.limit or 'Unlimited'}")
        print("=" * 65)
        print("Capturing packets. Press Ctrl+C to stop.\n")

        try:
            sniff(
                iface=self.interface,
                prn=self.process_packet,
                store=False,
                count=self.limit
            )

        except KeyboardInterrupt:
            print("\nPacket capture stopped by user.")

        except PermissionError:
            print(
                "\nPermission denied. Reopen the terminal "
                "with Administrator privileges."
            )

        except Exception as error:
            print(f"\nCapture failed: {error}")
            print(
                "Check Npcap installation and the selected "
                "network interface."
            )

        finally:
            if self.file_handle:
                self.file_handle.close()

            print(f"\nTotal Packets Captured: {self.packet_count}")
            print(f"CSV Report: {os.path.abspath(self.output)}")


def main():
    parser = argparse.ArgumentParser(
        description="CodeAlpha Basic Network Sniffer"
    )

    parser.add_argument(
        "-i",
        "--interface",
        help="Network interface name"
    )

    parser.add_argument(
        "-c",
        "--count",
        type=int,
        default=0,
        help="Number of packets to capture; 0 means unlimited"
    )

    parser.add_argument(
        "-o",
        "--output",
        default="packets.csv",
        help="CSV report filename"
    )

    parser.add_argument(
        "--list-interfaces",
        action="store_true",
        help="Display available network interfaces"
    )

    args = parser.parse_args()

    if args.count < 0:
        parser.error("Packet count cannot be negative.")

    sniffer = NetworkSniffer(
        interface=args.interface,
        output=args.output,
        limit=args.count
    )

    if args.list_interfaces:
        sniffer.list_interfaces()
        return

    try:
        sniffer.start()

    except OSError as error:
        print(f"Unable to create the report file: {error}")
        sys.exit(1)


if __name__ == "__main__":
    main()
