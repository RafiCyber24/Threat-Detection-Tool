from tkinter import filedialog
import tkinter as tk
from scapy.all import *
import datetime
from scapy.layers.dhcp import DHCP
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether

print("🚀 Starting PCAP Security Analyzer...")
root = tk.Tk()
root.withdraw()

file_path = filedialog.askopenfilename(
    title="Select PCAP File",
    filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")]
)
root.destroy()

if file_path:
    print(f"\n📁 Selected file: {file_path}")
else:
    print(f"\n❌ No file selected.")

def read_first_dhcp_packet(file_path):
    # Read all packets from the pcap file
    packets = rdpcap(file_path)

    # Find the first DHCP packet
    for packet in packets:
        if DHCP in packet:
            # Extract timestamp
            timestamp = float(packet.time)
            gmt_time = datetime.datetime.fromtimestamp(timestamp, datetime.UTC)

            # Extract MAC addresses
            src_mac = packet[Ether].src
            dst_mac = packet[Ether].dst

            # Extract IP addresses if IP layer exists
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

            # Extract client name from DHCP options
            client_name = "Unknown"
            for option in packet[DHCP].options:

                # Look for hostname or client FQDN
                if isinstance(option, tuple):
                    if option[0] == 'client_FQDN':
                        # Skip first 3 bytes (flags) in client FQDN
                        client_name = option[1][3:].decode(errors='ignore')
                        break

                    elif option[0] == 'hostname':
                        client_name = option[1].decode(errors='ignore')
                        break

            # Print extracted data
            print(f"\nDHCP Packet Details:")
            print(f"  - Timestamp (Epoch): {timestamp}")
            print(f"  - Actual GMT Time: {gmt_time}")
            print(f"  - Frame Length: {len(packet)} bytes")
            print(f"  - Source MAC: {src_mac}")
            print(f"  - Destination MAC: {dst_mac}")
            print(f"  - Source IP: {src_ip}")
            print(f"  - Destination IP: {dst_ip}")
            print(f"  - Client name: {client_name}")

            # Stop after finding the first DHCP packet
            return

    # If no DHCP packet found
    print("No DHCP packet found in the capture file.")


# Run the function with your PCAP file
read_first_dhcp_packet(file_path)
