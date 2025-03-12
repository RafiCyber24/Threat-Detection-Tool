import struct
from tkinter import filedialog
import tkinter as tk

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


def read_pcap_header(file_path):
    with open(file_path, 'rb') as f:
        # Read the first 24 bytes of the PCAP file (global header)
        global_header = f.read(24)

        # Unpack the header fields
        magic_number, major_version, minor_version, _, _, snap_length, data_link_type = struct.unpack('I H H i I I I',
                                                                                                      global_header)

        # Determine endianness based on the magic number
        if magic_number == 0xa1b2c3d4:
            endianness = "Big Endian (Standard PCAP)"
        elif magic_number == 0xd4c3b2a1:
            endianness = "Little Endian (Reversed PCAP)"
        else:
            endianness = "Unknown format"

        # Print extracted values
        print(f"PCAP Global Header Information:")
        print(f"  - Length of Global Header: {len(global_header)} bytes")
        print(f"  - Magic Number: {hex(magic_number)} ({endianness})")
        print(f"  - Major Version: {major_version}")
        print(f"  - Minor Version: {minor_version}")
        print(f"  - Snap Length: {snap_length} bytes")
        print(f"  - Data Link Type: {data_link_type} (Ethernet if 1)")


# Run the function on the provided PCAP file
read_pcap_header(file_path)
