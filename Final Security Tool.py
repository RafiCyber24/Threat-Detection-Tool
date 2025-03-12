import re
import socket
import struct
import tkinter as tk
from collections import Counter
from tkinter import filedialog
import pyshark
import requests

class Colors:
    # Text colors
    BLACK = '\033[30m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'

    # Background colors
    BG_BLACK = '\033[40m'
    BG_RED = '\033[41m'
    BG_GREEN = '\033[42m'
    BG_YELLOW = '\033[43m'
    BG_BLUE = '\033[44m'
    BG_MAGENTA = '\033[45m'
    BG_CYAN = '\033[46m'
    BG_WHITE = '\033[47m'

    # Text styles
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

    # Reset all formatting
    ENDC = '\033[0m'


def select_file():
    """Opens a file dialog to select a PCAP file."""
    print("🚀 Starting PCAP Security Analyzer...")
    print("-" * 60)
    print("This tool helps you analyze network capture (PCAP) files to identify:")
    print(" • Network configuration (DHCP activity)")
    print(" • Potentially malicious websites")
    print(" • User browsing history (search engines)")
    print(" • File format and capture settings")
    print(f"\nPCAP files are created by network monitoring tools like Wireshark,")
    print(f"tcpdump, and other packet capture utilities. They contain a record of")
    print(f"network traffic that can be analyzed for security or troubleshooting.")
    print("=" * 60)

    root = tk.Tk()
    root.withdraw()

    file_path = filedialog.askopenfilename(
        title="Select PCAP File",
        filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")]
    )
    root.destroy()

    if file_path:
        print(f"\n{Colors.YELLOW}📁 Selected file:{Colors.ENDC} {Colors.BOLD} {file_path}{Colors.ENDC}")
        user_requirments(file_path)
    else:
        print(f"\n{Colors.RED}No file selected.❌{Colors.ENDC}")
        print(f"{Colors.BLUE}Please run the program again to select a file.{Colors.ENDC}")


def read_pcap_header(file_path):

    print("\n" + "-" * 50)
    print(f"{Colors.BLUE}{Colors.BOLD}🧠 1.PCAP GLOBAL HEADER INFORMATION{Colors.ENDC}")
    print("-" * 50)

    # Add a brief explanation about what the global header is
    print(f"{Colors.CYAN}The global header is the signature section at the beginning of each PCAP file")
    print(f"that includes metadata about how the capture was recorded.{Colors.ENDC}")
    print("")

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
            print(f"{Colors.BG_BLACK}{Colors.RED}❌ Unknown magic number: {hex(magic_number)}{Colors.ENDC}")

        # Print extracted values
        print(f"PCAP Global Header Information:")
        print(f"  - Length of Global Header: {len(global_header)} bytes")
        print(f"  - Magic Number: {hex(magic_number)} ({endianness})")
        print(f"  - Major Version: {major_version}")
        print(f"  - Minor Version: {minor_version}")
        print(f"  - Snap Length: {snap_length} bytes")
        print(f"  - Data Link Type: {data_link_type} (Ethernet if 1)")

        print(f"\n{Colors.GREEN}✅ Global Header Analysis Complete{Colors.ENDC}")
        print("The global header shows this is a valid PCAP file captured with standard settings.")
        print(f"This file can capture packets up to {snap_length} bytes in length.")
        print(f"The capture used data link type {data_link_type}, which is typically Ethernet in most networks.")


def option_dhcp(file_path):
    # Capture only DHCP packets
    capture = pyshark.FileCapture(file_path, display_filter="dhcp")
    frame_no = []

    # Store DHCP packets in a list with index numbers
    dhcp_packets = list(capture)
    x = len(dhcp_packets)

    print("\n" + "-" * 50)
    print(F"{Colors.BLUE}{Colors.BOLD}🔍 2.Available DHCP Packets:{Colors.ENDC}")
    print("-" * 50)

    # Add a brief explanation about what DHCP is and why it matters
    print(f"{Colors.CYAN}DHCP (Dynamic Host Configuration Protocol) is used to automatically")
    print(f"assign IP addresses to devices on a network. These packets show which")
    print(f"devices requested addresses and what configuration they received.{Colors.ENDC}")
    print("")


    for index, packet in enumerate(dhcp_packets, start=1):
        print(f"{Colors.BOLD}{index}. Frame #{packet.number} {Colors.ENDC}- Time: {packet.sniff_time} - Length: {packet.length} bytes")
        frame_no.append(packet.number)  # Frame numbers stored as strings

    def yes_no():
        try_again = input(F"{Colors.BOLD}\nWanna Do Again? (Y/N): {Colors.ENDC}").strip().lower()
        if try_again == "n":
            print("Thank You!")
            return False
        elif try_again == "y":
            return user_input()
        else:
            print(F"{Colors.RED}Please Only use 'Y' or 'N':{Colors.ENDC}")
            return yes_no()

    def user_input():
        while True:
            choice = input(
                f"\n{Colors.BOLD}Enter the packet number(s) to analyze (e.g., '1' or 'all', multiple numbers separated by space):{Colors.ENDC} ").strip().lower()

            if choice == "all":
                selected_packets = dhcp_packets  # Analyze all packets
            else:
                selected_packets = []
                choices = choice.split()  # Split input into a list

                for item in choices:
                    if item.isdigit():  # Ensure input is a number
                        frame_num = item
                        if frame_num in frame_no:  # Check if frame exists
                            selected_packets.append(dhcp_packets[frame_no.index(frame_num)])
                        else:
                            print(
                                f"{Colors.YELLOW}Frame #{frame_num} not found. Available frames: {frame_no}{Colors.ENDC}")
                            yes_no()
                            break
                    else:
                        print(f"{Colors.RED}Invalid input '{item}'. Please enter only numbers or 'all'.{Colors.ENDC}")
                        break
                else:
                    if not selected_packets:
                        print(f"{Colors.RED} valid frames selected. Please try again.{Colors.ENDC}")
                        continue

            # Process selected packets
            for packet in selected_packets:
                try:
                    dhcp_layer = packet.dhcp
                    src_mac = packet.eth.src
                    dst_mac = packet.eth.dst
                    src_ip = packet.ip.src if hasattr(packet, "ip") else "N/A"
                    dst_ip = packet.ip.dst if hasattr(packet, "ip") else "N/A"

                    print(f"\n📌{Colors.BOLD}Frame #{packet.number}:{Colors.ENDC}")
                    print(f"  - Time: {packet.sniff_time}")
                    print(f"  - Frame Length: {packet.length} bytes")
                    print(f"  - Source MAC: {src_mac}")
                    print(f"  - Destination MAC: {dst_mac}")
                    print(f"  - Source IP: {src_ip}")
                    print(f"  - Destination IP: {dst_ip}")
                    print(f"  - DHCP Message Type: {dhcp_layer.option_dhcp}")

                    print(f"\n{Colors.GREEN}✅ DHCP Analysis Complete{Colors.ENDC}")
                    print(f"Found {len(dhcp_packets)} DHCP packets in the capture.")
                    print("These packets show the IP address assignment process for devices on the network.")
                    print("DHCP activity can reveal new devices joining the network and their identities.")

                except AttributeError:
                    print(
                        f"⚠️{Colors.YELLOW}{Colors.BG_BLACK}⚠Skipping Frame #{packet.number} - Missing DHCP fields.{Colors.ENDC}")

            return False
    capture.close()
    user_input()


def find_suspect_websites(file_path):
    suspect_Domain = []
    domain_results = []

    with open(file_path, "rb") as f:
        data = f.read()

    # Multiple patterns to catch different formats of .top domains
    patterns = [
        rb"https?://([\w\-\.]+\.top)",  # URLs (http://example.top)
        rb"Host:\s*([\w\-\.]+\.top)",  # Host headers
        rb"Referer:\s*https?://([\w\-\.]+\.top)",  # Referer headers
        rb"(?:^|[^a-zA-Z0-9\-])([\w\-\.]+\.top)"  # Standalone domains
    ]

    for pattern in patterns:
        matches = re.findall(pattern, data)
        for x in matches:
            try:
                domain = x.decode("utf-8", errors="ignore").strip()
                if domain and domain not in suspect_Domain:
                    suspect_Domain.append(domain)
            except:
                continue

    final_Domain = list(set(suspect_Domain))

    print("\n" + "=" * 60)
    print(F"{Colors.BLUE}{Colors.BOLD}🔍3.Domains, corresponding IPs and their Health Status  {Colors.ENDC}")
    print("=" * 60)

    # Add a brief explanation about what makes domains suspicious
    print(f"{Colors.CYAN}This analysis searches for .top domains, which are frequently")
    print(f"used for malicious purposes. Each domain is analyzed for suspicious")
    print(f"characteristics and checked against reputation databases.{Colors.ENDC}")
    print("")

    for domain in final_Domain:
        domain_info = {"domain": domain, "ip": "Unknown", "ip_data": None, "characteristics": []}

        # Analyze domain characteristics
        domain_info["characteristics"] = analyze_domain_characteristics(domain)

        # Print domain characteristics
        print(f"🌐 Domain: {domain}")
        if domain_info["characteristics"]:
            print("⚠️ Suspicious characteristics:")
            for char in domain_info["characteristics"]:
                print(f"  - {char}")

        try:
            ip_addr = socket.gethostbyname(domain)
            domain_info["ip"] = ip_addr
            print(f"📡 IP Address: {ip_addr} \n")

            # Analyze IP reputation
            ip_data = check_ip_abuse(ip_addr)
            domain_info["ip_data"] = ip_data

        except socket.gaierror:
            print(f"{Colors.RED}❌ Could not resolve IP for {domain}{Colors.ENDC}")
            print("-" * 100 + ">" + "\n")

        domain_results.append(domain_info)

    # Generate summary report
    generate_report(final_Domain, domain_results, file_path)

    return domain_results


def check_ip_abuse(ip):
    API_KEY = "532fe8dac095a9c0b49e41b72adc5ce41e2e5946d1d9ac5c543e4a9d52dc40cb2a2bcfd60b0f5370"

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Accept": "application/json",
        "Key": API_KEY
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90  # Check reports from the last 90 days
    }

    response = requests.get(url, headers=headers, params=params)

    result = {
        "ip": ip,
        "status": "Unknown",
        "score": 0,
        "reports": 0,
        "country": "Unknown",
        "isp": "Unknown",
        "domain": "Unknown"
    }

    if response.status_code == 200:
        data = response.json()["data"]

        print("🔍 Site Health Check:")
        print(f"🌐 IP: {data['ipAddress']}")
        print(f"⚠️ Abuse Confidence Score: {data['abuseConfidenceScore']}%")
        print(f"📊 Total Reports: {data['totalReports']}")
        print(f"🌍 Country: {data['countryCode']}")
        print(f"🏢 ISP: {data['isp']}")
        print(f"🔗 Domain: {data['domain']} \n")

        print("📝 Site Status:")

        result["ip"] = data['ipAddress']
        result["score"] = data['abuseConfidenceScore']
        result["reports"] = data['totalReports']
        result["country"] = data['countryCode']
        result["isp"] = data['isp']
        result["domain"] = data['domain']

        if data["abuseConfidenceScore"] > 50:
            if data["totalReports"] > 10:
                print(F"🚨{Colors.RED}This Site is Highly Malicious, It's Better to Close the page ❌{Colors.ENDC}")
                result["status"] = "Highly Malicious"
            else:
                print(F"⚠️{Colors.YELLOW}This Site is Slightly Suspected{Colors.ENDC}")
                result["status"] = "Slightly Suspected"
        elif data["abuseConfidenceScore"] > 15:
            if data["totalReports"] > 5:
                print(F"⚠️{Colors.YELLOW}This Site might contain malicious content or Vulnerabilities{Colors.ENDC}")
                result["status"] = "Potentially Malicious"
            else:
                print(f"⚠️{Colors.YELLOW} Page was infected before. Be Aware!{Colors.ENDC}")
                result["status"] = "Previously Infected"
        else:
            print(F"{Colors.GREEN}✅Good To Goooooo!{Colors.ENDC}")
            result["status"] = "Safe"
        print("-" * 100 + ">")
    else:
        print(F"❌{Colors.RED} Error:{Colors.ENDC}", response.json())
    return result


def analyze_domain_characteristics(domain):
    characteristics = []

    # Check for suspicious characteristics
    if domain.endswith('.top'):
        characteristics.append("Uses .top TLD which is known for abuse")

    if len(domain.split('.')[0]) > 15:
        characteristics.append("Unusually long subdomain")

    if re.search(r'[0-9]{4,}', domain):
        characteristics.append("Contains lengthy numeric sequence")

    if re.search(r'[a-zA-Z0-9]{10,}', domain.split('.')[0]):
        characteristics.append("Contains long random-looking string")

    if re.match(r'^[a-z0-9]{8,}$', domain.split('.')[0]):
        characteristics.append("Likely algorithmically generated domain name")

    return characteristics


def generate_report(domains, domain_results, pcap_file):
    print(f"\n{Colors.BOLD}🔍SUMMARY OF FINDINGS:{Colors.ENDC}")
    print(f"Total suspicious domains found: {len(domains)}")
    for i, domain in enumerate(domains, 1):
        print(f"{i}. {domain}")

    print(f"\n{Colors.GREEN}✅ Suspicious Domain Analysis Complete{Colors.ENDC}")
    print(f"Found {len(domains)} potentially suspicious domains in the traffic.")
    print("These domains should be investigated further if they weren't intentionally visited.")
    print("Consider blocking high-risk domains in your network firewall for better security.")


def http_details(file_path):
    # Capture only HTTP requests
    z = 0
    s_engine_count = []
    capture = pyshark.FileCapture(file_path, display_filter="http.request")

    # List of known search engines
    search_engines = {
        "Bing": ["bing.com"],
        "Yahoo": ["search.yahoo.com"],
        "DuckDuckGo": ["duckduckgo.com"],
        "Baidu": ["baidu.com"],
        "Yandex": ["yandex.ru"],
    }

    try:
        # Force packet loading to avoid lazy evaluation issues
        packets = list(capture)
        print("\n" + "=" * 70)
        print(f"{Colors.BLUE}{Colors.BOLD}👀🔐 4.Search Engine Inspector Includes(Search Engine & Related Links){Colors.ENDC}")
        print("=" * 70)

        # Add a brief explanation about search engine monitoring
        print(f"{Colors.CYAN}This analysis identifies search engine usage in the captured traffic.")
        print(f"It shows which search engines were used, what was searched for,")
        print(f"and helps trace user browsing activity.{Colors.ENDC}")
        print("")


        for packet in packets:
            try:
                if hasattr(packet, 'http'):
                    host = getattr(packet.http, 'host', 'Unknown')
                    uri = getattr(packet.http, 'request_uri', '/')
                    method = getattr(packet.http, 'request_method', 'GET')
                    accept_link = getattr(packet.http, 'Accept', 'Clicked website not found')
                    referer_link = getattr(packet.http, 'Referer', 'Referer site not found')

                    # Check if the request comes from a known search engine
                    for engine, domains in search_engines.items():
                        if method == "POST":
                            continue
                        elif any(host.endswith(domain) for domain in domains):
                            print("\n" + "=" * 50)
                            print(f"📌 Search Engine: {engine}")
                            print("=" * 50)
                            print(f"🔹 Method       : {method}")
                            print(f"🔹 Host         : {host}")
                            print(f"🔹 URI          : {uri}")
                            print(f"🔸 Clicked Link : {accept_link}")
                            print(f"🔸 Referer Link : {referer_link}")
                            print("=" * 50 + "\n")
                            z = z + 1
                            s_engine_count.append(engine)



            except AttributeError:
                continue  # Skip packets without HTTP fields

        engine_usage = Counter(s_engine_count)

        print(f"\n{Colors.GREEN}✅ Search Engine Analysis Complete{Colors.ENDC}")

        if engine_usage:
            print(f"Totally {Colors.YELLOW}{z} {Colors.ENDC}Files Scanned")

            for engine, count in engine_usage.items():
                print(f"Most Used Search Engine is {Colors.YELLOW}{engine} {Colors.ENDC}: {count} Used times")
                print("The search terms can reveal what information was being sought during the capture period.")
        else:
            print("\n Not Known search engine traffic found in the capture.")

    except Exception as e:
        print(f"\n{Colors.RED}Error processing PCAP:{e}{Colors.ENDC}")

    capture.close()


def user_requirments(file_path):
    print(F"\n{Colors.GREEN}File Successfully Scanned.{Colors.ENDC}")
    print("This Tool Will Help You To Analyze: ")
    print(" 1.Global Header Of The PCAP File")
    print(" 2.DHCP Frames Inside The PCAP File")
    print(" 3.Suspected Websites In The PCAP File")
    print(" 4.Search Details of the HTTP Frames")

    print(f"\nYou Can Pick '1' {Colors.CYAN}or{Colors.ENDC} '1 2 3' {Colors.CYAN}or{Colors.ENDC} 'all' (Multiple Number Seperated By Space):")
    user_option = input(str("⌨️ Which Details You Wanted To Retrieve? ")).strip().lower()

    def thankyou_msg():
        print(f"\n🏁{Colors.BOLD}Thank you for using PCAP Security Analyzer!{Colors.ENDC}")


    if user_option == "all":
        read_pcap_header(file_path)
        option_dhcp(file_path)
        find_suspect_websites(file_path)
        http_details(file_path)
        thankyou_msg()

        return

    options = user_option.split()

    # Check if any option is invalid
    for option in options:
        if option not in ["1", "2", "3", "4"]:
            print(f"Invalid option: {option}. Please use only 1, 2, 3, or 4.")
            user_requirments(file_path)
            return

    # Process valid options
    if "1" in options:
        read_pcap_header(file_path)
        thankyou_msg()

    if "2" in options:
        option_dhcp(file_path)
        thankyou_msg()

    if "3" in options:
        find_suspect_websites(file_path)
        thankyou_msg()

    if "4" in options:
        http_details(file_path)
        thankyou_msg()
    # If no valid options were provided
    if not options:
        print("Please Use Only 1, 2, 3, or 4")
        user_requirments(file_path)


select_file()
# find_suspect_websites()
