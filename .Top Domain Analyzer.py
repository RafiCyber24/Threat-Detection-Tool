import requests
import re
import socket
import datetime
from tkinter import Tk, filedialog


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

    print("🔍 Domains, corresponding IPs and their Health Status : \n")

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
            print(f"❌ Could not resolve IP for {domain}")
            print("__________________\n")

        domain_results.append(domain_info)

    # Generate summary report
    generate_report(final_Domain, domain_results, file_path)

    return domain_results


def select_file():
    Tk().withdraw()
    pcap_file = filedialog.askopenfilename(filetypes=[("PCAP Files", "*.pcap")])

    if pcap_file:
        find_suspect_websites(pcap_file)
    else:
        print("❌ No file selected.")


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

        if data["abuseConfidenceScore"] > 60:
            if data["totalReports"] > 10:
                print("🚨 This Site is Highly Malicious, It's Better to Close the page ❌")
                result["status"] = "Highly Malicious"
            else:
                print("⚠️ This Site is Slightly Suspected")
                result["status"] = "Slightly Suspected"
        elif data["abuseConfidenceScore"] > 30:
            if data["totalReports"] > 5:
                print("⚠️ This Site might contain malicious content or Vulnerabilities")
                result["status"] = "Potentially Malicious"
            else:
                print("⚠️ This Page was infected before. Be Aware!")
                result["status"] = "Previously Infected"
        else:
            print("✅ Good To Goooooo!")
            result["status"] = "Safe"
        print("__________________")
    else:
        print("❌ Error:", response.json())


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
    print("\n🔍 SUMMARY OF FINDINGS:")
    print(f"Total suspicious domains found: {len(domains)}")
    for i, domain in enumerate(domains, 1):
        print(f"{i}. {domain}")

    # Save to report file
    current_time = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    report_filename = f"suspicious_domains_report_{current_time}.txt"



    with open(report_filename, "w") as report:
        report.write("SUSPICIOUS DOMAINS ANALYSIS REPORT\n")
        report.write("=" * 40 + "\n\n")
        report.write(f"Analysis Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        report.write(f"PCAP File Analyzed: {pcap_file}\n\n")
        report.write(f"Total suspicious domains found: {len(domains)}\n\n")

        for i, domain_info in enumerate(domain_results, 1):
            domain = domain_info["domain"]
            report.write(f"Domain {i}: {domain}\n")
            report.write(f"  IP Address: {domain_info['ip']}\n")

            # Write characteristics
            if domain_info["characteristics"]:
                report.write("  Suspicious characteristics:\n")
                for char in domain_info["characteristics"]:
                    report.write(f"  - {char}\n")

            # Write IP reputation data if available
            if domain_info["ip_data"]:
                ip_data = domain_info["ip_data"]
                report.write(f"  Abuse Confidence Score: {ip_data['score']}%\n")
                report.write(f"  Total Reports: {ip_data['reports']}\n")
                report.write(f"  Country: {ip_data['country']}\n")
                report.write(f"  ISP: {ip_data['isp']}\n")
                report.write(f"  Status: {ip_data['status']}\n")

            report.write("\n")

        report.write("\nCONCLUSION:\n")
        report.write("The analysis identified potentially suspicious domains with the '.top' TLD.\n")
        report.write("These domains should be investigated further for malicious activities.\n")
        report.write("Domains with high abuse confidence scores or suspicious characteristics\n")
        report.write("represent the highest risk to network security.\n\n")

        report.write("Report generated automatically by Suspicious Domain Detector\n")

    print(f"\n✅ Report generated: {report_filename}")


# Execute the script
select_file()