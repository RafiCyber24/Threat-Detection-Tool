from collections import Counter
from tkinter import filedialog
import tkinter as tk
import pyshark


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
    print(f"Search Engine Inspector")

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

    if engine_usage:
        print(F"\nSearch Engine Usage Status:")
        print(f"Totally {z} Files Scanned")

        for engine, count in engine_usage.items():
            print(f"Most Used Search Engine is {engine}: {count} Used times")

    else:
        print("\n Not Known search engine traffic found in the capture.")

except Exception as e:
    print(f"\nError processing PCAP:{e}")

capture.close()
