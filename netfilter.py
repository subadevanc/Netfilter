from scapy.all import *
import sys
import re
import os


print("""
 ███╗   ██╗███████╗████████╗███████╗██╗██╗     ███████╗████████╗███████╗██████╗ 
 ████╗  ██║██╔════╝╚══██╔══╝██╔════╝██║██║     ██╔════╝╚══██╔══╝██╔════╝██╔══██╗
 ██╔██╗ ██║█████╗     ██║   █████╗  ██║██║     █████╗     ██║   █████╗  ██████╔╝
 ██║╚██╗██║██╔══╝     ██║   ██╔══╝  ██║██║     ██╔══╝     ██║   ██╔══╝  ██╔══██╗
 ██║ ╚████║███████╗   ██║   ███████╗██║███████╗███████╗   ██║   ███████╗██║  ██║
 ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝╚═╝╚══════╝╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
                 Netfilter v1.0 — PCAP Keyword and Image Extractor
                        Author: Subadevan C | 2025 ©
--------------------------------------------------------------------------------
A powerful yet minimal Python-based forensic tool to scan PCAP files for
sensitive keyword leaks and embedded image data.

✔ Automatically detects and extracts credentials, tokens, and secrets.
✔ Scans and saves images (JPG, PNG, GIF) embedded in raw packet data.
✔ Outputs human-readable findings to 'flag.txt'.

Usage:
    python netfilter.py <file.pcap>
--------------------------------------------------------------------------------
"""
)

# Keywords to detect
keywords = [b"flag", b"password", b"pass", b"sessionid", b"token", b"auth", b"key", b"login", b"secret"]

img_signatures = {
    b'\xff\xd8\xff': 'jpg',
    b'\x89PNG\r\n\x1a\n': 'png',
    b'GIF89a': 'gif',
    b'GIF87a': 'gif'
}

# Prepare output files
flag_file = open("flag.txt", "w")
flag_file.write("Netfilter — Keyword Payloads Found\n\n")
img_count = 0

print("\n Netfilter — PCAP Scanner\n")

if len(sys.argv) != 2:
    print("Usage: python netfilter.py <file.pcap>")
    sys.exit(1)

pcap_file = sys.argv[1]

try:
    packets = rdpcap(pcap_file)
except:
    print("Couldn't load file.")
    sys.exit(1)

print("Packets loaded:", len(packets))
print("="*60)

for i, pkt in enumerate(packets):
    if pkt.haslayer(Raw):
        raw = pkt[Raw].load
        found = False

        # Keyword match
        for key in keywords:
            if key in raw.lower():
                try:
                    payload = raw.decode(errors='ignore')
                    for k in keywords:
                        payload = re.sub(k.decode(), f"[**{k.decode()}**]", payload, flags=re.IGNORECASE)
                    flag_file.write(f"[#] Packet {i + 1}\n")
                    flag_file.write(payload[:200] + "\n")
                    flag_file.write("-"*60 + "\n")
                    found = True
                except:
                    flag_file.write(f"[#] Packet {i + 1} — Keyword Found (Undecodable)\n")
                    flag_file.write("-"*60 + "\n")
                break

        if found:
            continue  # if saved to flag.txt, skip image check

        # Image detection
        for sig, ext in img_signatures.items():
            if raw.startswith(sig):
                img_count += 1
                filename = f"img_{img_count}.{ext}"
                with open(filename, "wb") as f:
                    f.write(raw)
                print(f"Extracted image → {filename}")
                break  # skip further checks once image found

flag_file.close()

print("\nDone.")
print(f"Keywords saved to: flag.txt")
print(f"Images saved: {img_count}")
