
Author: Subadevan C  
License: MIT  
Year: 2025

## What it does

Netfilter scans `.pcap` files for:

- Sensitive keywords like "flag", "password", "token", etc.
- Image data (jpg, png, gif) inside packet payloads

It saves:

- Found keywords to `flag.txt`
- Images as `img_1.jpg`, `img_2.png`, etc.

## How to use

1. Install Scapy:

```
pip install scapy
```

2. Run the script:

```
python netfilter.py <file.pcap>
```

3. Check the output in your current folder.

## Customize

You can edit the `keywords` and image types in the script as needed.
