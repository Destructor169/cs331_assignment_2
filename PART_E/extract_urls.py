#!/usr/bin/env python3
"""
Extract unique URLs/domains from PCAP files for DNS resolution testing
"""

from scapy.all import rdpcap, DNS, DNSQR
import json
import sys
import os

def extract_urls_from_pcap(pcap_file):
    """Extract unique domain names from DNS queries in PCAP"""
    try:
        packets = rdpcap(pcap_file)
        domains = set()
        
        for pkt in packets:
            if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
                # Extract domain name from DNS query
                qname = pkt[DNSQR].qname.decode('utf-8', errors='ignore')
                # Remove trailing dot if present
                if qname.endswith('.'):
                    qname = qname[:-1]
                if qname:
                    domains.add(qname)
        
        return sorted(list(domains))
    except Exception as e:
        print(f"Error reading {pcap_file}: {e}")
        return []

def main():
    # Get the script's directory and find CN folder
    script_dir = os.path.dirname(os.path.abspath(__file__))
    cn_dir = os.path.dirname(script_dir)  # Go up one level from e/ to CN/
    
    pcap_files = {
        'h1': os.path.join(cn_dir, 'PCAP_1_H1.pcap'),
        'h2': os.path.join(cn_dir, 'PCAP_2_H2.pcap'),
        'h3': os.path.join(cn_dir, 'PCAP_3_H3.pcap'),
        'h4': os.path.join(cn_dir, 'PCAP_4_H4.pcap')
    }
    
    print(f"Looking for PCAP files in: {cn_dir}\n")
    
    for host, pcap_file in pcap_files.items():
        print(f"Processing {os.path.basename(pcap_file)}...")
        
        # Check if file exists
        if not os.path.exists(pcap_file):
            print(f"  ✗ ERROR: File not found: {pcap_file}\n")
            continue
            
        domains = extract_urls_from_pcap(pcap_file)
        
        output_file = f'urls_{host}.json'
        output_data = {
            'source_pcap': os.path.basename(pcap_file),
            'total_domains': len(domains),
            'urls': domains
        }
        
        with open(output_file, 'w') as f:
            json.dump(output_data, f, indent=2)
        
        print(f"  ✓ Extracted {len(domains)} unique domains")
        print(f"  ✓ Saved to {output_file}")
        if domains:
            print(f"  Sample: {', '.join(domains[:3])}")
        print()

if __name__ == '__main__':
    main()
