#!/bin/python3

import re   #used to define patterns to detect sql injection
from scapy.all import sniff, IP, TCP  #scapy a network manipulation tool
#sniff to sniff packets, ip address and TCP for tcp connection
# Signature for SQL Injection (basic example)
sql_injection_pattern = re.compile(r"(\b(select|insert|update|delete|drop|union|into|load_file|outfile)\b.*[';]+)")  #basic regular expression that matches common sql injection such as SELECT INSERT UPDATE DROP

# List of blocked IPs (for demonstration purposes)
blocked_ips = []

def is_sql_injection(payload):
    """
    This function checks if the payload contains SQL Injection patterns.
    ACCEPTS the payloads and checks if it contain sql injection patterns	
    """
    if sql_injection_pattern.search(payload):
        return True
    return False

def block_ip(ip):
    """
    Adds the given IP address to the blocked IP list and prints a message.
    when attack is detected , block_ip functions adds ip to blocked_ips
    """
    if ip not in blocked_ips:
        blocked_ips.append(ip)
        print(f"Blocking IP: {ip}")

def packet_callback(packet):
    """
    This function is called for each captured packet.
    It inspects the packet for SQL injection attempts.
    the core function that processes each captured packet
    the function has an iplayer and a tcp layer
    extract the source and destinantion ip and payload
    """
    if packet.haslayer(IP) and packet.haslayer(TCP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst

        # Extract the payload (the data inside the TCP packet)
        payload = str(packet[TCP].payload)

        # If a potential SQL Injection is found in the payload
        if is_sql_injection(payload):
            print(f"Potential SQL Injection detected from {ip_src} to {ip_dst}: {payload}")
            block_ip(ip_src)

def start_sniffing():
    """
    Starts sniffing network packets and applies the callback function.
    """
    print("Starting packet sniffing...")
    sniff(prn=packet_callback, store=0)

if __name__ == "__main__":
    start_sniffing()

