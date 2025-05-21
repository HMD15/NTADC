#!/usr/bin/env python3
"""
Test script for validating network anomaly detection with simulated attacks
"""

import sys
import time
import argparse
from scapy.all import send, IP, TCP, UDP, ICMP, RandShort

def simulate_ddos_attack(target_ip, target_port=80, bursts=5, packets_per_burst=500, interval=1):
    """
    Simulates a DDoS attack by sending bursts of UDP packets to a target
    """
    print(f"[INFO] Simulating DDoS attack to {target_ip}:{target_port}")
    print(f"[INFO] Sending {bursts} bursts of {packets_per_burst} packets each")
    
    packet = IP(dst=target_ip)/UDP(dport=target_port)
    
    for i in range(bursts):
        print(f"[INFO] Burst {i+1}/{bursts} - sending {packets_per_burst} packets...")
        send(packet, count=packets_per_burst, inter=0.001, verbose=False)
        time.sleep(interval)
    
    print("[INFO] DDoS attack simulation complete")

def simulate_port_scan(target_ip, scan_type="SYN", ports=None, delay=0.1):
    """
    Simulates a port scan attack by sending packets to multiple ports
    """
    if ports is None:
        ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]
    
    print(f"[INFO] Simulating {scan_type} port scan on {target_ip}")
    print(f"[INFO] Scanning {len(ports)} ports: {ports}")
    
    for port in ports:
        if scan_type == "SYN":
            # SYN scan
            packet = IP(dst=target_ip)/TCP(dport=port, flags="S", seq=RandShort())
        elif scan_type == "FIN":
            # FIN scan
            packet = IP(dst=target_ip)/TCP(dport=port, flags="F", seq=RandShort())
        elif scan_type == "XMAS":
            # XMAS scan
            packet = IP(dst=target_ip)/TCP(dport=port, flags="FPU", seq=RandShort())
        elif scan_type == "NULL":
            # NULL scan
            packet = IP(dst=target_ip)/TCP(dport=port, flags="", seq=RandShort())
        elif scan_type == "UDP":
            # UDP scan
            packet = IP(dst=target_ip)/UDP(dport=port)
        else:
            print(f"[ERROR] Unknown scan type: {scan_type}")
            return
        
        send(packet, verbose=False)
        print(f"[INFO] Sent {scan_type} packet to port {port}")
        time.sleep(delay)
    
    print(f"[INFO] {scan_type} port scan simulation complete")

def simulate_normal_traffic(target_ip, duration=60, interval=1):
    """
    Simulates normal traffic by sending occasional HTTP-like requests
    """
    print(f"[INFO] Simulating normal traffic to {target_ip} for {duration} seconds")
    
    common_ports = [80, 443, 8080]
    end_time = time.time() + duration
    
    while time.time() < end_time:
        # Send HTTP-like request to a common port
        port = common_ports[int(time.time()) % len(common_ports)]
        packet = IP(dst=target_ip)/TCP(dport=port, flags="S", seq=RandShort())
        send(packet, verbose=False)
        
        # Wait for the next interval
        time.sleep(interval)
    
    print("[INFO] Normal traffic simulation complete")

def main():
    parser = argparse.ArgumentParser(description="Network Anomaly Detection Test Tool")
    parser.add_argument("target_ip", help="Target IP address")
    parser.add_argument("--test", choices=["ddos", "scan", "normal", "all"], default="all",
                        help="Test type to run (default: all)")
    parser.add_argument("--port", type=int, default=80, help="Target port for DDoS (default: 80)")
    parser.add_argument("--scan-type", choices=["SYN", "FIN", "XMAS", "NULL", "UDP"], default="SYN",
                        help="Port scan type (default: SYN)")
    parser.add_argument("--duration", type=int, default=60, 
                        help="Duration in seconds for normal traffic simulation (default: 60)")
    
    args = parser.parse_args()
    
    if args.test == "ddos" or args.test == "all":
        simulate_ddos_attack(args.target_ip, args.port)
        time.sleep(5)  # Pause between tests
    
    if args.test == "scan" or args.test == "all":
        simulate_port_scan(args.target_ip, args.scan_type)
        time.sleep(5)  # Pause between tests
    
    if args.test == "normal" or args.test == "all":
        simulate_normal_traffic(args.target_ip, args.duration)

if __name__ == "__main__":
    main()
