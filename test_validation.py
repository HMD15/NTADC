#!/usr/bin/env python3
"""
Test script for validating end-to-end functionality of the Network Traffic Anomaly Detection Tool
"""

import os
import sys
import time
import threading
import random
from scapy.all import IP, TCP, UDP, ICMP, Ether, Raw, sendp
from model_integration import AnomalyDetector

# Path to models directory
MODELS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'models')

def generate_normal_packet():
    """Generate a normal network packet"""
    # Create a random source and destination IP
    src_ip = f"192.168.1.{random.randint(2, 254)}"
    dst_ip = f"192.168.1.{random.randint(2, 254)}"
    
    # Create random source and destination ports
    src_port = random.randint(1024, 65535)
    dst_port = random.choice([80, 443, 22, 53, 8080])
    
    # Choose protocol (TCP or UDP)
    if random.random() < 0.8:  # 80% TCP
        proto = TCP(sport=src_port, dport=dst_port, flags="S")
    else:  # 20% UDP
        proto = UDP(sport=src_port, dport=dst_port)
    
    # Create packet
    packet = Ether()/IP(src=src_ip, dst=dst_ip)/proto
    
    # Add some random payload
    payload = "".join(random.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(random.randint(10, 100)))
    packet = packet/Raw(load=payload)
    
    return packet

def generate_attack_packet(attack_type):
    """Generate an attack packet of the specified type"""
    # Create a random source and destination IP
    src_ip = f"192.168.1.{random.randint(2, 254)}"
    dst_ip = f"192.168.1.{random.randint(2, 254)}"
    
    # Create random source and destination ports
    src_port = random.randint(1024, 65535)
    
    if attack_type == "ddos":
        # DDoS attack - many packets to same destination
        dst_port = 80
        proto = TCP(sport=src_port, dport=dst_port, flags="S")
        packet = Ether()/IP(src=src_ip, dst=dst_ip)/proto
    
    elif attack_type == "scanning":
        # Port scanning - sequential ports
        dst_port = random.randint(1, 1024)
        proto = TCP(sport=src_port, dport=dst_port, flags="S")
        packet = Ether()/IP(src=src_ip, dst=dst_ip)/proto
    
    elif attack_type == "injection":
        # SQL injection payload
        dst_port = 80
        proto = TCP(sport=src_port, dport=dst_port, flags="A")
        payload = "' OR 1=1; DROP TABLE users; --"
        packet = Ether()/IP(src=src_ip, dst=dst_ip)/proto/Raw(load=payload)
    
    elif attack_type == "xss":
        # XSS payload
        dst_port = 80
        proto = TCP(sport=src_port, dport=dst_port, flags="A")
        payload = "<script>alert('XSS')</script>"
        packet = Ether()/IP(src=src_ip, dst=dst_ip)/proto/Raw(load=payload)
    
    else:
        # Generic attack packet
        dst_port = random.randint(1, 1024)
        proto = TCP(sport=src_port, dport=dst_port, flags="S")
        packet = Ether()/IP(src=src_ip, dst=dst_ip)/proto
    
    return packet

def packet_generator_thread(interface="lo", duration=60, attack_probability=0.2):
    """Thread to generate and send test packets"""
    print(f"Starting packet generator on interface {interface} for {duration} seconds")
    print(f"Attack probability: {attack_probability * 100}%")
    
    # Get available attack types
    attack_types = ["ddos", "scanning", "injection", "xss", "backdoor", "dos"]
    
    start_time = time.time()
    packet_count = 0
    attack_count = 0
    
    while time.time() - start_time < duration:
        # Decide if this is an attack packet
        is_attack = random.random() < attack_probability
        
        if is_attack:
            # Choose a random attack type
            attack_type = random.choice(attack_types)
            packet = generate_attack_packet(attack_type)
            attack_count += 1
            print(f"Sending attack packet: {attack_type}")
        else:
            # Generate normal packet
            packet = generate_normal_packet()
        
        # Send the packet
        try:
            sendp(packet, iface=interface, verbose=0)
            packet_count += 1
        except Exception as e:
            print(f"Error sending packet: {str(e)}")
        
        # Sleep for a random time
        time.sleep(random.uniform(0.1, 0.5))
    
    print(f"Packet generator finished. Sent {packet_count} packets ({attack_count} attacks)")

def test_detector():
    """Test the anomaly detector with simulated traffic"""
    print("Testing anomaly detector with simulated traffic")
    
    # Initialize the detector
    detector = AnomalyDetector()
    
    # Define a callback function for alerts
    def alert_callback(result):
        print("\n" + "=" * 50)
        print(f"ALERT: {result['attack_type']} attack detected!")
        print(f"Source: {result['src_ip']}:{result['src_port']}")
        print(f"Destination: {result['dst_ip']}:{result['dst_port']}")
        print(f"Confidence: {result['confidence']:.2f}")
        print("=" * 50)
    
    # Register the callback
    detector.register_callback(alert_callback)
    
    # Start monitoring
    print("Starting network monitoring on loopback interface")
    detector.start_monitoring(interface="lo")
    
    # Start packet generator thread
    generator_thread = threading.Thread(
        target=packet_generator_thread,
        kwargs={"interface": "lo", "duration": 60, "attack_probability": 0.2},
        daemon=True
    )
    generator_thread.start()
    
    try:
        # Wait for the generator to finish
        generator_thread.join()
        
        # Keep monitoring for a bit longer to process remaining packets
        print("Packet generation complete. Continuing monitoring for 10 more seconds...")
        time.sleep(10)
        
    except KeyboardInterrupt:
        print("\nTest interrupted by user")
    finally:
        # Stop monitoring
        print("Stopping monitoring...")
        detector.stop_monitoring()
        print("Test complete")

def main():
    """Main function"""
    # Check if models exist
    if not os.path.exists(MODELS_DIR):
        print(f"Error: Models directory not found: {MODELS_DIR}")
        return 1
    
    # Check if required model files exist
    required_files = [
        'preprocessor.pkl',
        'selector_binary.pkl',
        'selector_multi.pkl',
        'binary_randomforest.pkl',
        'multi_randomforest.pkl',
        'label_encoder.pkl'
    ]
    
    missing_files = [f for f in required_files if not os.path.exists(os.path.join(MODELS_DIR, f))]
    if missing_files:
        print(f"Error: Missing required model files: {', '.join(missing_files)}")
        return 1
    
    # Run the test
    test_detector()
    return 0

if __name__ == "__main__":
    sys.exit(main())
