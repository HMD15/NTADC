#!/usr/bin/env python3
"""
Real-time Network Traffic Anomaly Detection with Scapy
Captures and analyzes network traffic for anomalies
"""

import os
import time
import queue
import threading
import pickle
import json
import numpy as np
import pandas as pd
from scapy.all import sniff, IP, TCP, UDP, DNS, Raw
from collections import defaultdict, Counter

# Important features from the dataset
IMPORTANT_NUMERICAL = ['src_port', 'dst_port', 'duration', 'src_bytes', 'dst_bytes', 'src_pkts', 'dst_pkts']
IMPORTANT_CATEGORICAL = ['proto', 'service', 'conn_state']

# Connection tracking
active_connections = {}
completed_connections = []
CONNECTION_TIMEOUT = 60  # seconds

# Scanning detection
port_scan_tracking = defaultdict(lambda: {'ports': set(), 'last_update': 0, 'count': 0})
PORT_SCAN_THRESHOLD = 5  # Reduced from 10 to 5 for more sensitive detection
PORT_SCAN_WINDOW = 10  # Increased from 5 to 10 seconds to catch slower scans

# Thread-safe queues and locks
packet_queue = queue.Queue()
FEATURES_LOCK = threading.Lock()

# Stop events for clean shutdown
STOP_CAPTURE = threading.Event()
STOP_PROCESSING = threading.Event()
STOP_DETECTION = threading.Event()

# Load models and preprocessing components
def load_models(model_dir=None):
    """Load trained models and preprocessing components"""
    if model_dir is None:
        model_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'models')
    
    # Load preprocessor
    with open(os.path.join(model_dir, 'preprocessor.pkl'), 'rb') as f:
        preprocessor = pickle.load(f)
    
    # Load feature selectors
    with open(os.path.join(model_dir, 'selector_binary.pkl'), 'rb') as f:
        selector_binary = pickle.load(f)
    
    with open(os.path.join(model_dir, 'selector_multi.pkl'), 'rb') as f:
        selector_multi = pickle.load(f)
    
    # Load binary classification model
    try:
        # Try to load best model first
        with open(os.path.join(model_dir, 'best_binary_model.pkl'), 'rb') as f:
            binary_model = pickle.load(f)
    except FileNotFoundError:
        # Fall back to RandomForest model
        with open(os.path.join(model_dir, 'binary_randomforest.pkl'), 'rb') as f:
            binary_model = pickle.load(f)
    
    # Load multi-class classification model
    try:
        # Try to load best model first
        with open(os.path.join(model_dir, 'best_multi_model.pkl'), 'rb') as f:
            multi_model = pickle.load(f)
    except FileNotFoundError:
        # Fall back to RandomForest model
        with open(os.path.join(model_dir, 'multi_randomforest.pkl'), 'rb') as f:
            multi_model = pickle.load(f)
    
    # Load label encoder
    with open(os.path.join(model_dir, 'label_encoder.pkl'), 'rb') as f:
        label_encoder = pickle.load(f)
    
    return preprocessor, selector_binary, selector_multi, binary_model, multi_model, label_encoder

# Check if IP is local
def is_local_ip(ip):
    """Check if an IP address is in a local/private range"""
    # Check for localhost
    if ip.startswith('127.'):
        return True
    
    # Check for private IP ranges
    if ip.startswith('10.') or ip.startswith('172.16.') or ip.startswith('192.168.'):
        return True
    
    # Check for link-local addresses
    if ip.startswith('169.254.'):
        return True
    
    return False

# Get connection key from packet
def get_conn_key(packet):
    """Get a unique key for the connection based on IP addresses and ports"""
    if IP not in packet:
        return None
    
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    
    # Get protocol and ports
    if TCP in packet:
        proto = 'tcp'
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
    elif UDP in packet:
        proto = 'udp'
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
    else:
        proto = 'other'
        src_port = 0
        dst_port = 0
    
    # Create a consistent key regardless of direction
    if (src_ip < dst_ip) or (src_ip == dst_ip and src_port < dst_port):
        return (src_ip, src_port, dst_ip, dst_port, proto)
    else:
        return (dst_ip, dst_port, src_ip, src_port, proto)

# Get protocol and service from packet
def get_protocol_service(packet):
    """Extract protocol and service information from packet"""
    # Default values
    proto = 'other'
    service = '-'
    
    # Determine protocol
    if TCP in packet:
        proto = 'tcp'
        dst_port = packet[TCP].dport
        
        # Map common ports to services
        if dst_port == 80 or dst_port == 8080:
            service = 'http'
        elif dst_port == 443:
            service = 'https'
        elif dst_port == 22:
            service = 'ssh'
        elif dst_port == 21:
            service = 'ftp'
        elif dst_port == 25:
            service = 'smtp'
        elif dst_port == 53:
            service = 'dns'
        else:
            service = f'tcp-{dst_port}'
    
    elif UDP in packet:
        proto = 'udp'
        dst_port = packet[UDP].dport
        
        # Map common UDP ports to services
        if dst_port == 53:
            service = 'dns'
        elif dst_port == 67 or dst_port == 68:
            service = 'dhcp'
        elif dst_port == 123:
            service = 'ntp'
        else:
            service = f'udp-{dst_port}'
    
    # Special case for DNS
    if DNS in packet:
        service = 'dns'
    
    return proto, service

# Extract DNS information from packet
def extract_dns_info(packet):
    """Extract DNS-specific information from packet"""
    dns_info = {
        'dns_qry_name': '-',
        'dns_qry_type': 0,
        'dns_qry_class': 0,
        'dns_rcode': 0,
        'dns_rejected': 'no'
    }
    
    if DNS not in packet:
        return dns_info
    
    # Extract DNS query information
    if packet[DNS].qr == 0:  # Query
        if packet[DNS].qd and packet[DNS].qd.qname:
            dns_info['dns_qry_name'] = packet[DNS].qd.qname.decode('utf-8', errors='ignore')
        if packet[DNS].qd and hasattr(packet[DNS].qd, 'qtype'):
            dns_info['dns_qry_type'] = packet[DNS].qd.qtype
        if packet[DNS].qd and hasattr(packet[DNS].qd, 'qclass'):
            dns_info['dns_qry_class'] = packet[DNS].qd.qclass
    else:  # Response
        dns_info['dns_rcode'] = packet[DNS].rcode
        dns_info['dns_rejected'] = 'yes' if packet[DNS].rcode != 0 else 'no'
    
    return dns_info

# Check for port scanning activity
def check_port_scan(src_ip, dst_ip, dst_port):
    """Check if a source IP is performing a port scan"""
    current_time = time.time()
    key = f"{src_ip}->{dst_ip}"
    
    # Update port scan tracking
    if current_time - port_scan_tracking[key]['last_update'] > PORT_SCAN_WINDOW:
        # Reset if outside time window
        port_scan_tracking[key] = {'ports': {dst_port}, 'last_update': current_time, 'count': 1}
    else:
        # Update within time window
        port_scan_tracking[key]['ports'].add(dst_port)
        port_scan_tracking[key]['last_update'] = current_time
        port_scan_tracking[key]['count'] += 1
    
    # Check if this is a port scan
    is_scan = len(port_scan_tracking[key]['ports']) >= PORT_SCAN_THRESHOLD
    
    # Debug output
    if len(port_scan_tracking[key]['ports']) > 3:
        print(f"DEBUG: Potential scan from {src_ip} to {dst_ip}: {len(port_scan_tracking[key]['ports'])} unique ports")
    
    return is_scan, len(port_scan_tracking[key]['ports'])

# Process a packet and update connection state
def process_packet(packet):
    """Process a packet and update connection tracking"""
    if IP not in packet:
        return
    
    # Get connection key
    conn_key = get_conn_key(packet)
    if not conn_key:
        return
    
    # Get current time
    current_time = time.time()
    
    # Extract basic packet info
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    proto, service = get_protocol_service(packet)
    
    # Extract port information
    src_port = 0
    dst_port = 0
    if TCP in packet:
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
    elif UDP in packet:
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
    
    # Check for port scanning
    is_scan = False
    unique_ports = 0
    if TCP in packet or UDP in packet:
        is_scan, unique_ports = check_port_scan(src_ip, dst_ip, dst_port)
    
    # Calculate packet sizes
    ip_len = len(packet[IP])
    payload_len = 0
    if Raw in packet:
        payload_len = len(packet[Raw])
    
    # DNS information
    dns_info = extract_dns_info(packet)
    
    with FEATURES_LOCK:
        # If this is a new connection
        if conn_key not in active_connections:
            active_connections[conn_key] = {
                'start_time': current_time,
                'last_update': current_time,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': src_port,
                'dst_port': dst_port,
                'proto': proto,
                'service': service,
                'src_pkts': 0,
                'dst_pkts': 0,
                'src_bytes': 0,
                'dst_bytes': 0,
                'src_ip_bytes': 0,
                'dst_ip_bytes': 0,
                'missed_bytes': 0,
                'conn_state': 'S0',  # Initial state
                'is_scan': is_scan,
                'unique_ports': unique_ports,
                **dns_info
            }
        
        # Update connection information
        conn = active_connections[conn_key]
        conn['last_update'] = current_time
        
        # Update port scan information
        if is_scan:
            conn['is_scan'] = True
            conn['unique_ports'] = unique_ports
        
        # Update packet and byte counts based on direction
        if src_ip == conn['src_ip']:
            conn['src_pkts'] += 1
            conn['src_bytes'] += payload_len
            conn['src_ip_bytes'] += ip_len
        else:
            conn['dst_pkts'] += 1
            conn['dst_bytes'] += payload_len
            conn['dst_ip_bytes'] += ip_len
        
        # Update connection state for TCP
        if TCP in packet:
            flags = packet[TCP].flags
            if flags & 0x02:  # SYN
                if flags & 0x10:  # ACK
                    conn['conn_state'] = 'S1'  # SYN-ACK
                else:
                    conn['conn_state'] = 'S0'  # SYN
            elif flags & 0x01:  # FIN
                conn['conn_state'] = 'SF'  # FIN
            elif flags & 0x04:  # RST
                conn['conn_state'] = 'REJ'  # RST
            elif conn['src_pkts'] > 0 and conn['dst_pkts'] > 0:
                conn['conn_state'] = 'S3'  # Established
        else:
            # For non-TCP, use simplified states
            if conn['src_pkts'] > 0 and conn['dst_pkts'] > 0:
                conn['conn_state'] = 'S3'  # Established
            else:
                conn['conn_state'] = 'S0'  # Initial

# Check for timed-out connections and add them to completed list
def check_timeouts():
    """Check for timed-out connections and move them to completed list"""
    current_time = time.time()
    
    with FEATURES_LOCK:
        to_remove = []
        for conn_key, conn in active_connections.items():
            # If connection has been inactive for too long
            if current_time - conn['last_update'] > CONNECTION_TIMEOUT:
                # Calculate duration
                conn['duration'] = conn['last_update'] - conn['start_time']
                
                # Add to completed connections
                completed_connections.append(conn)
                
                # Mark for removal
                to_remove.append(conn_key)
        
        # Remove timed-out connections
        for conn_key in to_remove:
            del active_connections[conn_key]

# Convert connection data to feature vector
def connection_to_features(conn):
    """Convert connection data to feature vector matching the training data format"""
    # Create a DataFrame with one row
    df = pd.DataFrame([{
        'src_port': conn['src_port'],
        'dst_port': conn['dst_port'],
        'proto': conn['proto'],
        'service': conn['service'],
        'duration': conn['duration'],
        'src_bytes': conn['src_bytes'],
        'dst_bytes': conn['dst_bytes'],
        'conn_state': conn['conn_state'],
        'missed_bytes': conn['missed_bytes'],
        'src_pkts': conn['src_pkts'],
        'dst_pkts': conn['dst_pkts'],
        'src_ip_bytes': conn['src_ip_bytes'],
        'dst_ip_bytes': conn['dst_ip_bytes']
    }])
    
    return df[IMPORTANT_NUMERICAL + IMPORTANT_CATEGORICAL]

# Capture thread
def capture_thread(interface=None):
    """Thread for capturing network packets"""
    print(f"Starting packet capture on interface: {interface or 'default'}")
    
    # Start packet capture
    sniff(
        iface=interface,
        prn=lambda pkt: packet_queue.put(pkt) if not STOP_CAPTURE.is_set() else None,
        store=0,
        stop_filter=lambda pkt: STOP_CAPTURE.is_set()
    )

# Packet processing thread
def processing_thread():
    """Thread for processing captured packets"""
    print("Starting packet processing thread")
    
    while not STOP_PROCESSING.is_set():
        # Process packets from queue
        try:
            packet = packet_queue.get(timeout=1)
            process_packet(packet)
            packet_queue.task_done()
        except queue.Empty:
            pass
        
        # Check for timeouts every second
        check_timeouts()
        
        # Sleep briefly to reduce CPU usage
        time.sleep(0.01)

# Detection thread
def detection_thread(callback=None):
    """Thread for running anomaly detection on completed connections"""
    print("Starting anomaly detection thread")
    
    # Load models and preprocessing components
    preprocessor, selector_binary, selector_multi, binary_model, multi_model, label_encoder = load_models()
    
    # Track which connections have been processed
    processed_indices = set()
    
    while not STOP_DETECTION.is_set():
        with FEATURES_LOCK:
            # Get new completed connections
            new_connections = [
                conn for i, conn in enumerate(completed_connections)
                if i not in processed_indices
            ]
            
            # Update processed indices
            processed_indices.update(range(len(processed_indices), len(completed_connections)))
        
        # Process new connections
        for conn in new_connections:
            # Check for direct port scan detection first
            is_scan_detected = conn.get('is_scan', False)
            unique_ports = conn.get('unique_ports', 0)
            
            # Debug output for scan detection
            print(f"DEBUG: Connection from {conn['src_ip']} to {conn['dst_ip']} - is_scan: {is_scan_detected}, unique_ports: {unique_ports}")
            
            # Convert connection to features
            features_df = connection_to_features(conn)
            
            # Preprocess features
            X_preprocessed = preprocessor.transform(features_df)
            
            # Apply feature selection
            X_binary = selector_binary.transform(X_preprocessed)
            
            # Make binary prediction (normal vs anomaly)
            # Get probability scores first
            anomaly_proba = 0
            if hasattr(binary_model, 'predict_proba'):
                anomaly_proba = binary_model.predict_proba(X_binary)[0][1]  # Probability of being anomaly
            else:
                # For models without predict_proba, use decision function if available
                if hasattr(binary_model, 'decision_function'):
                    decision_score = binary_model.decision_function(X_binary)[0]
                    # Convert to a pseudo-probability (sigmoid)
                    anomaly_proba = 1 / (1 + np.exp(-decision_score))
            
            # Apply stricter threshold for anomaly detection (default was 0.5)
            # Reduce threshold to increase detection sensitivity
            ANOMALY_THRESHOLD = 0.6  # Lowered from 0.85 to 0.6 to increase detection sensitivity
            is_anomaly = 1 if anomaly_proba > ANOMALY_THRESHOLD else 0
            
            # Debug output for anomaly probability
            print(f"DEBUG: Anomaly probability: {anomaly_proba:.4f}, threshold: {ANOMALY_THRESHOLD}, is_anomaly: {is_anomaly}")
            
            # Override with direct scan detection if applicable
            if is_scan_detected:
                is_anomaly = 1
                print(f"DEBUG: Scan detection override applied, is_anomaly set to 1")
            
            # If anomaly, classify the type
            attack_type = None
            attack_prob = None
            if is_anomaly == 1:
                # If direct scan detection triggered, override classification
                if is_scan_detected:
                    attack_type = 'scanning'
                    attack_prob = 0.95  # High confidence for direct detection
                else:
                    # Apply feature selection for multi-class
                    X_multi = selector_multi.transform(X_preprocessed)
                    
                    # Predict attack type
                    attack_type_idx = multi_model.predict(X_multi)[0]
                    attack_type = label_encoder.inverse_transform([attack_type_idx])[0]
                    
                    # Get probability if available
                    if hasattr(multi_model, 'predict_proba'):
                        probs = multi_model.predict_proba(X_multi)[0]
                        attack_prob = float(probs[attack_type_idx])
            
            # Determine traffic direction - critical for correct classification
            direction = "internal"
            if is_local_ip(conn['src_ip']) and not is_local_ip(conn['dst_ip']):
                direction = "outbound"
            elif not is_local_ip(conn['src_ip']) and is_local_ip(conn['dst_ip']):
                direction = "inbound"
            elif is_local_ip(conn['src_ip']) and is_local_ip(conn['dst_ip']):
                direction = "internal"
            
            # Correct misclassifications based on directionality
            # Inbound connections with many ports are likely scans
            if direction == "inbound" and conn.get('unique_ports', 0) >= PORT_SCAN_THRESHOLD:
                is_anomaly = 1
                attack_type = 'scanning'
                attack_prob = 0.95
            
            # Outbound connections to many different IPs might be DDoS
            # But only if they're actually anomalous by other metrics
            if direction == "outbound" and is_anomaly and attack_type == 'ddos':
                # Verify this is actually a DDoS by checking packet patterns
                if conn['src_pkts'] > 100 and conn['dst_pkts'] < 10:
                    # Confirmed DDoS pattern - many outbound packets, few responses
                    pass
                else:
                    # Likely false positive - reclassify as normal
                    is_anomaly = 0
                    attack_type = 'normal'
                    attack_prob = 0.9
            
            # Create result dictionary
            result = {
                'timestamp': time.time(),
                'src_ip': conn['src_ip'],
                'dst_ip': conn['dst_ip'],
                'src_port': conn['src_port'],
                'dst_port': conn['dst_port'],
                'proto': conn['proto'],
                'service': conn['service'],
                'duration': conn['duration'],
                'src_pkts': conn['src_pkts'],
                'dst_pkts': conn['dst_pkts'],
                'is_anomaly': bool(is_anomaly),
                'attack_type': 'normal',
                'confidence': attack_prob if attack_prob else 1.0,
                'direction': direction,
                'unique_ports': conn.get('unique_ports', 0)
            }
            
            # Set appropriate attack type
            if is_anomaly:
                # If it's an anomaly but the attack type is 'normal', label it as 'unknown'
                if attack_type == 'normal' or attack_type is None:
                    result['attack_type'] = 'unknown anomaly'
                else:
                    result['attack_type'] = attack_type
            
            # Call callback if provided
            if callback:
                callback(result)
            
            # Print detection result with more context
            if is_anomaly:
                print(f"ALERT: {result['attack_type']} attack detected from {conn['src_ip']}:{conn['src_port']} to {conn['dst_ip']}:{conn['dst_port']} ({direction}, unique ports: {conn.get('unique_ports', 0)})")
            else:
                print(f"Normal traffic: {conn['src_ip']}:{conn['src_port']} to {conn['dst_ip']}:{conn['dst_port']} ({direction})")
        
        # Sleep briefly to reduce CPU usage
        time.sleep(0.1)

# Function to start the sniffer
def start_sniffer(interface=None, detection_callback=None):
    """Start the network sniffer with real-time anomaly detection"""
    # Reset stop events
    STOP_CAPTURE.clear()
    STOP_PROCESSING.clear()
    STOP_DETECTION.clear()
    
    # Create and start capture thread
    capture_t = threading.Thread(target=capture_thread, args=(interface,), daemon=True)
    capture_t.start()
    
    # Create and start processing thread
    processing_t = threading.Thread(target=processing_thread, daemon=True)
    processing_t.start()
    
    # Create and start detection thread
    detection_t = threading.Thread(target=detection_thread, args=(detection_callback,), daemon=True)
    detection_t.start()
    
    return (capture_t, processing_t, detection_t)

# Function to stop the sniffer
def stop_sniffer():
    """Stop all sniffer threads"""
    print("Stopping network sniffer...")
    
    # Set stop events
    STOP_CAPTURE.set()
    STOP_PROCESSING.set()
    STOP_DETECTION.set()
    
    # Allow threads time to terminate
    time.sleep(2)
    
    return True

# Main function for standalone testing
def main():
    """Main function for standalone testing"""
    def print_detection(result):
        """Print detection results"""
        if result['is_anomaly']:
            print(f"ALERT: {result['attack_type']} attack detected!")
            print(f"Source: {result['src_ip']}:{result['src_port']}")
            print(f"Destination: {result['dst_ip']}:{result['dst_port']}")
            print(f"Direction: {result['direction']}")
            print(f"Confidence: {result['confidence']:.2f}")
            print("-" * 50)
    
    # Start sniffer
    threads = start_sniffer(detection_callback=print_detection)
    
    try:
        # Keep main thread alive
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Stopping...")
        stop_sniffer()

if __name__ == "__main__":
    main()
