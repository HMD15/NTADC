# Network Traffic Anomaly Detection Testing Guide

This guide provides step-by-step instructions for testing the real time detection capabilities of your Network Traffic Anomaly Detection tool. It includes procedures for validating both attack detection and confidence threshold functionality.

## Prerequisites

1. The Network Traffic Anomaly Detector application installed and running
2. Python with Scapy installed (included in requirements.txt)
3. Administrator/root privileges for packet capture
4. Two machines on the same network (one running the detector, one for attack simulation)

## Testing the Confidence Threshold

The confidence threshold has been fixed and now properly filters alerts based on your settings:

1. Open the Network Traffic Anomaly Detector application
2. Go to the "Settings" tab
3. Adjust the "Minimum Confidence Threshold" slider (default: 70%)
4. Start monitoring your network
5. Run attack simulations with varying intensities
6. Verify that only attacks with confidence above your threshold generate alerts

## Attack Simulation Testing

We've provided a test script (`test_attacks.py`) that can simulate various attacks to validate detection:

### DDoS Attack Test

```bash
# From your attack simulation machine:
sudo python3 test_attacks.py <target_ip> --test ddos --port 80
```

Expected result:
- The detector should identify this as a DDoS attack
- You should see alerts in the application with "ddos" attack type
- The attack distribution graph should show DDoS attacks

### Port Scanning Test

```bash
# From your attack simulation machine:
sudo python3 test_attacks.py <target_ip> --test scan --scan-type SYN
```

Expected result:
- The detector should identify this as a scanning attack
- You should see alerts with "scanning" attack type
- The attack distribution graph should show scanning attacks

### Testing Different Scan Types

```bash
# Try different scan types:
sudo python3 test_attacks.py <target_ip> --test scan --scan-type FIN
sudo python3 test_attacks.py <target_ip> --test scan --scan-type XMAS
sudo python3 test_attacks.py <target_ip> --test scan --scan-type NULL
sudo python3 test_attacks.py <target_ip> --test scan --scan-type UDP
```

### Normal Traffic Test

```bash
# Generate normal traffic:
sudo python3 test_attacks.py <target_ip> --test normal --duration 30
```

Expected result:
- The detector should classify this as normal traffic
- The normal traffic counter should increase
- No alerts should be generated

## Using Kali Linux for Testing

If you have Kali Linux available, you can use its built-in tools for more realistic testing:

### Nmap Scanning
```bash
# Basic scan:
sudo nmap -sS <target_ip>

# Aggressive scan:
sudo nmap -A -T4 <target_ip>

# Comprehensive scan:
sudo nmap -sS -sV -O -A <target_ip>
```

### Hping3 for DDoS Simulation
```bash
# SYN flood:
sudo hping3 -S --flood -V -p 80 <target_ip>

# UDP flood:
sudo hping3 --udp -p 80 --flood <target_ip>
```

## Validation Checklist

- [ ] DDoS attack detection works
- [ ] Port scanning detection works
- [ ] Normal traffic is correctly classified
- [ ] Confidence threshold properly filters alerts
- [ ] Start/stop monitoring functions work correctly
- [ ] GUI statistics update in real-time
- [ ] Alerts are displayed in the alerts tab

## Troubleshooting

If detection is not working as expected:

1. Verify that you're running the application with administrator/root privileges
2. Check that you've selected the correct network interface
3. Ensure the attack simulation is targeting the correct IP address
4. Try adjusting the confidence threshold to a lower value (e.g., 50%)
5. Check the console output for any error messages

## Feedback

After testing, please provide feedback on:
- Detection accuracy for different attack types
- False positive/negative rates
- GUI responsiveness
- Any errors or unexpected behavior

This will help us further improve the tool to meet your specific needs.
