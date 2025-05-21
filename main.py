#!/usr/bin/env python3
"""
Main entry point for the Network Traffic Anomaly Detection Tool
Integrates all components and provides a unified interface
"""

import os
import sys
import argparse
from PyQt5.QtWidgets import QApplication

# Import our modules
from gui import NetworkMonitorGUI
from model_integration import AnomalyDetector
from network_sniffer import start_sniffer

def main():
    """Main function to start the application"""
    parser = argparse.ArgumentParser(description='Network Traffic Anomaly Detection Tool')
    parser.add_argument('--cli', action='store_true', help='Run in command-line mode without GUI')
    parser.add_argument('--interface', type=str, help='Network interface to monitor')
    parser.add_argument('--test', action='store_true', help='Run in test mode with simulated traffic')
    args = parser.parse_args()
    
    # If CLI mode is requested
    if args.cli:
        print("Starting Network Traffic Anomaly Detection Tool in CLI mode...")
        
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
        print(f"Monitoring network interface: {args.interface or 'default'}")
        detector.start_monitoring(interface=args.interface)
        
        try:
            # Keep the main thread alive
            import time
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nStopping monitoring...")
            detector.stop_monitoring()
            print("Monitoring stopped. Exiting.")
    else:
        # GUI mode
        app = QApplication(sys.argv)
        
        # Check if PyQtGraph is installed
        try:
            import pyqtgraph
        except ImportError:
            # Install PyQtGraph if not available
            import subprocess
            subprocess.call([sys.executable, "-m", "pip", "install", "pyqtgraph"])
            
            # Try importing again
            try:
                import pyqtgraph
            except ImportError:
                print("Error: Failed to install required dependency: pyqtgraph")
                return 1
        
        # Create and show the main window
        window = NetworkMonitorGUI()
        window.show()
        
        # If interface is specified, start monitoring automatically
        if args.interface:
            window.interface_combo.setCurrentText(args.interface)
            window.start_monitoring()
        
        # Start the application event loop
        return app.exec_()

if __name__ == "__main__":
    sys.exit(main())
