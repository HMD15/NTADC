
# Network Traffic Anomaly Detection Tool - User Manual

## Overview

The Network Traffic Anomaly Detection Tool is designed to monitor network traffic in real-time, detect anomalies, and classify potential attacks. The tool uses machine learning models trained on the TON-IoT dataset to identify various types of network attacks.

## Installation

### Prerequisites

- Python 3.8 or higher
- PyQt5
- Scapy
- PyQtGraph
- NumPy, Pandas, Scikit-learn

### Installation Steps

1. Ensure all prerequisites are installed:
   ```
   pip install PyQt5 scapy pyqtgraph numpy pandas scikit-learn
   ```

2. Extract the provided package to your desired location.

3. The package includes pre-trained models based on the TON-IoT dataset.

## Usage

### Starting the Application

1. Navigate to the installation directory.

2. Run the main application:
   ```
   python main.py
   ```

   For command-line mode without GUI:
   ```
   python main.py --cli
   ```

   To specify a network interface:
   ```
   python main.py --interface eth0
   ```

### Using the GUI

The GUI consists of four main tabs:

1. **Dashboard**:
   - Overview of network traffic statistics
   - Real-time traffic graphs
   - Recent alerts display

2. **Alerts**:
   - Detailed list of detected anomalies
   - Alert details and information

3. **Traffic Analysis**:
   - Protocol distribution
   - Port usage statistics
   - Traffic flow information

4. **Settings**:
   - Detection sensitivity configuration
   - Alert notification settings
   - Display preferences

### Starting Monitoring

1. Select the network interface from the dropdown menu.
2. Click "Start Monitoring" to begin capturing and analyzing network traffic.
3. The dashboard will update in real-time with traffic statistics and alerts.

### Responding to Alerts

When an anomaly is detected:

1. A desktop notification will appear (if enabled).
2. The alert will be added to the Alerts tab.
3. The dashboard will show the alert in the recent alerts section.
4. Traffic graphs will update to show the anomaly.

### Stopping Monitoring

Click "Stop Monitoring" to cease packet capture and analysis.

## Troubleshooting

### Common Issues

1. **Permission Errors**:
   - The application requires administrator/root privileges to capture network packets.
   - Run the application with sudo/administrator rights.

2. **No Traffic Detected**:
   - Ensure the correct network interface is selected.
   - Verify that the interface is active and connected.

3. **High Resource Usage**:
   - Reduce the update frequency in Settings.
   - Limit the maximum number of alerts to display.

### Getting Help

For additional assistance, please refer to the documentation or contact support.

## Technical Details

The tool consists of several components:

1. **Network Sniffer**: Uses Scapy to capture and process network packets.
2. **Feature Extraction**: Converts raw packets into feature vectors.
3. **Anomaly Detection**: Uses machine learning models to identify anomalies.
4. **Classification**: Categorizes detected anomalies by attack type.
5. **GUI**: Provides visualization and interaction capabilities.

The pre-trained models were developed using the TON-IoT dataset and achieve high accuracy in detecting various network attacks.
