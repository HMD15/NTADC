#!/usr/bin/env python3
"""
PyQt5 GUI for Network Traffic Anomaly Detection and Classification
Provides real-time monitoring, visualization, and alerts for network traffic anomalies
"""

import os
import sys
import time
import json
import threading
import queue
import numpy as np
from datetime import datetime
from PyQt5.QtWidgets import (QApplication, QMainWindow, QTabWidget, QWidget, QVBoxLayout, 
                            QHBoxLayout, QLabel, QPushButton, QComboBox, QTableWidget, 
                            QTableWidgetItem, QHeaderView, QProgressBar, QTextEdit, 
                            QSplitter, QFrame, QCheckBox, QGroupBox, QFormLayout, 
                            QSpinBox, QMessageBox, QSystemTrayIcon, QMenu, QAction)
from PyQt5.QtCore import Qt, QTimer, pyqtSignal, QThread, QSize
from PyQt5.QtGui import QIcon, QColor, QPixmap, QPainter, QPen, QBrush, QFont
import pyqtgraph as pg

# Import our modules
from model_integration import AnomalyDetector

# Alert queue for thread-safe communication
alert_queue = queue.Queue()

class NetworkMonitorGUI(QMainWindow):
    """Main GUI window for network traffic monitoring and anomaly detection"""
    
    def __init__(self):
        super().__init__()
        
        # Initialize the anomaly detector
        self.detector = AnomalyDetector()
        
        # Set up the UI
        self.init_ui()
        
        # Initialize data structures
        self.alerts = []
        self.traffic_stats = {
            'normal': 0,
            'anomaly': 0,
            'total_packets': 0,
            'connections': 0,
            'attack_types': {}
        }
        
        # Set up the system tray icon
        self.setup_tray_icon()
        
        # Register callback with the detector
        self.detector.register_callback(self.handle_detection)
        
        # Start the alert processing timer
        self.alert_timer = QTimer()
        self.alert_timer.timeout.connect(self.process_alerts)
        self.alert_timer.start(100)  # Process alerts every 100ms
        
        # Start the stats update timer
        self.stats_timer = QTimer()
        self.stats_timer.timeout.connect(self.update_stats_display)
        self.stats_timer.start(1000)  # Update stats every second
        
        # Start the graph update timer
        self.graph_timer = QTimer()
        self.graph_timer.timeout.connect(self.update_graphs)
        self.graph_timer.start(2000)  # Update graphs every 2 seconds
        
        # Initialize monitoring status
        self.monitoring_active = False
    
    def init_ui(self):
        """Initialize the user interface"""
        self.setWindowTitle('Network Traffic Anomaly Detector')
        self.setGeometry(100, 100, 1200, 800)
        
        # Create the central widget and layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        
        # Create the control panel
        control_panel = self.create_control_panel()
        main_layout.addLayout(control_panel)
        
        # Create the tab widget
        self.tabs = QTabWidget()
        main_layout.addWidget(self.tabs)
        
        # Create the dashboard tab
        dashboard_tab = self.create_dashboard_tab()
        self.tabs.addTab(dashboard_tab, "Dashboard")
        
        # Create the alerts tab
        alerts_tab = self.create_alerts_tab()
        self.tabs.addTab(alerts_tab, "Alerts")
        
        # Create the traffic tab
        traffic_tab = self.create_traffic_tab()
        self.tabs.addTab(traffic_tab, "Traffic Analysis")
        
        # Create the settings tab
        settings_tab = self.create_settings_tab()
        self.tabs.addTab(settings_tab, "Settings")
        
        # Create status bar
        self.statusBar().showMessage('Ready')
    
    def create_control_panel(self):
        """Create the control panel with start/stop buttons"""
        control_layout = QHBoxLayout()
        
        # Interface selection
        self.interface_label = QLabel("Network Interface:")
        control_layout.addWidget(self.interface_label)
        
        self.interface_combo = QComboBox()
        self.interface_combo.addItem("Default")
        # Add available interfaces
        try:
            from scapy.arch import get_if_list
            interfaces = get_if_list()
            for iface in interfaces:
                self.interface_combo.addItem(iface)
        except:
            pass
        control_layout.addWidget(self.interface_combo)
        
        # Spacer
        control_layout.addStretch()
        
        # Start button
        self.start_button = QPushButton("Start Monitoring")
        self.start_button.clicked.connect(self.start_monitoring)
        control_layout.addWidget(self.start_button)
        
        # Stop button
        self.stop_button = QPushButton("Stop Monitoring")
        self.stop_button.clicked.connect(self.stop_monitoring)
        self.stop_button.setEnabled(False)
        control_layout.addWidget(self.stop_button)
        
        return control_layout
    
    def create_dashboard_tab(self):
        """Create the dashboard tab with overview and stats"""
        dashboard_widget = QWidget()
        dashboard_layout = QVBoxLayout(dashboard_widget)
        
        # Stats overview section
        stats_group = QGroupBox("Network Traffic Statistics")
        stats_layout = QHBoxLayout()
        
        # Normal traffic stats
        self.normal_count = QLabel("0")
        self.normal_count.setStyleSheet("font-size: 24px; color: green;")
        normal_layout = QVBoxLayout()
        normal_layout.addWidget(QLabel("Normal Traffic"))
        normal_layout.addWidget(self.normal_count, alignment=Qt.AlignCenter)
        stats_layout.addLayout(normal_layout)
        
        # Anomaly stats
        self.anomaly_count = QLabel("0")
        self.anomaly_count.setStyleSheet("font-size: 24px; color: red;")
        anomaly_layout = QVBoxLayout()
        anomaly_layout.addWidget(QLabel("Anomalies Detected"))
        anomaly_layout.addWidget(self.anomaly_count, alignment=Qt.AlignCenter)
        stats_layout.addLayout(anomaly_layout)
        
        # Total packets
        self.packet_count = QLabel("0")
        self.packet_count.setStyleSheet("font-size: 24px;")
        packet_layout = QVBoxLayout()
        packet_layout.addWidget(QLabel("Total Packets"))
        packet_layout.addWidget(self.packet_count, alignment=Qt.AlignCenter)
        stats_layout.addLayout(packet_layout)
        
        # Connections
        self.connection_count = QLabel("0")
        self.connection_count.setStyleSheet("font-size: 24px;")
        conn_layout = QVBoxLayout()
        conn_layout.addWidget(QLabel("Connections"))
        conn_layout.addWidget(self.connection_count, alignment=Qt.AlignCenter)
        stats_layout.addLayout(conn_layout)
        
        stats_group.setLayout(stats_layout)
        dashboard_layout.addWidget(stats_group)
        
        # Graphs section
        graphs_splitter = QSplitter(Qt.Horizontal)
        
        # Traffic over time graph
        traffic_group = QGroupBox("Traffic Over Time")
        traffic_layout = QVBoxLayout()
        self.traffic_graph = pg.PlotWidget()
        self.traffic_graph.setBackground('w')
        self.traffic_graph.setTitle("Packets per Second")
        self.traffic_graph.setLabel('left', 'Packets')
        self.traffic_graph.setLabel('bottom', 'Time')
        self.traffic_graph.showGrid(x=True, y=True)
        self.traffic_data = {'time': [], 'normal': [], 'anomaly': []}
        self.normal_line = self.traffic_graph.plot(pen=pg.mkPen('g', width=2), name="Normal")
        self.anomaly_line = self.traffic_graph.plot(pen=pg.mkPen('r', width=2), name="Anomaly")
        traffic_layout.addWidget(self.traffic_graph)
        traffic_group.setLayout(traffic_layout)
        graphs_splitter.addWidget(traffic_group)
        
        # Attack distribution pie chart
        attack_group = QGroupBox("Attack Type Distribution")
        attack_layout = QVBoxLayout()
        self.attack_graph = pg.PlotWidget()
        self.attack_graph.setBackground('w')
        self.attack_graph.setTitle("Attack Types")
        self.attack_graph.setAspectLocked(True)
        attack_layout.addWidget(self.attack_graph)
        attack_group.setLayout(attack_layout)
        graphs_splitter.addWidget(attack_group)
        
        dashboard_layout.addWidget(graphs_splitter)
        
        # Recent alerts section
        alerts_group = QGroupBox("Recent Alerts")
        alerts_layout = QVBoxLayout()
        
        self.recent_alerts_table = QTableWidget()
        self.recent_alerts_table.setColumnCount(5)
        self.recent_alerts_table.setHorizontalHeaderLabels(["Time", "Source", "Destination", "Attack Type", "Confidence"])
        self.recent_alerts_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        alerts_layout.addWidget(self.recent_alerts_table)
        
        alerts_group.setLayout(alerts_layout)
        dashboard_layout.addWidget(alerts_group)
        
        return dashboard_widget
    
    def create_alerts_tab(self):
        """Create the alerts tab with detailed alert information"""
        alerts_widget = QWidget()
        alerts_layout = QVBoxLayout(alerts_widget)
        
        # Alerts table
        self.alerts_table = QTableWidget()
        self.alerts_table.setColumnCount(7)
        self.alerts_table.setHorizontalHeaderLabels([
            "Time", "Source IP", "Source Port", "Destination IP", 
            "Destination Port", "Attack Type", "Confidence"
        ])
        self.alerts_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        alerts_layout.addWidget(self.alerts_table)
        
        # Alert details
        details_group = QGroupBox("Alert Details")
        details_layout = QVBoxLayout()
        
        self.alert_details = QTextEdit()
        self.alert_details.setReadOnly(True)
        details_layout.addWidget(self.alert_details)
        
        details_group.setLayout(details_layout)
        alerts_layout.addWidget(details_group)
        
        return alerts_widget
    
    def create_traffic_tab(self):
        """Create the traffic analysis tab with detailed traffic information"""
        traffic_widget = QWidget()
        traffic_layout = QVBoxLayout(traffic_widget)
        
        # Traffic statistics graphs
        stats_splitter = QSplitter(Qt.Horizontal)
        
        # Protocol distribution
        proto_group = QGroupBox("Protocol Distribution")
        proto_layout = QVBoxLayout()
        self.proto_graph = pg.PlotWidget()
        self.proto_graph.setBackground('w')
        self.proto_graph.setTitle("Protocols")
        proto_layout.addWidget(self.proto_graph)
        proto_group.setLayout(proto_layout)
        stats_splitter.addWidget(proto_group)
        
        # Port distribution
        port_group = QGroupBox("Top Ports")
        port_layout = QVBoxLayout()
        self.port_graph = pg.PlotWidget()
        self.port_graph.setBackground('w')
        self.port_graph.setTitle("Top Destination Ports")
        port_layout.addWidget(self.port_graph)
        port_group.setLayout(port_layout)
        stats_splitter.addWidget(port_group)
        
        traffic_layout.addWidget(stats_splitter)
        
        # Traffic flow table
        flow_group = QGroupBox("Traffic Flows")
        flow_layout = QVBoxLayout()
        
        self.flow_table = QTableWidget()
        self.flow_table.setColumnCount(7)
        self.flow_table.setHorizontalHeaderLabels([
            "Source IP", "Source Port", "Destination IP", 
            "Destination Port", "Protocol", "Packets", "Status"
        ])
        self.flow_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        flow_layout.addWidget(self.flow_table)
        
        flow_group.setLayout(flow_layout)
        traffic_layout.addWidget(flow_group)
        
        return traffic_widget
    
    def create_settings_tab(self):
        """Create the settings tab with configuration options"""
        settings_widget = QWidget()
        settings_layout = QVBoxLayout(settings_widget)
        
        # Detection settings
        detection_group = QGroupBox("Detection Settings")
        detection_layout = QFormLayout()
        
        # Confidence threshold
        self.confidence_threshold = QSpinBox()
        self.confidence_threshold.setRange(50, 100)
        self.confidence_threshold.setValue(70)
        self.confidence_threshold.setSuffix("%")
        detection_layout.addRow("Minimum Confidence Threshold:", self.confidence_threshold)
        
        # Alert settings
        self.enable_alerts = QCheckBox("Enable Desktop Notifications")
        self.enable_alerts.setChecked(True)
        detection_layout.addRow("", self.enable_alerts)
        
        self.enable_sound = QCheckBox("Enable Sound Alerts")
        self.enable_sound.setChecked(True)
        detection_layout.addRow("", self.enable_sound)
        
        detection_group.setLayout(detection_layout)
        settings_layout.addWidget(detection_group)
        
        # Display settings
        display_group = QGroupBox("Display Settings")
        display_layout = QFormLayout()
        
        # Update frequency
        self.update_frequency = QSpinBox()
        self.update_frequency.setRange(1, 10)
        self.update_frequency.setValue(2)
        self.update_frequency.setSuffix(" seconds")
        display_layout.addRow("Graph Update Frequency:", self.update_frequency)
        self.update_frequency.valueChanged.connect(self.update_timer_intervals)
        
        # Max alerts to display
        self.max_alerts = QSpinBox()
        self.max_alerts.setRange(10, 1000)
        self.max_alerts.setValue(100)
        display_layout.addRow("Maximum Alerts to Display:", self.max_alerts)
        
        display_group.setLayout(display_layout)
        settings_layout.addWidget(display_group)
        
        # Add spacer
        settings_layout.addStretch()
        
        return settings_widget
    
    def setup_tray_icon(self):
        """Set up the system tray icon for notifications"""
        self.tray_icon = QSystemTrayIcon(self)
        self.tray_icon.setIcon(QIcon.fromTheme("network-wired"))
        
        # Create tray menu
        tray_menu = QMenu()
        
        show_action = QAction("Show", self)
        show_action.triggered.connect(self.show)
        tray_menu.addAction(show_action)
        
        hide_action = QAction("Hide", self)
        hide_action.triggered.connect(self.hide)
        tray_menu.addAction(hide_action)
        
        quit_action = QAction("Quit", self)
        quit_action.triggered.connect(self.close)
        tray_menu.addAction(quit_action)
        
        self.tray_icon.setContextMenu(tray_menu)
        self.tray_icon.show()
    
    def start_monitoring(self):
        """Start network monitoring"""
        if self.monitoring_active:
            return
        
        # Get selected interface
        interface = self.interface_combo.currentText()
        if interface == "Default":
            interface = None
        
        # Start the detector
        try:
            self.detector.start_monitoring(interface=interface)
            self.monitoring_active = True
            
            # Update UI
            self.start_button.setEnabled(False)
            self.stop_button.setEnabled(True)
            self.interface_combo.setEnabled(False)
            self.statusBar().showMessage(f'Monitoring active on interface: {interface or "default"}')
            
            # Show notification
            self.tray_icon.showMessage(
                "Network Monitoring Started",
                f"Monitoring active on interface: {interface or 'default'}",
                QSystemTrayIcon.Information,
                2000
            )
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to start monitoring: {str(e)}")
    
    def stop_monitoring(self):
        """Stop network monitoring"""
        if not self.monitoring_active:
            return
        
        # Stop the detector
        try:
            self.detector.stop_monitoring()
            self.monitoring_active = False
            
            # Update UI
            self.start_button.setEnabled(True)
            self.stop_button.setEnabled(False)
            self.interface_combo.setEnabled(True)
            self.statusBar().showMessage('Monitoring stopped')
            
            # Show notification
            self.tray_icon.showMessage(
                "Network Monitoring Stopped",
                "Network traffic monitoring has been stopped",
                QSystemTrayIcon.Information,
                2000
            )
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to stop monitoring: {str(e)}")
    
    def handle_detection(self, result):
        """Handle detection results from the detector"""
        # Add to alert queue for thread-safe processing
        alert_queue.put(result)
    
    def process_alerts(self):
        """Process alerts from the queue"""
        # Process all available alerts
        while not alert_queue.empty():
            try:
                result = alert_queue.get_nowait()
                
                # Process based on detection result
                if result['is_anomaly']:
                    # Add to alerts list
                    self.alerts.append(result)
                    
                    # Update stats
                    self.traffic_stats['anomaly'] += 1
                    attack_type = result['attack_type']
                    if attack_type in self.traffic_stats['attack_types']:
                        self.traffic_stats['attack_types'][attack_type] += 1
                    else:
                        self.traffic_stats['attack_types'][attack_type] = 1
                    
                    # Update alerts table
                    self.update_alerts_table()
                    
                    # Show notification if enabled
                    if self.enable_alerts.isChecked():
                        self.show_alert_notification(result)
                else:
                    # Update normal traffic stats
                    self.traffic_stats['normal'] += 1
                
                # Update total packets and connections
                self.traffic_stats['total_packets'] += 1
                if result.get('src_pkts', 0) > 0 and result.get('dst_pkts', 0) > 0:
                    self.traffic_stats['connections'] += 1
                
                # Mark as processed
                alert_queue.task_done()
            except queue.Empty:
                break
    
    def update_alerts_table(self):
        """Update the alerts tables with the latest alerts"""
        # Get max alerts to display
        max_alerts = self.max_alerts.value()
        
        # Limit alerts list
        if len(self.alerts) > max_alerts:
            self.alerts = self.alerts[-max_alerts:]
        
        # Update main alerts table
        self.alerts_table.setRowCount(len(self.alerts))
        
        for i, alert in enumerate(reversed(self.alerts)):
            # Time
            time_item = QTableWidgetItem(datetime.fromtimestamp(alert['timestamp']).strftime('%H:%M:%S'))
            self.alerts_table.setItem(i, 0, time_item)
            
            # Source IP
            src_ip_item = QTableWidgetItem(alert['src_ip'])
            self.alerts_table.setItem(i, 1, src_ip_item)
            
            # Source Port
            src_port_item = QTableWidgetItem(str(alert['src_port']))
            self.alerts_table.setItem(i, 2, src_port_item)
            
            # Destination IP
            dst_ip_item = QTableWidgetItem(alert['dst_ip'])
            self.alerts_table.setItem(i, 3, dst_ip_item)
            
            # Destination Port
            dst_port_item = QTableWidgetItem(str(alert['dst_port']))
            self.alerts_table.setItem(i, 4, dst_port_item)
            
            # Attack Type
            attack_type_item = QTableWidgetItem(alert['attack_type'])
            attack_type_item.setForeground(QColor('red'))
            self.alerts_table.setItem(i, 5, attack_type_item)
            
            # Confidence
            confidence_item = QTableWidgetItem(f"{alert['confidence']*100:.1f}%")
            self.alerts_table.setItem(i, 6, confidence_item)
        
        # Update recent alerts table (dashboard)
        self.recent_alerts_table.setRowCount(min(5, len(self.alerts)))
        
        for i, alert in enumerate(reversed(self.alerts[:5])):
            # Time
            time_item = QTableWidgetItem(datetime.fromtimestamp(alert['timestamp']).strftime('%H:%M:%S'))
            self.recent_alerts_table.setItem(i, 0, time_item)
            
            # Source
            src_item = QTableWidgetItem(f"{alert['src_ip']}:{alert['src_port']}")
            self.recent_alerts_table.setItem(i, 1, src_item)
            
            # Destination
            dst_item = QTableWidgetItem(f"{alert['dst_ip']}:{alert['dst_port']}")
            self.recent_alerts_table.setItem(i, 2, dst_item)
            
            # Attack Type
            attack_type_item = QTableWidgetItem(alert['attack_type'])
            attack_type_item.setForeground(QColor('red'))
            self.recent_alerts_table.setItem(i, 3, attack_type_item)
            
            # Confidence
            confidence_item = QTableWidgetItem(f"{alert['confidence']*100:.1f}%")
            self.recent_alerts_table.setItem(i, 4, confidence_item)
    
    def update_stats_display(self):
        """Update the statistics display"""
        # Update count labels
        self.normal_count.setText(str(self.traffic_stats['normal']))
        self.anomaly_count.setText(str(self.traffic_stats['anomaly']))
        self.packet_count.setText(str(self.traffic_stats['total_packets']))
        self.connection_count.setText(str(self.traffic_stats['connections']))
        
        # Update status bar
        if self.monitoring_active:
            self.statusBar().showMessage(
                f"Monitoring active | Normal: {self.traffic_stats['normal']} | "
                f"Anomalies: {self.traffic_stats['anomaly']} | "
                f"Total: {self.traffic_stats['total_packets']}"
            )
    
    def update_graphs(self):
        """Update all graphs with the latest data"""
        current_time = time.time()
        
        # Update traffic over time graph
        if len(self.traffic_data['time']) > 100:
            # Remove old data points
            self.traffic_data['time'] = self.traffic_data['time'][-100:]
            self.traffic_data['normal'] = self.traffic_data['normal'][-100:]
            self.traffic_data['anomaly'] = self.traffic_data['anomaly'][-100:]
        
        # Add new data point
        self.traffic_data['time'].append(current_time)
        self.traffic_data['normal'].append(self.traffic_stats['normal'])
        self.traffic_data['anomaly'].append(self.traffic_stats['anomaly'])
        
        # Update plot data
        self.normal_line.setData(self.traffic_data['time'], self.traffic_data['normal'])
        self.anomaly_line.setData(self.traffic_data['time'], self.traffic_data['anomaly'])
        
        # Update attack distribution graph
        self.update_attack_distribution()
        
        # Update protocol distribution graph
        self.update_protocol_distribution()
        
        # Update port distribution graph
        self.update_port_distribution()
    
    def update_attack_distribution(self):
        """Update the attack distribution visualization using a bar chart instead of pie chart"""
        # Clear the graph
        self.attack_graph.clear()
        
        # Get attack types and counts
        attack_types = list(self.traffic_stats['attack_types'].keys())
        attack_counts = list(self.traffic_stats['attack_types'].values())
        
        if not attack_types:
            # If no attacks, show placeholder text
            text = pg.TextItem(text="No attacks detected yet", anchor=(0.5, 0.5))
            text.setPos(0, 0)
            self.attack_graph.addItem(text)
            return
        
        # Colors for bars
        colors = ['#ff0000', '#ff6600', '#ffcc00', '#cc0000', '#990000', 
                 '#ff3399', '#cc3399', '#9900cc', '#6600cc', '#0000cc']
        
        # Create bar chart instead of pie chart
        x = np.arange(len(attack_types))
        y = np.array(attack_counts)
        
        # Create a bar graph
        bargraph = pg.BarGraphItem(x=x, height=y, width=0.6, 
                                  brushes=[pg.mkBrush(colors[i % len(colors)]) for i in range(len(attack_types))])
        self.attack_graph.addItem(bargraph)
        
        # Add labels
        axis = self.attack_graph.getAxis('bottom')
        axis.setTicks([[(i, t) for i, t in enumerate(attack_types)]])
        
        # Set title
        self.attack_graph.setTitle("Attack Type Distribution")
        self.attack_graph.setLabel('left', 'Count')
        
        # Add value labels above bars
        for i, count in enumerate(attack_counts):
            text = pg.TextItem(text=str(count), anchor=(0.5, 0))
            text.setPos(i, count)
            self.attack_graph.addItem(text)
    
    def update_protocol_distribution(self):
        """Update the protocol distribution graph"""
        # This would be updated with real data from the network sniffer
        # For now, use placeholder data
        protocols = ['TCP', 'UDP', 'ICMP', 'Other']
        counts = [70, 25, 3, 2]
        
        # Clear the graph
        self.proto_graph.clear()
        
        # Create bar graph
        x = np.arange(len(protocols))
        y = np.array(counts)
        
        bargraph = pg.BarGraphItem(x=x, height=y, width=0.6, brush='b')
        self.proto_graph.addItem(bargraph)
        
        # Add labels
        axis = self.proto_graph.getAxis('bottom')
        axis.setTicks([[(i, p) for i, p in enumerate(protocols)]])
    
    def update_port_distribution(self):
        """Update the port distribution graph"""
        # This would be updated with real data from the network sniffer
        # For now, use placeholder data
        ports = ['80', '443', '53', '22', '3389']
        counts = [45, 30, 15, 5, 5]
        
        # Clear the graph
        self.port_graph.clear()
        
        # Create bar graph
        x = np.arange(len(ports))
        y = np.array(counts)
        
        bargraph = pg.BarGraphItem(x=x, height=y, width=0.6, brush='g')
        self.port_graph.addItem(bargraph)
        
        # Add labels
        axis = self.port_graph.getAxis('bottom')
        axis.setTicks([[(i, p) for i, p in enumerate(ports)]])
    
    def update_timer_intervals(self):
        """Update timer intervals based on settings"""
        update_freq = self.update_frequency.value() * 1000  # Convert to milliseconds
        self.graph_timer.setInterval(update_freq)
    
    def show_alert_notification(self, alert):
        """Show a desktop notification for an alert"""
        if not self.enable_alerts.isChecked():
            return
        
        # Create notification message
        message = (
            f"Attack Type: {alert['attack_type']}\n"
            f"Source: {alert['src_ip']}:{alert['src_port']}\n"
            f"Destination: {alert['dst_ip']}:{alert['dst_port']}\n"
            f"Confidence: {alert['confidence']*100:.1f}%"
        )
        
        # Show notification
        self.tray_icon.showMessage(
            "Network Anomaly Detected!",
            message,
            QSystemTrayIcon.Critical,
            5000
        )
        
        # Play sound if enabled
        if self.enable_sound.isChecked():
            # This would play a sound alert
            # QSound.play("alert.wav")
            pass
    
    def closeEvent(self, event):
        """Handle window close event"""
        # Stop monitoring if active
        if self.monitoring_active:
            self.stop_monitoring()
        
        # Accept the close event
        event.accept()

def main():
    """Main function to start the application"""
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
            QMessageBox.critical(None, "Error", "Failed to install required dependency: pyqtgraph")
            return 1
    
    # Create and show the main window
    window = NetworkMonitorGUI()
    window.show()
    
    # Start the application event loop
    return app.exec_()

if __name__ == "__main__":
    sys.exit(main())
