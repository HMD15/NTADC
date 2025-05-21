#!/usr/bin/env python3
"""
Model Integration Module for Network Traffic Anomaly Detection
Integrates trained models with real-time network sniffer
"""

import os
import pickle
import numpy as np
import pandas as pd
import json
from network_sniffer import start_sniffer

class AnomalyDetector:
    """Class for integrating trained models with real-time network traffic analysis"""
    
    def __init__(self, model_dir=None):
        """Initialize the anomaly detector with trained models"""
        if model_dir is None:
            model_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'models')
        
        self.model_dir = model_dir
        self.detection_callbacks = []
        self.sniffer_threads = None
        self.load_models()
    
    def load_models(self):
        """Load all required models and preprocessing components"""
        print("Loading models and preprocessing components...")
        
        # Load preprocessor
        with open(os.path.join(self.model_dir, 'preprocessor.pkl'), 'rb') as f:
            self.preprocessor = pickle.load(f)
        
        # Load feature selectors
        with open(os.path.join(self.model_dir, 'selector_binary.pkl'), 'rb') as f:
            self.selector_binary = pickle.load(f)
        
        with open(os.path.join(self.model_dir, 'selector_multi.pkl'), 'rb') as f:
            self.selector_multi = pickle.load(f)
        
        # Load binary classification model
        try:
            # Try to load best model first
            with open(os.path.join(self.model_dir, 'best_binary_model.pkl'), 'rb') as f:
                self.binary_model = pickle.load(f)
            print("Loaded best binary model")
        except FileNotFoundError:
            # Fall back to RandomForest model
            with open(os.path.join(self.model_dir, 'binary_randomforest.pkl'), 'rb') as f:
                self.binary_model = pickle.load(f)
            print("Loaded RandomForest binary model")
        
        # Load multi-class classification model
        try:
            # Try to load best model first
            with open(os.path.join(self.model_dir, 'best_multi_model.pkl'), 'rb') as f:
                self.multi_model = pickle.load(f)
            print("Loaded best multi-class model")
        except FileNotFoundError:
            # Fall back to RandomForest model
            with open(os.path.join(self.model_dir, 'multi_randomforest.pkl'), 'rb') as f:
                self.multi_model = pickle.load(f)
            print("Loaded RandomForest multi-class model")
        
        # Load label encoder
        with open(os.path.join(self.model_dir, 'label_encoder.pkl'), 'rb') as f:
            self.label_encoder = pickle.load(f)
        
        # Load batch metadata if available
        try:
            with open(os.path.join(os.path.dirname(self.model_dir), 'preprocessed', 'batch_metadata.json'), 'r') as f:
                self.metadata = json.load(f)
            print(f"Loaded metadata: {self.metadata}")
        except FileNotFoundError:
            self.metadata = None
            print("No metadata found")
        
        print("Models loaded successfully")
    
    def register_callback(self, callback):
        """Register a callback function to be called when an anomaly is detected"""
        self.detection_callbacks.append(callback)
        return len(self.detection_callbacks) - 1  # Return callback ID
    
    def unregister_callback(self, callback_id):
        """Unregister a callback function"""
        if 0 <= callback_id < len(self.detection_callbacks):
            self.detection_callbacks[callback_id] = None
            return True
        return False
    
    def detection_handler(self, result):
        """Handle detection results and call registered callbacks"""
        # Add timestamp if not present
        if 'timestamp' not in result:
            import time
            result['timestamp'] = time.time()
        
        # Get the current confidence threshold from GUI (if available)
        confidence_threshold = 0.7  # Default 70%
        
        # Check if we have access to the GUI's confidence threshold
        from PyQt5.QtWidgets import QApplication
        if QApplication.instance():
            for widget in QApplication.instance().topLevelWidgets():
                if hasattr(widget, 'confidence_threshold'):
                    # Convert from percentage (50-100) to decimal (0.5-1.0)
                    confidence_threshold = widget.confidence_threshold.value() / 100.0
                    break
        
        # Only process results that meet the confidence threshold
        if result['is_anomaly'] and result['confidence'] < confidence_threshold:
            # Downgrade to normal traffic if confidence is below threshold
            result['is_anomaly'] = False
            result['attack_type'] = 'normal'
            print(f"Alert suppressed due to low confidence: {result['confidence']:.2f} < {confidence_threshold:.2f}")
        
        # Call all registered callbacks
        for callback in self.detection_callbacks:
            if callback is not None:
                try:
                    callback(result)
                except Exception as e:
                    print(f"Error in callback: {str(e)}")
        
        return result
    
    def start_monitoring(self, interface=None):
        """Start monitoring network traffic for anomalies"""
        print(f"Starting network monitoring on interface: {interface or 'default'}")
        
        # Start the sniffer with our detection handler
        self.sniffer_threads = start_sniffer(
            interface=interface,
            detection_callback=self.detection_handler
        )
        
        return True
    
    def stop_monitoring(self):
        """Stop monitoring network traffic"""
        print("Stopping network monitoring")
        
        # Call the stop_sniffer function to properly terminate all threads
        from network_sniffer import stop_sniffer
        stop_result = stop_sniffer()
        
        self.sniffer_threads = None
        return stop_result
    
    def predict_single_connection(self, connection_data):
        """Make a prediction on a single connection (for testing)"""
        # Convert connection data to DataFrame
        if isinstance(connection_data, dict):
            df = pd.DataFrame([connection_data])
        else:
            df = connection_data
        
        # Ensure all required columns are present
        required_cols = self.metadata.get('numerical_features', []) + self.metadata.get('categorical_features', [])
        for col in required_cols:
            if col not in df.columns:
                df[col] = 0 if col in self.metadata.get('numerical_features', []) else '-'
        
        # Preprocess features
        X_preprocessed = self.preprocessor.transform(df[required_cols])
        
        # Apply feature selection for binary classification
        X_binary = self.selector_binary.transform(X_preprocessed)
        
        # Make binary prediction (normal vs anomaly)
        is_anomaly = self.binary_model.predict(X_binary)[0]
        
        # Initialize result
        result = {
            'is_anomaly': bool(is_anomaly),
            'attack_type': 'normal',
            'confidence': 1.0
        }
        
        # If anomaly, classify the type
        if is_anomaly == 1:
            # Apply feature selection for multi-class
            X_multi = self.selector_multi.transform(X_preprocessed)
            
            # Predict attack type
            attack_type_idx = self.multi_model.predict(X_multi)[0]
            attack_type = self.label_encoder.inverse_transform([attack_type_idx])[0]
            result['attack_type'] = attack_type
            
            # Get probability if available
            if hasattr(self.multi_model, 'predict_proba'):
                probs = self.multi_model.predict_proba(X_multi)[0]
                result['confidence'] = float(probs[attack_type_idx])
        
        return result

# Example usage
def test_integration():
    """Test the integration of models with the sniffer"""
    detector = AnomalyDetector()
    
    # Define a callback function
    def alert_callback(result):
        print(f"ALERT: {result['attack_type']} attack detected!")
        print(f"Source: {result['src_ip']}:{result['src_port']}")
        print(f"Destination: {result['dst_ip']}:{result['dst_port']}")
        print(f"Confidence: {result['confidence']:.2f}")
        print("-" * 50)
    
    # Register the callback
    detector.register_callback(alert_callback)
    
    # Start monitoring
    detector.start_monitoring()
    
    try:
        # Keep the main thread alive
        import time
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Stopping...")
        detector.stop_monitoring()

if __name__ == "__main__":
    test_integration()
