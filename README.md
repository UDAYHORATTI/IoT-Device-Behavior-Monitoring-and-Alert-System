# IoT-Device-Behavior-Monitoring-and-Alert-System
This project monitors the behavior of IoT devices on a network and detects unusual activity, such as data exfiltration, command injections, or unexpected traffic spikes, by analyzing real-time network patterns.
import time
from scapy.all import sniff, IP, TCP, UDP
from sklearn.ensemble import IsolationForest
import numpy as np
import smtplib
from email.mime.text import MIMEText

# Behavior baseline (e.g., normal packet sizes and frequency for devices)
BASELINE = {
    "192.168.1.2": {"avg_packet_size": 100, "max_frequency": 10},  # Device 1
    "192.168.1.3": {"avg_packet_size": 150, "max_frequency": 5},   # Device 2
}

# Anomaly detection model
anomaly_model = IsolationForest(contamination=0.05, random_state=42)

# Captured traffic data
traffic_data = []

# Email configuration for alerts
EMAIL_CONFIG = {
    "sender": "your_email@example.com",
    "password": "your_password",
    "smtp_server": "smtp.example.com",
    "port": 587
}
ALERT_RECIPIENT = "alert_recipient@example.com"

def send_alert(device_ip, issue):
    """
    Send an email alert for suspicious activity.
    """
    try:
        msg = MIMEText(f"Alert: Suspicious activity detected on device {device_ip}.\nIssue: {issue}")
        msg["Subject"] = "IoT Security Alert"
        msg["From"] = EMAIL_CONFIG["sender"]
        msg["To"] = ALERT_RECIPIENT

        with smtplib.SMTP(EMAIL_CONFIG["smtp_server"], EMAIL_CONFIG["port"]) as server:
            server.starttls()
            server.login(EMAIL_CONFIG["sender"], EMAIL_CONFIG["password"])
            server.send_message(msg)
        print(f"Alert sent for device {device_ip}.")
    except Exception as e:
        print(f"Failed to send alert: {e}")

def extract_features(packet):
    """
    Extract features from a network packet.
    """
    try:
        if IP in packet:
            src_ip = packet[IP].src
            length = len(packet)
            return {"src_ip": src_ip, "length": length, "timestamp": time.time()}
    except Exception as e:
        print(f"Error extracting features: {e}")
        return None

def detect_anomalies():
    """
    Detect anomalies based on traffic data and the baseline.
    """
    global traffic_data
    for device_ip, baseline in BASELINE.items():
        device_traffic = [d for d in traffic_data if d["src_ip"] == device_ip]

        # Check packet size anomalies
        avg_packet_size = np.mean([d["length"] for d in device_traffic])
        if avg_packet_size > baseline["avg_packet_size"] * 1.5:
            send_alert(device_ip, "Unusual packet sizes detected.")

        # Check frequency anomalies
        timestamps = [d["timestamp"] for d in device_traffic]
        if len(timestamps) > 1:
            frequency = len(timestamps) / (max(timestamps) - min(timestamps))
            if frequency > baseline["max_frequency"]:
                send_alert(device_ip, "High traffic frequency detected.")

def packet_handler(packet):
    """
    Handle each captured packet and process it.
    """
    global traffic_data
    features = extract_features(packet)
    if features:
        traffic_data.append(features)

    # Analyze traffic periodically
    if len(traffic_data) > 100:
        detect_anomalies()
        traffic_data = []  # Reset data for next interval

def start_monitoring(interface="eth0"):
    """
    Start monitoring the network for suspicious behavior.
    """
    print(f"Starting network monitoring on interface {interface}...")
    sniff(iface=interface, prn=packet_handler, store=False)

if __name__ == "__main__":
    try:
        start_monitoring()
    except KeyboardInterrupt:
        print("Monitoring stopped.")
