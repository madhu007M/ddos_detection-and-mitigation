"""
Clean DDoS Detection System - No Heavy Dependencies
Works with just Flask and SQLAlchemy
"""
import os
import logging
from datetime import datetime, timedelta
from threading import Thread
import time
import random
from flask import Flask, render_template, request, jsonify, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from collections import defaultdict, deque

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-change-in-production'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///ddos_detection.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
db = SQLAlchemy(app)
CORS(app)

# ============================================================================
# Database Models
# ============================================================================

class TrafficLog(db.Model):
    __tablename__ = 'traffic_log'
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    source_ip = db.Column(db.String(50), index=True)
    destination_ip = db.Column(db.String(50))
    source_port = db.Column(db.Integer)
    destination_port = db.Column(db.Integer)
    protocol = db.Column(db.String(20))
    packet_size = db.Column(db.Integer)
    is_attack = db.Column(db.Boolean, default=False)

class ThreatAlert(db.Model):
    __tablename__ = 'threat_alert'
    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    source_ip = db.Column(db.String(50), index=True)
    attack_type = db.Column(db.String(100))
    severity = db.Column(db.String(20))
    confidence_score = db.Column(db.Float)
    details = db.Column(db.Text)
    is_blocked = db.Column(db.Boolean, default=False)

class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200))
    email = db.Column(db.String(120))
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# ============================================================================
# Simple DDoS Detection Logic (No ML Required)
# ============================================================================

class SimpleDDoSDetector:
    """Simple rule-based DDoS detector"""
    
    def __init__(self):
        self.ip_requests = defaultdict(lambda: deque(maxlen=100))
        self.thresholds = {
            'requests_per_second': 50,
            'requests_per_minute': 500,
            'packet_size_anomaly': 2000
        }
    
    def analyze_traffic(self, source_ip, packet_size, timestamp):
        """Analyze traffic for DDoS patterns"""
        self.ip_requests[source_ip].append({
            'timestamp': timestamp,
            'packet_size': packet_size
        })
        
        recent_requests = list(self.ip_requests[source_ip])
        
        # Check request rate
        if len(recent_requests) >= 10:
            time_diff = (recent_requests[-1]['timestamp'] - recent_requests[-10]['timestamp']).total_seconds()
            if time_diff > 0:
                rate = 10 / time_diff
                
                if rate > self.thresholds['requests_per_second']:
                    return {
                        'is_attack': True,
                        'attack_type': 'DDoS - High Request Rate',
                        'severity': 'CRITICAL',
                        'confidence': 0.9,
                        'details': f'Request rate: {rate:.2f} req/s'
                    }
        
        # Check packet size anomaly
        avg_size = sum(r['packet_size'] for r in recent_requests) / len(recent_requests)
        if avg_size > self.thresholds['packet_size_anomaly']:
            return {
                'is_attack': True,
                'attack_type': 'DDoS - Large Packet Attack',
                'severity': 'HIGH',
                'confidence': 0.75,
                'details': f'Avg packet