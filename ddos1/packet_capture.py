from scapy.all import sniff, IP, TCP, UDP, ICMP
import threading
import queue
import pandas as pd
from datetime import datetime
import logging
from typing import Callable, Dict
import asyncio

class PacketCapture:
    def __init__(self, interface=None, callback=None):
        self.interface = interface
        self.callback = callback
        self.packet_queue = queue.Queue(maxsize=10000)
        self.is_running = False
        self.capture_thread = None
        self.logger = logging.getLogger(__name__)
        self.packet_count = 0
        self.stats = {
            'total_packets': 0,
            'tcp_packets': 0,
            'udp_packets': 0,
            'icmp_packets': 0,
            'other_packets': 0
        }
    
    def packet_handler(self, packet):
        """Handle captured packets"""
        try:
            if IP in packet:
                packet_data = {
                    'timestamp': datetime.now(),
                    'src_ip': packet[IP].src,
                    'dst_ip': packet[IP].dst,
                    'protocol': packet[IP].proto,
                    'packet_size': len(packet),
                    'ttl': packet[IP].ttl
                }
                
                # TCP specific
                if TCP in packet:
                    packet_data['src_port'] = packet[TCP].sport
                    packet_data['dst_port'] = packet[TCP].dport
                    packet_data['flags'] = packet[TCP].flags
                    packet_data['protocol'] = 'TCP'
                    self.stats['tcp_packets'] += 1
                
                # UDP specific
                elif UDP in packet:
                    packet_data['src_port'] = packet[UDP].sport
                    packet_data['dst_port'] = packet[UDP].dport
                    packet_data['protocol'] = 'UDP'
                    self.stats['udp_packets'] += 1
                
                # ICMP specific
                elif ICMP in packet:
                    packet_data['icmp_type'] = packet[ICMP].type
                    packet_data['icmp_code'] = packet[ICMP].code
                    packet_data['protocol'] = 'ICMP'
                    self.stats['icmp_packets'] += 1
                else:
                    self.stats['other_packets'] += 1
                
                self.stats['total_packets'] += 1
                self.packet_count += 1
                
                # Add to queue
                if not self.packet_queue.full():
                    self.packet_queue.put(packet_data)
                
                # Callback for real-time processing
                if self.callback:
                    self.callback(packet_data)
                
        except Exception as e:
            self.logger.error(f"Error handling packet: {e}")
    
    def start_capture(self, filter_str=None, count=0):
        """Start packet capture"""
        self.is_running = True
        self.logger.info(f"Starting packet capture on interface: {self.interface}")
        
        def capture():
            try:
                sniff(
                    iface=self.interface,
                    prn=self.packet_handler,
                    filter=filter_str,
                    count=count,
                    store=False,
                    stop_filter=lambda x: not self.is_running
                )
            except Exception as e:
                self.logger.error(f"Capture error: {e}")
                self.is_running = False
        
        self.capture_thread = threading.Thread(target=capture, daemon=True)
        self.capture_thread.start()
    
    def stop_capture(self):
        """Stop packet capture"""
        self.is_running = False
        if self.capture_thread:
            self.capture_thread.join(timeout=5)
        self.logger.info("Packet capture stopped")
    
    def get_packets(self, max_packets=100):
        """Get captured packets from queue"""
        packets = []
        while not self.packet_queue.empty() and len(packets) < max_packets:
            try:
                packets.append(self.packet_queue.get_nowait())
            except queue.Empty:
                break
        return packets
    
    def get_stats(self):
        """Get capture statistics"""
        return self.stats.copy()
    
    def clear_queue(self):
        """Clear packet queue"""
        while not self.packet_queue.empty():
            try:
                self.packet_queue.get_nowait()
            except queue.Empty:
                break

class TrafficAnalyzer:
    """Real-time traffic analysis"""
    def __init__(self, window_size=60):
        self.window_size = window_size  # seconds
        self.traffic_buffer = []
        self.logger = logging.getLogger(__name__)
    
    def analyze_packet(self, packet_data: Dict) -> Dict:
        """Analyze individual packet for anomalies"""
        analysis = {
            'is_suspicious': False,
            'reasons': []
        }
        
        # Check for suspicious packet size
        if packet_data.get('packet_size', 0) > 9000:
            analysis['is_suspicious'] = True
            analysis['reasons'].append('Abnormally large packet')
        
        # Check for suspicious TTL
        ttl = packet_data.get('ttl', 64)
        if ttl < 10 or ttl > 255:
            analysis['is_suspicious'] = True
            analysis['reasons'].append('Suspicious TTL value')
        
        # Check for SYN flood indicators
        if packet_data.get('protocol') == 'TCP':
            flags = packet_data.get('flags', '')
            if 'S' in str(flags) and 'A' not in str(flags):
                analysis['is_suspicious'] = True
                analysis['reasons'].append('Possible SYN flood')
        
        # Check for UDP flood to DNS
        if packet_data.get('protocol') == 'UDP' and packet_data.get('dst_port') == 53:
            if packet_data.get('packet_size', 0) > 512:
                analysis['is_suspicious'] = True
                analysis['reasons'].append('Possible DNS amplification')
        
        return analysis
    
    def add_packet(self, packet_data: Dict):
        """Add packet to buffer for analysis"""
        current_time = datetime.now()
        packet_data['added_at'] = current_time
        self.traffic_buffer.append(packet_data)
        
        # Remove old packets
        cutoff_time = current_time.timestamp() - self.window_size
        self.traffic_buffer = [
            p for p in self.traffic_buffer 
            if p['added_at'].timestamp() > cutoff_time
        ]
    
    def get_current_metrics(self) -> Dict:
        """Get current traffic metrics"""
        if not self.traffic_buffer:
            return {}
        
        df = pd.DataFrame(self.traffic_buffer)
        
        metrics = {
            'packet_count': len(df),
            'packets_per_second': len(df) / self.window_size,
            'unique_src_ips': df['src_ip'].nunique(),
            'unique_dst_ips': df['dst_ip'].nunique(),
            'avg_packet_size': df['packet_size'].mean(),
            'total_bytes': df['packet_size'].sum(),
            'bytes_per_second': df['packet_size'].sum() / self.window_size
        }
        
        # Protocol distribution
        if 'protocol' in df.columns:
            protocol_dist = df['protocol'].value_counts().to_dict()
            metrics['protocol_distribution'] = protocol_dist
        
        # Top source IPs
        top_src_ips = df['src_ip'].value_counts().head(10).to_dict()
        metrics['top_src_ips'] = top_src_ips
        
        # Top destination ports
        if 'dst_port' in df.columns:
            top_dst_ports = df['dst_port'].value_counts().head(10).to_dict()
            metrics['top_dst_ports'] = top_dst_ports
        
        return metrics
    
    def detect_anomalies(self) -> Dict:
        """Detect traffic anomalies"""
        metrics = self.get_current_metrics()
        anomalies = {
            'detected': False,
            'anomaly_types': []
        }
        
        # High packet rate
        if metrics.get('packets_per_second', 0) > 10000:
            anomalies['detected'] = True
            anomalies['anomaly_types'].append('High packet rate')
        
        # Low source IP diversity (possible DDoS)
        packet_count = metrics.get('packet_count', 0)
        unique_src = metrics.get('unique_src_ips', 0)
        if packet_count > 1000 and unique_src < 10:
            anomalies['detected'] = True
            anomalies['anomaly_types'].append('Low source IP diversity')
        
        # High concentration on single destination
        unique_dst = metrics.get('unique_dst_ips', 0)
        if packet_count > 1000 and unique_dst < 3:
            anomalies['detected'] = True
            anomalies['anomaly_types'].append('Targeted attack pattern')
        
        # Protocol anomalies
        protocol_dist = metrics.get('protocol_distribution', {})
        total_packets = sum(protocol_dist.values())
        
        for protocol, count in protocol_dist.items():
            ratio = count / total_packets
            if protocol == 'UDP' and ratio > 0.8:
                anomalies['detected'] = True
                anomalies['anomaly_types'].append('UDP flood')
            elif protocol == 'ICMP' and ratio > 0.5:
                anomalies['detected'] = True
                anomalies['anomaly_types'].append('ICMP flood')
        
        return anomalies

class RealTimeMonitor:
    """Orchestrate real-time monitoring"""
    def __init__(self, detector_model, database_manager, alert_system):
        self.packet_capture = PacketCapture(callback=self.process_packet)
        self.traffic_analyzer = TrafficAnalyzer()
        self.detector_model = detector_model
        self.db = database_manager
        self.alerts = alert_system
        self.logger = logging.getLogger(__name__)
        self.monitoring = False
        self.batch_size = 100
        self.packet_buffer = []
    
    def process_packet(self, packet_data: Dict):
        """Process each captured packet"""
        # Add to analyzer
        self.traffic_analyzer.add_packet(packet_data)
        
        # Quick analysis
        analysis = self.traffic_analyzer.analyze_packet(packet_data)
        if analysis['is_suspicious']:
            self.logger.warning(f"Suspicious packet detected: {analysis['reasons']}")
        
        # Buffer for batch processing
        self.packet_buffer.append(packet_data)
        
        if len(self.packet_buffer) >= self.batch_size:
            self.process_batch()
    
    def process_batch(self):
        """Process batch of packets with ML model"""
        if not self.packet_buffer:
            return
        
        try:
            df = pd.DataFrame(self.packet_buffer)
            
            # Feature extraction
            from feature_engineering import AdvancedFeatureEngineering
            fe = AdvancedFeatureEngineering()
            features = fe.extract_advanced_features(df)
            
            # Predict
            prediction = self.detector_model.predict([features.values])
            confidence = self.detector_model.predict_proba([features.values])
            
            if prediction[0] == 1:  # Attack detected
                attack_data = {
                    'timestamp': datetime.now(),
                    'attack_type': 'DDoS',
                    'severity': 'high' if confidence[0][1] > 0.9 else 'medium',
                    'confidence': float(confidence[0][1]),
                    'source_ips': df['src_ip'].unique().tolist()[:20],
                    'target_ip': df['dst_ip'].mode()[0] if len(df) > 0 else 'Unknown',
                    'target_ports': df.get('dst_port', pd.Series()).unique().tolist()[:10],
                    'packet_count': len(df),
                    'data_volume': df['packet_size'].sum(),
                    'duration': 60,
                    'peak_rate': len(df),
                    'recommendations': [
                        'Block suspicious source IPs',
                        'Enable rate limiting',
                        'Alert security team'
                    ]
                }
                
                # Log to database
                event_id = self.db.log_attack_event(attack_data)
                
                # Send alerts
                alert_msg = f"DDoS attack detected! Type: {attack_data['attack_type']}, Severity: {attack_data['severity']}"
                self.alerts.send_multi_channel_alert(
                    subject="DDoS Attack Detected",
                    message=alert_msg,
                    severity=attack_data['severity']
                )
                
                # Auto-block IPs
                for ip in attack_data['source_ips'][:10]:
                    self.db.block_ip(ip, "Auto-blocked during DDoS attack", duration=60)
            
            # Log traffic
            self.db.bulk_log_traffic([{**p, 'is_attack': bool(prediction[0])} 
                                      for p in self.packet_buffer])
            
            # Clear buffer
            self.packet_buffer = []
            
        except Exception as e:
            self.logger.error(f"Batch processing error: {e}")
    
    def start_monitoring(self, interface=None):
        """Start real-time monitoring"""
        self.monitoring = True
        self.packet_capture.interface = interface
        self.packet_capture.start_capture()
        self.logger.info("Real-time monitoring started")
    
    def stop_monitoring(self):
        """Stop monitoring"""
        self.monitoring = False
        self.packet_capture.stop_capture()
        self.process_batch()  # Process remaining packets
        self.logger.info("Real-time monitoring stopped")
    
    def get_status(self) -> Dict:
        """Get monitoring status"""
        return {
            'is_monitoring': self.monitoring,
            'capture_stats': self.packet_capture.get_stats(),
            'traffic_metrics': self.traffic_analyzer.get_current_metrics(),
            'anomalies': self.traffic_analyzer.detect_anomalies(),
            'buffer_size': len(self.packet_buffer)
        }