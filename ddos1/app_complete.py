"""
Complete DDoS Detection System - No complex dependencies
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

# ==================== DATABASE MODELS ====================

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
    flags = db.Column(db.String(50))
    is_attack = db.Column(db.Boolean, default=False, index=True)

class ThreatAlert(db.Model):
    __tablename__ = 'threat_alert'
    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    source_ip = db.Column(db.String(50), index=True)
    attack_type = db.Column(db.String(100))
    severity = db.Column(db.String(20), index=True)
    confidence_score = db.Column(db.Float)
    details = db.Column(db.Text)
    is_blocked = db.Column(db.Boolean, default=False)
    blocked_at = db.Column(db.DateTime)

class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200))
    email = db.Column(db.String(120))
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class SystemMetrics(db.Model):
    __tablename__ = 'system_metrics'
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    cpu_usage = db.Column(db.Float)
    memory_usage = db.Column(db.Float)
    network_usage = db.Column(db.Float)
    active_connections = db.Column(db.Integer)
    threat_level = db.Column(db.String(20))

# ==================== BASIC DETECTION LOGIC ====================

class SimpleDetector:
    """Simple rule-based DDoS detection"""
    
    def __init__(self):
        self.ip_request_count = {}
        self.time_window = 60  # seconds
        self.threshold = 50    # requests per minute
    
    def analyze_traffic(self, source_ip):
        """Analyze if traffic is suspicious"""
        current_time = datetime.utcnow()
        
        # Initialize IP tracking
        if source_ip not in self.ip_request_count:
            self.ip_request_count[source_ip] = []
        
        # Add current request
        self.ip_request_count[source_ip].append(current_time)
        
        # Remove old requests outside time window
        cutoff_time = current_time - timedelta(seconds=self.time_window)
        self.ip_request_count[source_ip] = [
            t for t in self.ip_request_count[source_ip] 
            if t > cutoff_time
        ]
        
        # Check if threshold exceeded
        request_count = len(self.ip_request_count[source_ip])
        
        if request_count > self.threshold:
            return {
                'is_attack': True,
                'attack_type': 'DDoS - High Volume Attack',
                'severity': 'CRITICAL' if request_count > 100 else 'HIGH',
                'confidence': min(request_count / self.threshold, 1.0),
                'details': f'Detected {request_count} requests in {self.time_window}s'
            }
        
        return {'is_attack': False}

# Initialize detector
detector = SimpleDetector()

# ==================== WEB ROUTES ====================

@app.route('/')
def index():
    """Home page"""
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        if user and user.password == password:
            session['user_id'] = user.id
            session['username'] = user.username
            logger.info(f'✓ User {username} logged in')
            return redirect(url_for('dashboard'))
        
        logger.warning(f'✗ Failed login attempt for {username}')
        return render_template('login.html', error='Invalid credentials')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    """Logout"""
    username = session.get('username', 'Unknown')
    session.clear()
    logger.info(f'✓ User {username} logged out')
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    """Main dashboard"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # Get statistics
    one_hour_ago = datetime.utcnow() - timedelta(hours=1)
    
    stats = {
        'total_traffic': TrafficLog.query.count(),
        'total_threats': ThreatAlert.query.count(),
        'critical_threats': ThreatAlert.query.filter_by(severity='CRITICAL').count(),
        'blocked_threats': ThreatAlert.query.filter_by(is_blocked=True).count(),
        'last_hour_traffic': TrafficLog.query.filter(
            TrafficLog.timestamp >= one_hour_ago
        ).count(),
        'last_hour_threats': ThreatAlert.query.filter(
            ThreatAlert.created_at >= one_hour_ago
        ).count()
    }
    
    # Get recent threats
    recent_threats = ThreatAlert.query.order_by(
        ThreatAlert.created_at.desc()
    ).limit(10).all()
    
    return render_template('dashboard.html', 
                         stats=stats, 
                         recent_threats=recent_threats,
                         username=session.get('username'))

@app.route('/enhanced-dashboard')
def enhanced_dashboard():
    """Enhanced dashboard with charts"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    return render_template('enhanced_dashboard.html',
                         username=session.get('username'))

# ==================== API ENDPOINTS ====================

@app.route('/api/stats')
def api_stats():
    """Get system statistics"""
    one_hour_ago = datetime.utcnow() - timedelta(hours=1)
    
    stats = {
        'total_traffic': TrafficLog.query.count(),
        'total_threats': ThreatAlert.query.count(),
        'critical_threats': ThreatAlert.query.filter_by(severity='CRITICAL').count(),
        'last_hour_traffic': TrafficLog.query.filter(
            TrafficLog.timestamp >= one_hour_ago
        ).count(),
        'status': 'operational',
        'timestamp': datetime.utcnow().isoformat()
    }
    
    return jsonify(stats)

@app.route('/api/enhanced/stats')
def api_enhanced_stats():
    """Enhanced statistics for dashboard"""
    one_hour_ago = datetime.utcnow() - timedelta(hours=1)
    
    # Attack types distribution
    from sqlalchemy import func
    attack_types = db.session.query(
        ThreatAlert.attack_type,
        func.count(ThreatAlert.id).label('count')
    ).group_by(ThreatAlert.attack_type).all()
    
    stats = {
        'current': {
            'total_requests': TrafficLog.query.count(),
            'last_hour': TrafficLog.query.filter(
                TrafficLog.timestamp >= one_hour_ago
            ).count()
        },
        'threats': {
            'total': ThreatAlert.query.count(),
            'critical': ThreatAlert.query.filter_by(severity='CRITICAL').count(),
            'high': ThreatAlert.query.filter_by(severity='HIGH').count(),
            'medium': ThreatAlert.query.filter_by(severity='MEDIUM').count(),
            'last_hour': ThreatAlert.query.filter(
                ThreatAlert.created_at >= one_hour_ago
            ).count()
        },
        'attack_types': {at: count for at, count in attack_types}
    }
    
    return jsonify(stats)

@app.route('/api/enhanced/chart-data')
def api_chart_data():
    """Get data for charts"""
    hours = int(request.args.get('hours', 24))
    start_time = datetime.utcnow() - timedelta(hours=hours)
    
    from sqlalchemy import func
    
    # Traffic over time
    traffic_data = db.session.query(
        func.strftime('%Y-%m-%d %H:00:00', TrafficLog.timestamp).label('hour'),
        func.count(TrafficLog.id).label('count')
    ).filter(
        TrafficLog.timestamp >= start_time
    ).group_by('hour').order_by('hour').all()
    
    # Threats over time
    threat_data = db.session.query(
        func.strftime('%Y-%m-%d %H:00:00', ThreatAlert.created_at).label('hour'),
        func.count(ThreatAlert.id).label('count')
    ).filter(
        ThreatAlert.created_at >= start_time
    ).group_by('hour').order_by('hour').all()
    
    return jsonify({
        'traffic': [{'time': h, 'count': c} for h, c in traffic_data],
        'threats': [{'time': h, 'count': c} for h, c in threat_data]
    })

@app.route('/api/recent-threats')
def api_recent_threats():
    """Get recent threats"""
    limit = request.args.get('limit', 10, type=int)
    
    threats = ThreatAlert.query.order_by(
        ThreatAlert.created_at.desc()
    ).limit(limit).all()
    
    return jsonify([{
        'id': t.id,
        'source_ip': t.source_ip,
        'attack_type': t.attack_type,
        'severity': t.severity,
        'confidence': t.confidence_score,
        'timestamp': t.created_at.isoformat(),
        'is_blocked': t.is_blocked,
        'details': t.details
    } for t in threats])

@app.route('/api/block-ip', methods=['POST'])
def api_block_ip():
    """Block an IP address"""
    data = request.get_json()
    ip = data.get('ip')
    
    if not ip:
        return jsonify({'error': 'IP address required'}), 400
    
    # Create or update threat alert
    alert = ThreatAlert.query.filter_by(source_ip=ip, is_blocked=False).first()
    
    if alert:
        alert.is_blocked = True
        alert.blocked_at = datetime.utcnow()
        db.session.commit()
        logger.warning(f'🚫 IP {ip} blocked')
        return jsonify({'success': True, 'message': f'IP {ip} blocked'})
    
    return jsonify({'error': 'Threat not found'}), 404

# ==================== TRAFFIC SIMULATOR ====================

def simulate_traffic():
    """Simulate network traffic for testing"""
    logger.info('🚗 Traffic simulator started')
    
    normal_mode = True
    attack_counter = 0
    
    while True:
        try:
            if normal_mode:
                # Normal traffic
                for _ in range(random.randint(3, 7)):
                    ip = f'192.168.1.{random.randint(1, 254)}'
                    
                    traffic = TrafficLog(
                        source_ip=ip,
                        destination_ip='10.0.0.1',
                        source_port=random.randint(1024, 65535),
                        destination_port=random.choice([80, 443, 22, 3306]),
                        protocol=random.choice(['TCP', 'UDP', 'ICMP']),
                        packet_size=random.randint(64, 1500),
                        flags='SYN',
                        is_attack=False
                    )
                    db.session.add(traffic)
                    
                    # Check for attacks
                    result = detector.analyze_traffic(ip)
                    if result['is_attack']:
                        alert = ThreatAlert(
                            source_ip=ip,
                            attack_type=result['attack_type'],
                            severity=result['severity'],
                            confidence_score=result['confidence'],
                            details=result['details'],
                            is_blocked=False
                        )
                        db.session.add(alert)
                        logger.warning(f'🚨 {result["severity"]} threat from {ip}')
                
                db.session.commit()
                logger.info(f'✓ Normal traffic: {_+1} requests')
                time.sleep(random.uniform(0.5, 2))
                
                # Randomly switch to attack mode
                if random.random() < 0.05:  # 5% chance
                    normal_mode = False
                    attack_counter = 0
                    logger.warning('💥 Switching to attack mode...')
            
            else:
                # Attack traffic
                attacker_ip = f'10.0.0.{random.randint(1, 254)}'
                attack_type = random.choice(['DDoS', 'Brute Force', 'Port Scan'])
                
                for _ in range(random.randint(50, 150)):
                    traffic = TrafficLog(
                        source_ip=attacker_ip,
                        destination_ip='10.0.0.1',
                        source_port=random.randint(1024, 65535),
                        destination_port=random.choice([80, 443, 22]),
                        protocol='TCP',
                        packet_size=random.randint(64, 1500),
                        flags='SYN',
                        is_attack=True
                    )
                    db.session.add(traffic)
                
                # Create alert
                alert = ThreatAlert(
                    source_ip=attacker_ip,
                    attack_type=f'{attack_type} Attack',
                    severity='CRITICAL',
                    confidence_score=0.95,
                    details=f'High volume {attack_type} detected',
                    is_blocked=True,
                    blocked_at=datetime.utcnow()
                )
                db.session.add(alert)
                db.session.commit()
                
                attack_counter += 1
                logger.warning(f'🚨 {attack_type} attack #{attack_counter} from {attacker_ip}')
                
                time.sleep(random.uniform(1, 3))
                
                # Switch back to normal after 3-5 attacks
                if attack_counter >= random.randint(3, 5):
                    normal_mode = True
                    logger.info('✅ Switching back to normal mode')
        
        except Exception as e:
            logger.error(f'Simulator error: {e}')
            db.session.rollback()
            time.sleep(1)

# ==================== INITIALIZATION ====================

def initialize_app():
    """Initialize the application"""
    with app.app_context():
        # Create database
        db.create_all()
        logger.info('✓ Database initialized')
        
        # Create admin user
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            admin = User(
                username='admin',
                password='admin123',
                email='admin@ddos-detection.local',
                is_admin=True
            )
            db.session.add(admin)
            db.session.commit()
            logger.info('✓ Admin user created (admin/admin123)')
        else:
            logger.info('✓ Admin user exists')
        
        # Start traffic simulator
        simulator_thread = Thread(target=simulate_traffic, daemon=True)
        simulator_thread.start()
        logger.info('✅ Traffic simulator started')

# ==================== MAIN ====================

if __name__ == '__main__':
    print("\n" + "="*80)
    print("🛡️  DDoS Detection System - Complete Version")
    print("="*80)
    print("\n📊 Access Points:")
    print(f"   • Main Page:        http://127.0.0.1:5000/")
    print(f"   • Login:            http://127.0.0.1:5000/login")
    print(f"   • Dashboard:        http://127.0.0.1:5000/dashboard")
    print(f"   • Enhanced Dashboard: http://127.0.0.1:5000/enhanced-dashboard")
    print("\n🔐 Login Credentials:")
    print("   Username: admin")
    print("   Password: admin123")
    print("\n📡 API Endpoints:")
    print("   • GET  /api/stats")
    print("   • GET  /api/recent-threats")
    print("   • POST /api/block-ip")
    print("\n" + "="*80 + "\n")
    
    initialize_app()
    app.run(host='127.0.0.1', port=5000, debug=False, threaded=True)