"""
Simplified version without ML dependencies
Uses your existing detection logic
"""
from flask import Flask, render_template, request, jsonify, redirect, url_for, session
from flask_cors import CORS
from models import db, TrafficLog, ThreatAlert, User
from datetime import datetime, timedelta
from sqlalchemy import func
import logging
import os

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Create Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-change-in-production'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///ddos_detection.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
db.init_app(app)
CORS(app)

# Enhanced Dashboard Routes
@app.route('/api/enhanced/stats')
def enhanced_stats():
    """Enhanced real-time statistics"""
    try:
        one_hour_ago = datetime.utcnow() - timedelta(hours=1)
        one_day_ago = datetime.utcnow() - timedelta(days=1)
        
        # Current stats
        stats = {
            'current': {
                'total_requests': TrafficLog.query.count(),
                'last_hour': TrafficLog.query.filter(
                    TrafficLog.timestamp >= one_hour_ago
                ).count(),
                'last_day': TrafficLog.query.filter(
                    TrafficLog.timestamp >= one_day_ago
                ).count(),
            },
            'threats': {
                'total': ThreatAlert.query.count(),
                'last_hour': ThreatAlert.query.filter(
                    ThreatAlert.created_at >= one_hour_ago
                ).count(),
                'critical': ThreatAlert.query.filter_by(severity='CRITICAL').count(),
                'high': ThreatAlert.query.filter_by(severity='HIGH').count(),
                'medium': ThreatAlert.query.filter_by(severity='MEDIUM').count(),
            },
            'attack_types': {}
        }
        
        # Attack types distribution
        attack_types = db.session.query(
            ThreatAlert.attack_type,
            func.count(ThreatAlert.id).label('count')
        ).group_by(ThreatAlert.attack_type).all()
        
        stats['attack_types'] = {
            attack_type: count for attack_type, count in attack_types
        }
        
        return jsonify(stats)
    except Exception as e:
        logger.error(f"Error getting enhanced stats: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/enhanced/chart-data')
def chart_data():
    """Get data for charts"""
    try:
        hours = int(request.args.get('hours', 24))
        start_time = datetime.utcnow() - timedelta(hours=hours)
        
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
            'traffic': [
                {'time': hour, 'count': count}
                for hour, count in traffic_data
            ],
            'threats': [
                {'time': hour, 'count': count}
                for hour, count in threat_data
            ]
        })
    except Exception as e:
        logger.error(f"Error getting chart data: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/enhanced/recent-threats')
def recent_threats():
    """Get recent threats with details"""
    try:
        limit = int(request.args.get('limit', 10))
        
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
            'details': t.details
        } for t in threats])
    except Exception as e:
        logger.error(f"Error getting recent threats: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/enhanced/top-attackers')
def top_attackers():
    """Get top attacking IPs"""
    try:
        limit = int(request.args.get('limit', 10))
        hours = int(request.args.get('hours', 24))
        start_time = datetime.utcnow() - timedelta(hours=hours)
        
        top_ips = db.session.query(
            ThreatAlert.source_ip,
            func.count(ThreatAlert.id).label('attack_count'),
            func.max(ThreatAlert.severity).label('max_severity')
        ).filter(
            ThreatAlert.created_at >= start_time
        ).group_by(
            ThreatAlert.source_ip
        ).order_by(
            func.count(ThreatAlert.id).desc()
        ).limit(limit).all()
        
        return jsonify([{
            'ip': ip,
            'attacks': count,
            'severity': severity
        } for ip, count, severity in top_ips])
    except Exception as e:
        logger.error(f"Error getting top attackers: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/enhanced-dashboard')
def enhanced_dashboard():
    """Enhanced dashboard page"""
    return render_template('enhanced_dashboard.html')

# Initialize database
with app.app_context():
    db.create_all()
    logger.info("✓ Database initialized")

if __name__ == '__main__':
    print("\n" + "="*60)
    print("🛡️  Enhanced DDoS Detection System")
    print("="*60)
    print("\n📊 Dashboards:")
    print(f"   Original: http://127.0.0.1:5000/dashboard")
    print(f"   Enhanced: http://127.0.0.1:5000/enhanced-dashboard")
    print("\n🔐 Login: http://127.0.0.1:5000/login")
    print("   Username: admin")
    print("   Password: admin123")
    print("\n" + "="*60 + "\n")
    
    app.run(host='127.0.0.1', port=5000, debug=False)