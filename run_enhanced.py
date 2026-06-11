"""
Enhanced Dashboard - Runs independently on port 5001
"""
from flask import Flask, render_template, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from datetime import datetime, timedelta
from sqlalchemy import func
import logging

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///ddos_detection.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
CORS(app)

db = SQLAlchemy(app)

# Import models
class TrafficLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    source_ip = db.Column(db.String(50))
    destination_ip = db.Column(db.String(50))
    source_port = db.Column(db.Integer)
    destination_port = db.Column(db.Integer)
    protocol = db.Column(db.String(20))
    packet_size = db.Column(db.Integer)
    is_attack = db.Column(db.Boolean, default=False)

class ThreatAlert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    source_ip = db.Column(db.String(50))
    attack_type = db.Column(db.String(100))
    severity = db.Column(db.String(20))
    confidence_score = db.Column(db.Float)
    details = db.Column(db.Text)
    is_blocked = db.Column(db.Boolean, default=False)

@app.route('/')
def index():
    return render_template('enhanced_dashboard.html')

@app.route('/api/enhanced/stats')
def get_stats():
    try:
        one_hour_ago = datetime.utcnow() - timedelta(hours=1)
        
        stats = {
            'current': {
                'total_requests': TrafficLog.query.count(),
                'last_hour': TrafficLog.query.filter(
                    TrafficLog.timestamp >= one_hour_ago
                ).count(),
            },
            'threats': {
                'total': ThreatAlert.query.count(),
                'critical': ThreatAlert.query.filter_by(severity='CRITICAL').count(),
                'high': ThreatAlert.query.filter_by(severity='HIGH').count(),
            },
            'attack_types': {}
        }
        
        attack_types = db.session.query(
            ThreatAlert.attack_type,
            func.count(ThreatAlert.id)
        ).group_by(ThreatAlert.attack_type).all()
        
        stats['attack_types'] = {at: count for at, count in attack_types}
        
        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/enhanced/chart-data')
def get_chart_data():
    try:
        hours = 24
        start_time = datetime.utcnow() - timedelta(hours=hours)
        
        traffic_data = db.session.query(
            func.strftime('%Y-%m-%d %H:00:00', TrafficLog.timestamp).label('hour'),
            func.count(TrafficLog.id).label('count')
        ).filter(
            TrafficLog.timestamp >= start_time
        ).group_by('hour').order_by('hour').all()
        
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
    except Exception as e:
        return jsonify({'traffic': [], 'threats': []}), 500

@app.route('/api/enhanced/recent-threats')
def get_recent_threats():
    try:
        threats = ThreatAlert.query.order_by(
            ThreatAlert.created_at.desc()
        ).limit(10).all()
        
        return jsonify([{
            'id': t.id,
            'source_ip': t.source_ip,
            'attack_type': t.attack_type,
            'severity': t.severity,
            'confidence': t.confidence_score,
            'timestamp': t.created_at.isoformat()
        } for t in threats])
    except Exception as e:
        return jsonify([]), 500

if __name__ == '__main__':
    print("\n" + "="*70)
    print("🎨 Enhanced DDoS Detection Dashboard")
    print("="*70)
    print("\n✨ Enhanced Dashboard: http://127.0.0.1:5001")
    print("\n💡 Make sure main system is running on port 5000!")
    print("="*70 + "\n")
    
    app.run(host='127.0.0.1', port=5001, debug=False)