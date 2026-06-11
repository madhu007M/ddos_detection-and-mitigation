"""
Enhanced Dashboard - Add this alongside your existing dashboard
"""
from flask import Blueprint, render_template, jsonify
from models import db, TrafficLog, ThreatAlert
from sqlalchemy import func
from datetime import datetime, timedelta
import json

dashboard_bp = Blueprint('dashboard_enhanced', __name__)

@dashboard_bp.route('/api/realtime-stats')
def realtime_stats():
    """Get real-time statistics for dashboard"""
    # Last hour stats
    one_hour_ago = datetime.utcnow() - timedelta(hours=1)
    
    stats = {
        'total_requests': TrafficLog.query.filter(
            TrafficLog.timestamp >= one_hour_ago
        ).count(),
        
        'threats_detected': ThreatAlert.query.filter(
            ThreatAlert.created_at >= one_hour_ago
        ).count(),
        
        'blocked_ips': ThreatAlert.query.filter(
            ThreatAlert.created_at >= one_hour_ago,
            ThreatAlert.severity == 'CRITICAL'
        ).count(),
        
        'attack_types': db.session.query(
            ThreatAlert.attack_type,
            func.count(ThreatAlert.id)
        ).filter(
            ThreatAlert.created_at >= one_hour_ago
        ).group_by(ThreatAlert.attack_type).all()
    }
    
    return jsonify(stats)

@dashboard_bp.route('/api/traffic-chart')
def traffic_chart():
    """Get traffic data for charts"""
    # Last 24 hours, grouped by hour
    one_day_ago = datetime.utcnow() - timedelta(days=1)
    
    traffic_data = db.session.query(
        func.date_trunc('hour', TrafficLog.timestamp).label('hour'),
        func.count(TrafficLog.id).label('count')
    ).filter(
        TrafficLog.timestamp >= one_day_ago
    ).group_by('hour').order_by('hour').all()
    
    return jsonify([
        {'time': str(hour), 'count': count}
        for hour, count in traffic_data
    ])

@dashboard_bp.route('/api/threat-map')
def threat_map():
    """Get geographic threat data"""
    threats = ThreatAlert.query.filter(
        ThreatAlert.created_at >= datetime.utcnow() - timedelta(hours=24)
    ).all()
    
    threat_data = []
    for threat in threats:
        # Parse source_ip to get location (you'd use a GeoIP library here)
        threat_data.append({
            'ip': threat.source_ip,
            'type': threat.attack_type,
            'severity': threat.severity,
            'timestamp': threat.created_at.isoformat()
        })
    
    return jsonify(threat_data)