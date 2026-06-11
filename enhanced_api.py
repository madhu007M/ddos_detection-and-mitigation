"""
Enhanced API endpoints - Add to your existing system
This works with your current database models
"""
from flask import Blueprint, jsonify, request
from datetime import datetime, timedelta
from sqlalchemy import func
import logging

# Create blueprint
enhanced_bp = Blueprint('enhanced', __name__, url_prefix='/api/enhanced')
logger = logging.getLogger(__name__)

# Import your existing models (they're already working)
try:
    from models import db, TrafficLog, ThreatAlert
except ImportError:
    # If models.py doesn't exist, we'll create a simple version
    from flask_sqlalchemy import SQLAlchemy
    db = SQLAlchemy()

@enhanced_bp.route('/stats')
def get_stats():
    """Get enhanced statistics"""
    try:
        one_hour_ago = datetime.utcnow() - timedelta(hours=1)
        one_day_ago = datetime.utcnow() - timedelta(days=1)
        
        stats = {
            'current': {
                'total_requests': db.session.query(func.count(TrafficLog.id)).scalar() or 0,
                'last_hour': db.session.query(func.count(TrafficLog.id)).filter(
                    TrafficLog.timestamp >= one_hour_ago
                ).scalar() or 0,
                'last_day': db.session.query(func.count(TrafficLog.id)).filter(
                    TrafficLog.timestamp >= one_day_ago
                ).scalar() or 0,
            },
            'threats': {
                'total': db.session.query(func.count(ThreatAlert.id)).scalar() or 0,
                'last_hour': db.session.query(func.count(ThreatAlert.id)).filter(
                    ThreatAlert.created_at >= one_hour_ago
                ).scalar() or 0,
                'critical': db.session.query(func.count(ThreatAlert.id)).filter(
                    ThreatAlert.severity == 'CRITICAL'
                ).scalar() or 0,
                'high': db.session.query(func.count(ThreatAlert.id)).filter(
                    ThreatAlert.severity == 'HIGH'
                ).scalar() or 0,
                'medium': db.session.query(func.count(ThreatAlert.id)).filter(
                    ThreatAlert.severity == 'MEDIUM'
                ).scalar() or 0,
            },
            'attack_types': {}
        }
        
        # Get attack types
        attack_types = db.session.query(
            ThreatAlert.attack_type,
            func.count(ThreatAlert.id).label('count')
        ).group_by(ThreatAlert.attack_type).all()
        
        stats['attack_types'] = {
            attack_type: count for attack_type, count in attack_types
        }
        
        return jsonify(stats)
    except Exception as e:
        logger.error(f"Error in get_stats: {e}")
        return jsonify({'error': str(e)}), 500

@enhanced_bp.route('/chart-data')
def get_chart_data():
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
        logger.error(f"Error in get_chart_data: {e}")
        return jsonify({'error': str(e)}), 500

@enhanced_bp.route('/recent-threats')
def get_recent_threats():
    """Get recent threats"""
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
        logger.error(f"Error in get_recent_threats: {e}")
        return jsonify({'error': str(e)}), 500

@enhanced_bp.route('/top-attackers')
def get_top_attackers():
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
        logger.error(f"Error in get_top_attackpythoners: {e}")
        return jsonify({'error': str(e)}), 500