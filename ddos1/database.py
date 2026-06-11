from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, Boolean, Text, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from datetime import datetime
import redis
import json
from typing import List, Dict, Optional
import logging

Base = declarative_base()

# Database Models
class TrafficLog(Base):
    __tablename__ = 'traffic_logs'
    
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    src_ip = Column(String(45), index=True)
    dst_ip = Column(String(45), index=True)
    src_port = Column(Integer)
    dst_port = Column(Integer)
    protocol = Column(String(10))
    packet_size = Column(Integer)
    flags = Column(String(50))
    is_attack = Column(Boolean, default=False)
    confidence = Column(Float)
    attack_type = Column(String(50))

class AttackEvent(Base):
    __tablename__ = 'attack_events'
    
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    attack_type = Column(String(50), index=True)
    severity = Column(String(20), index=True)
    confidence = Column(Float)
    source_ips = Column(JSON)
    target_ip = Column(String(45))
    target_ports = Column(JSON)
    packet_count = Column(Integer)
    data_volume = Column(Integer)  # bytes
    duration = Column(Float)  # seconds
    peak_rate = Column(Integer)  # packets/sec
    status = Column(String(20), default='active')  # active, mitigated, resolved
    recommendations = Column(JSON)
    notes = Column(Text)

class BlockedIP(Base):
    __tablename__ = 'blocked_ips'
    
    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String(45), unique=True, index=True)
    reason = Column(String(200))
    blocked_at = Column(DateTime, default=datetime.utcnow)
    unblock_at = Column(DateTime, nullable=True)
    is_active = Column(Boolean, default=True)
    attack_count = Column(Integer, default=1)

class SystemMetrics(Base):
    __tablename__ = 'system_metrics'
    
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    total_requests = Column(Integer)
    blocked_requests = Column(Integer)
    detected_attacks = Column(Integer)
    model_accuracy = Column(Float)
    avg_response_time = Column(Float)  # milliseconds
    cpu_usage = Column(Float)
    memory_usage = Column(Float)

class ModelPerformance(Base):
    __tablename__ = 'model_performance'
    
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    model_name = Column(String(50))
    accuracy = Column(Float)
    precision = Column(Float)
    recall = Column(Float)
    f1_score = Column(Float)
    false_positive_rate = Column(Float)
    false_negative_rate = Column(Float)
    training_samples = Column(Integer)

class DatabaseManager:
    def __init__(self, database_url: str = "sqlite:///ddos_detection.db"):
        self.engine = create_engine(database_url, echo=False)
        Base.metadata.create_all(self.engine)
        self.SessionLocal = sessionmaker(bind=self.engine)
        self.logger = logging.getLogger(__name__)
    
    def get_session(self) -> Session:
        """Get database session"""
        return self.SessionLocal()
    
    # Traffic Log Operations
    def log_traffic(self, traffic_data: Dict):
        """Log network traffic"""
        session = self.get_session()
        try:
            log = TrafficLog(**traffic_data)
            session.add(log)
            session.commit()
        except Exception as e:
            self.logger.error(f"Error logging traffic: {e}")
            session.rollback()
        finally:
            session.close()
    
    def bulk_log_traffic(self, traffic_data_list: List[Dict]):
        """Bulk insert traffic logs"""
        session = self.get_session()
        try:
            logs = [TrafficLog(**data) for data in traffic_data_list]
            session.bulk_save_objects(logs)
            session.commit()
        except Exception as e:
            self.logger.error(f"Error bulk logging traffic: {e}")
            session.rollback()
        finally:
            session.close()
    
    # Attack Event Operations
    def log_attack_event(self, attack_data: Dict) -> int:
        """Log attack event and return event ID"""
        session = self.get_session()
        try:
            event = AttackEvent(**attack_data)
            session.add(event)
            session.commit()
            return event.id
        except Exception as e:
            self.logger.error(f"Error logging attack event: {e}")
            session.rollback()
            return None
        finally:
            session.close()
    
    def get_attack_events(self, limit: int = 100, severity: str = None) -> List[AttackEvent]:
        """Get recent attack events"""
        session = self.get_session()
        try:
            query = session.query(AttackEvent).order_by(AttackEvent.timestamp.desc())
            if severity:
                query = query.filter(AttackEvent.severity == severity)
            return query.limit(limit).all()
        finally:
            session.close()
    
    def update_attack_status(self, event_id: int, status: str, notes: str = None):
        """Update attack event status"""
        session = self.get_session()
        try:
            event = session.query(AttackEvent).filter(AttackEvent.id == event_id).first()
            if event:
                event.status = status
                if notes:
                    event.notes = notes
                session.commit()
        except Exception as e:
            self.logger.error(f"Error updating attack status: {e}")
            session.rollback()
        finally:
            session.close()
    
    # Blocked IP Operations
    def block_ip(self, ip_address: str, reason: str, duration: Optional[int] = None):
        """Block an IP address"""
        session = self.get_session()
        try:
            # Check if IP already blocked
            existing = session.query(BlockedIP).filter(
                BlockedIP.ip_address == ip_address,
                BlockedIP.is_active == True
            ).first()
            
            if existing:
                existing.attack_count += 1
                session.commit()
                return existing.id
            
            unblock_at = None
            if duration:
                from datetime import timedelta
                unblock_at = datetime.utcnow() + timedelta(minutes=duration)
            
            blocked_ip = BlockedIP(
                ip_address=ip_address,
                reason=reason,
                unblock_at=unblock_at
            )
            session.add(blocked_ip)
            session.commit()
            return blocked_ip.id
        except Exception as e:
            self.logger.error(f"Error blocking IP: {e}")
            session.rollback()
            return None
        finally:
            session.close()
    
    def unblock_ip(self, ip_address: str):
        """Unblock an IP address"""
        session = self.get_session()
        try:
            blocked_ip = session.query(BlockedIP).filter(
                BlockedIP.ip_address == ip_address,
                BlockedIP.is_active == True
            ).first()
            
            if blocked_ip:
                blocked_ip.is_active = False
                session.commit()
                return True
            return False
        except Exception as e:
            self.logger.error(f"Error unblocking IP: {e}")
            session.rollback()
            return False
        finally:
            session.close()
    
    def get_blocked_ips(self, active_only: bool = True) -> List[BlockedIP]:
        """Get list of blocked IPs"""
        session = self.get_session()
        try:
            query = session.query(BlockedIP)
            if active_only:
                query = query.filter(BlockedIP.is_active == True)
            return query.order_by(BlockedIP.blocked_at.desc()).all()
        finally:
            session.close()
    
    def is_ip_blocked(self, ip_address: str) -> bool:
        """Check if IP is blocked"""
        session = self.get_session()
        try:
            blocked = session.query(BlockedIP).filter(
                BlockedIP.ip_address == ip_address,
                BlockedIP.is_active == True
            ).first()
            return blocked is not None
        finally:
            session.close()
    
    # System Metrics Operations
    def log_metrics(self, metrics: Dict):
        """Log system metrics"""
        session = self.get_session()
        try:
            metric = SystemMetrics(**metrics)
            session.add(metric)
            session.commit()
        except Exception as e:
            self.logger.error(f"Error logging metrics: {e}")
            session.rollback()
        finally:
            session.close()
    
    def get_metrics(self, hours: int = 24) -> List[SystemMetrics]:
        """Get system metrics for specified hours"""
        session = self.get_session()
        try:
            from datetime import timedelta
            since = datetime.utcnow() - timedelta(hours=hours)
            return session.query(SystemMetrics).filter(
                SystemMetrics.timestamp >= since
            ).order_by(SystemMetrics.timestamp.asc()).all()
        finally:
            session.close()
    
    # Model Performance Operations
    def log_model_performance(self, performance_data: Dict):
        """Log model performance metrics"""
        session = self.get_session()
        try:
            performance = ModelPerformance(**performance_data)
            session.add(performance)
            session.commit()
        except Exception as e:
            self.logger.error(f"Error logging model performance: {e}")
            session.rollback()
        finally:
            session.close()
    
    # Analytics Operations
    def get_attack_statistics(self, days: int = 7) -> Dict:
        """Get attack statistics for specified days"""
        session = self.get_session()
        try:
            from datetime import timedelta
            from sqlalchemy import func
            
            since = datetime.utcnow() - timedelta(days=days)
            
            # Total attacks
            total_attacks = session.query(func.count(AttackEvent.id)).filter(
                AttackEvent.timestamp >= since
            ).scalar()
            
            # Attacks by type
            attacks_by_type = session.query(
                AttackEvent.attack_type,
                func.count(AttackEvent.id)
            ).filter(
                AttackEvent.timestamp >= since
            ).group_by(AttackEvent.attack_type).all()
            
            # Attacks by severity
            attacks_by_severity = session.query(
                AttackEvent.severity,
                func.count(AttackEvent.id)
            ).filter(
                AttackEvent.timestamp >= since
            ).group_by(AttackEvent.severity).all()
            
            return {
                'total_attacks': total_attacks,
                'attacks_by_type': dict(attacks_by_type),
                'attacks_by_severity': dict(attacks_by_severity),
                'period_days': days
            }
        finally:
            session.close()

class RedisCache:
    """Redis caching for high-performance operations"""
    def __init__(self, redis_url: str = "redis://localhost:6379"):
        try:
            self.redis_client = redis.from_url(redis_url, decode_responses=True)
            self.logger = logging.getLogger(__name__)
        except Exception as e:
            self.logger.error(f"Failed to connect to Redis: {e}")
            self.redis_client = None
    
    def cache_blocked_ips(self, ips: List[str], ttl: int = 3600):
        """Cache blocked IPs in Redis"""
        if not self.redis_client:
            return
        
        try:
            pipe = self.redis_client.pipeline()
            for ip in ips:
                pipe.setex(f"blocked_ip:{ip}", ttl, "1")
            pipe.execute()
        except Exception as e:
            self.logger.error(f"Redis cache error: {e}")
    
    def is_ip_blocked_cache(self, ip: str) -> bool:
        """Check if IP is blocked (from cache)"""
        if not self.redis_client:
            return False
        
        try:
            return self.redis_client.exists(f"blocked_ip:{ip}") > 0
        except Exception as e:
            self.logger.error(f"Redis check error: {e}")
            return False
    
    def cache_traffic_stats(self, stats: Dict, ttl: int = 60):
        """Cache traffic statistics"""
        if not self.redis_client:
            return
        
        try:
            self.redis_client.setex(
                "traffic_stats",
                ttl,
                json.dumps(stats)
            )
        except Exception as e:
            self.logger.error(f"Redis cache error: {e}")
    
    def get_traffic_stats(self) -> Optional[Dict]:
        """Get cached traffic statistics"""
        if not self.redis_client:
            return None
        
        try:
            data = self.redis_client.get("traffic_stats")
            return json.loads(data) if data else None
        except Exception as e:
            self.logger.error(f"Redis get error: {e}")
            return None