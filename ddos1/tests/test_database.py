import pytest
from database import DatabaseManager, TrafficLog, AttackEvent, BlockedIP
from datetime import datetime

class TestDatabase:
    @pytest.fixture
    def db_manager(self):
        """Create test database manager"""
        return DatabaseManager("sqlite:///:memory:")
    
    def test_log_traffic(self, db_manager):
        """Test traffic logging"""
        traffic_data = {
            'timestamp': datetime.now(),
            'src_ip': '192.168.1.1',
            'dst_ip': '10.0.0.1',
            'src_port': 12345,
            'dst_port': 80,
            'protocol': 'TCP',
            'packet_size': 1500,
            'is_attack': False
        }
        
        db_manager.log_traffic(traffic_data)
        # Test passed if no exception
    
    def test_log_attack_event(self, db_manager):
        """Test attack event logging"""
        attack_data = {
            'timestamp': datetime.now(),
            'attack_type': 'SYN Flood',
            'severity': 'high',
            'confidence': 0.95,
            'source_ips': ['192.168.1.1'],
            'target_ip': '10.0.0.1',
            'target_ports': [80],
            'packet_count': 10000,
            'data_volume': 15000000,
            'duration': 60.0,
            'peak_rate': 1000
        }
        
        event_id = db_manager.log_attack_event(attack_data)
        assert event_id is not None
    
    def test_block_ip(self, db_manager):
        """Test IP blocking"""
        ip_id = db_manager.block_ip('192.168.1.100', 'Test block')
        assert ip_id is not None
        
        is_blocked = db_manager.is_ip_blocked('192.168.1.100')
        assert is_blocked is True
    
    def test_unblock_ip(self, db_manager):
        """Test IP unblocking"""
        db_manager.block_ip('192.168.1.100', 'Test block')
        result = db_manager.unblock_ip('192.168.1.100')
        assert result is True
        
        is_blocked = db_manager.is_ip_blocked('192.168.1.100')
        assert is_blocked is False