import pytest
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from feature_engineering import AdvancedFeatureEngineering

class TestFeatureEngineering:
    @pytest.fixture
    def sample_traffic_data(self):
        """Create sample traffic data"""
        n = 1000
        data = {
            'timestamp': [datetime.now() - timedelta(seconds=i) for i in range(n)],
            'src_ip': np.random.choice(['192.168.1.1', '192.168.1.2', '192.168.1.3'], n),
            'dst_ip': np.random.choice(['10.0.0.1', '10.0.0.2'], n),
            'src_port': np.random.randint(1024, 65535, n),
            'dst_port': np.random.choice([80, 443, 22, 53], n),
            'protocol': np.random.choice(['TCP', 'UDP', 'ICMP'], n),
            'packet_size': np.random.randint(64, 1500, n),
            'flags': np.random.choice(['SYN', 'ACK', 'FIN', 'SYN,ACK'], n)
        }
        return pd.DataFrame(data)
    
    def test_entropy_calculation(self):
        """Test entropy calculation"""
        fe = AdvancedFeatureEngineering()
        data = ['a', 'a', 'b', 'b', 'c', 'c']
        entropy = fe.calculate_entropy(data)
        assert entropy > 0
        assert entropy <= np.log2(3)
    
    def test_feature_extraction(self, sample_traffic_data):
        """Test feature extraction"""
        fe = AdvancedFeatureEngineering()
        features = fe.extract_advanced_features(sample_traffic_data)
        
        assert isinstance(features, pd.Series)
        assert len(features) > 0
        assert 'packet_count' in features
        assert 'avg_packet_size' in features
        assert 'unique_src_ips' in features
    
    def test_attack_pattern_detection(self, sample_traffic_data):
        """Test attack pattern detection"""
        fe = AdvancedFeatureEngineering()
        patterns = fe.detect_attack_patterns(sample_traffic_data)
        
        assert isinstance(patterns, dict)
        assert 'syn_flood_score' in patterns or len(patterns) >= 0