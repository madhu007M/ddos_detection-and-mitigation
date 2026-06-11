import numpy as np
import pandas as pd
from scipy import stats
from sklearn.preprocessing import StandardScaler, MinMaxScaler

class AdvancedFeatureEngineering:
    def __init__(self):
        self.feature_names = []
    
    def calculate_entropy(self, data):
        """Calculate Shannon entropy"""
        if len(data) == 0:
            return 0
        
        value_counts = pd.Series(data).value_counts()
        probabilities = value_counts / len(data)
        entropy = -np.sum(probabilities * np.log2(probabilities + 1e-10))
        return entropy
    
    def extract_advanced_features(self, df):
        """Extract comprehensive network traffic features"""
        features = {}
        
        # Basic statistical features
        features['packet_count'] = len(df)
        features['total_bytes'] = df['packet_size'].sum() if 'packet_size' in df.columns else 0
        features['avg_packet_size'] = df['packet_size'].mean() if 'packet_size' in df.columns else 0
        features['std_packet_size'] = df['packet_size'].std() if 'packet_size' in df.columns else 0
        features['min_packet_size'] = df['packet_size'].min() if 'packet_size' in df.columns else 0
        features['max_packet_size'] = df['packet_size'].max() if 'packet_size' in df.columns else 0
        
        # Time-based features
        if 'timestamp' in df.columns:
            df['timestamp'] = pd.to_datetime(df['timestamp'])
            time_diffs = df['timestamp'].diff().dt.total_seconds()
            
            features['avg_inter_arrival_time'] = time_diffs.mean()
            features['std_inter_arrival_time'] = time_diffs.std()
            features['min_inter_arrival_time'] = time_diffs.min()
            features['max_inter_arrival_time'] = time_diffs.max()
            
            # Traffic rate features
            duration = (df['timestamp'].max() - df['timestamp'].min()).total_seconds()
            features['packets_per_second'] = len(df) / max(duration, 1)
            features['bytes_per_second'] = features['total_bytes'] / max(duration, 1)
            
            # Time-based patterns
            features['hour'] = df['timestamp'].dt.hour.mode()[0] if len(df) > 0 else 0
            features['day_of_week'] = df['timestamp'].dt.dayofweek.mode()[0] if len(df) > 0 else 0
        
        # Protocol distribution
        if 'protocol' in df.columns:
            protocol_counts = df['protocol'].value_counts()
            features['num_protocols'] = len(protocol_counts)
            features['protocol_entropy'] = self.calculate_entropy(df['protocol'])
            
            # Top protocol percentages
            for i, (protocol, count) in enumerate(protocol_counts.head(5).items()):
                features[f'protocol_{protocol}_ratio'] = count / len(df)
        
        # IP-based features
        if 'src_ip' in df.columns:
            features['unique_src_ips'] = df['src_ip'].nunique()
            features['src_ip_entropy'] = self.calculate_entropy(df['src_ip'])
            
            # Check for IP concentration (sign of DDoS)
            src_ip_counts = df['src_ip'].value_counts()
            features['max_src_ip_concentration'] = src_ip_counts.max() / len(df)
            features['src_ip_gini'] = self._calculate_gini(src_ip_counts.values)
        
        if 'dst_ip' in df.columns:
            features['unique_dst_ips'] = df['dst_ip'].nunique()
            features['dst_ip_entropy'] = self.calculate_entropy(df['dst_ip'])
            
            dst_ip_counts = df['dst_ip'].value_counts()
            features['max_dst_ip_concentration'] = dst_ip_counts.max() / len(df)
        
        # Port-based features
        if 'src_port' in df.columns:
            features['unique_src_ports'] = df['src_port'].nunique()
            features['src_port_entropy'] = self.calculate_entropy(df['src_port'])
        
        if 'dst_port' in df.columns:
            features['unique_dst_ports'] = df['dst_port'].nunique()
            features['dst_port_entropy'] = self.calculate_entropy(df['dst_port'])
            
            # Common service ports
            common_ports = [80, 443, 22, 21, 25, 53]
            for port in common_ports:
                features[f'dst_port_{port}_ratio'] = (df['dst_port'] == port).sum() / len(df)
        
        # Connection patterns
        if 'flags' in df.columns:
            features['syn_ratio'] = (df['flags'].str.contains('SYN', na=False)).sum() / len(df)
            features['fin_ratio'] = (df['flags'].str.contains('FIN', na=False)).sum() / len(df)
            features['rst_ratio'] = (df['flags'].str.contains('RST', na=False)).sum() / len(df)
            features['ack_ratio'] = (df['flags'].str.contains('ACK', na=False)).sum() / len(df)
        
        # Advanced statistical features
        if 'packet_size' in df.columns:
            features['packet_size_skewness'] = stats.skew(df['packet_size'])
            features['packet_size_kurtosis'] = stats.kurtosis(df['packet_size'])
            features['packet_size_cv'] = df['packet_size'].std() / (df['packet_size'].mean() + 1e-10)
            
            # Percentiles
            features['packet_size_25th'] = df['packet_size'].quantile(0.25)
            features['packet_size_75th'] = df['packet_size'].quantile(0.75)
            features['packet_size_iqr'] = features['packet_size_75th'] - features['packet_size_25th']
        
        # Flow-based features
        if all(col in df.columns for col in ['src_ip', 'dst_ip', 'src_port', 'dst_port']):
            df['flow'] = df['src_ip'] + ':' + df['src_port'].astype(str) + '->' + \
                         df['dst_ip'] + ':' + df['dst_port'].astype(str)
            features['unique_flows'] = df['flow'].nunique()
            features['flow_entropy'] = self.calculate_entropy(df['flow'])
        
        self.feature_names = list(features.keys())
        return pd.Series(features)
    
    def _calculate_gini(self, values):
        """Calculate Gini coefficient for concentration measure"""
        if len(values) == 0:
            return 0
        
        sorted_values = np.sort(values)
        n = len(values)
        index = np.arange(1, n + 1)
        return (2 * np.sum(index * sorted_values)) / (n * np.sum(sorted_values)) - (n + 1) / n
    
    def create_temporal_features(self, df, window_sizes=[5, 10, 30, 60]):
        """Create rolling window features"""
        temporal_features = pd.DataFrame()
        
        if 'timestamp' in df.columns:
            df = df.sort_values('timestamp')
            
            for window in window_sizes:
                # Rolling statistics
                temporal_features[f'rolling_count_{window}'] = df.groupby('src_ip')['packet_size'].transform(
                    lambda x: x.rolling(window, min_periods=1).count()
                )
                temporal_features[f'rolling_mean_{window}'] = df.groupby('src_ip')['packet_size'].transform(
                    lambda x: x.rolling(window, min_periods=1).mean()
                )
                temporal_features[f'rolling_std_{window}'] = df.groupby('src_ip')['packet_size'].transform(
                    lambda x: x.rolling(window, min_periods=1).std()
                )
        
        return temporal_features
    
    def detect_attack_patterns(self, df):
        """Detect specific DDoS attack patterns"""
        patterns = {}
        
        # SYN Flood detection
        if 'flags' in df.columns:
            syn_count = (df['flags'].str.contains('SYN', na=False) & 
                        ~df['flags'].str.contains('ACK', na=False)).sum()
            patterns['syn_flood_score'] = syn_count / len(df)
        
        # UDP Flood detection
        if 'protocol' in df.columns:
            udp_ratio = (df['protocol'] == 'UDP').sum() / len(df)
            patterns['udp_flood_score'] = udp_ratio if udp_ratio > 0.7 else 0
        
        # HTTP Flood detection
        if 'dst_port' in df.columns:
            http_ports = [80, 443, 8080, 8443]
            http_ratio = df['dst_port'].isin(http_ports).sum() / len(df)
            patterns['http_flood_score'] = http_ratio if http_ratio > 0.8 else 0
        
        # ICMP Flood detection
        if 'protocol' in df.columns:
            icmp_ratio = (df['protocol'] == 'ICMP').sum() / len(df)
            patterns['icmp_flood_score'] = icmp_ratio if icmp_ratio > 0.5 else 0
        
        # DNS Amplification detection
        if 'dst_port' in df.columns and 'packet_size' in df.columns:
            dns_traffic = df[df['dst_port'] == 53]
            if len(dns_traffic) > 0:
                avg_dns_size = dns_traffic['packet_size'].mean()
                patterns['dns_amplification_score'] = 1 if avg_dns_size > 512 else 0
        
        return patterns