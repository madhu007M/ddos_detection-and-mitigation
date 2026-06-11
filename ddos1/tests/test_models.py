import pytest
import numpy as np
import pandas as pd
from enhanced_models import EnhancedDDoSDetector, AnomalyDetector

class TestEnhancedModels:
    @pytest.fixture
    def sample_data(self):
        """Create sample training data"""
        np.random.seed(42)
        X = np.random.randn(1000, 20)
        y = np.random.randint(0, 2, 1000)
        return X, y
    
    def test_ensemble_model_creation(self):
        """Test ensemble model creation"""
        detector = EnhancedDDoSDetector()
        model = detector.create_ensemble_model()
        assert model is not None
    
    def test_deep_learning_model_creation(self):
        """Test deep learning model creation"""
        detector = EnhancedDDoSDetector()
        model = detector.create_deep_learning_model(20)
        assert model is not None
        assert len(model.layers) > 0
    
    def test_model_training(self, sample_data):
        """Test model training"""
        X, y = sample_data
        X_train, X_test = X[:800], X[800:]
        y_train, y_test = y[:800], y[800:]
        
        detector = EnhancedDDoSDetector()
        results = detector.train_all_models(X_train, y_train, X_test, y_test)
        
        assert 'ensemble' in results
        assert 'deep_learning' in results
        assert all(0 <= score <= 1 for score in results.values())
    
    def test_prediction(self, sample_data):
        """Test model prediction"""
        X, y = sample_data
        X_train, X_test = X[:800], X[800:]
        y_train, y_test = y[:800], y[800:]
        
        detector = EnhancedDDoSDetector()
        detector.train_all_models(X_train, y_train, X_test, y_test)
        
        predictions = detector.predict(X_test)
        assert len(predictions) == len(X_test)
        assert all(p in [0, 1] for p in predictions)
    
    def test_anomaly_detector(self, sample_data):
        """Test anomaly detection"""
        X, _ = sample_data
        
        anomaly_detector = AnomalyDetector()
        anomaly_detector.fit(X[:800])
        
        predictions = anomaly_detector.predict(X[800:])
        assert len(predictions) == 200
        assert all(p in [-1, 1] for p in predictions)