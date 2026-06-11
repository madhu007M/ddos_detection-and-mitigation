import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, VotingClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split, cross_val_score
import xgboost as xgb
import lightgbm as lgb
from tensorflow import keras
from tensorflow.keras import layers
import joblib
import pickle

class EnhancedDDoSDetector:
    def __init__(self):
        self.models = {}
        self.scaler = StandardScaler()
        self.best_model = None
        
    def create_ensemble_model(self):
        """Create ensemble of multiple models"""
        rf = RandomForestClassifier(n_estimators=200, max_depth=20, random_state=42, n_jobs=-1)
        xgb_model = xgb.XGBClassifier(n_estimators=200, max_depth=10, learning_rate=0.1, random_state=42)
        lgb_model = lgb.LGBMClassifier(n_estimators=200, max_depth=10, learning_rate=0.1, random_state=42)
        gb = GradientBoostingClassifier(n_estimators=200, max_depth=10, learning_rate=0.1, random_state=42)
        
        ensemble = VotingClassifier(
            estimators=[('rf', rf), ('xgb', xgb_model), ('lgb', lgb_model), ('gb', gb)],
            voting='soft'
        )
        
        return ensemble
    
    def create_deep_learning_model(self, input_shape):
        """Create deep neural network for DDoS detection"""
        model = keras.Sequential([
            layers.Dense(256, activation='relu', input_shape=(input_shape,)),
            layers.Dropout(0.3),
            layers.BatchNormalization(),
            layers.Dense(128, activation='relu'),
            layers.Dropout(0.3),
            layers.BatchNormalization(),
            layers.Dense(64, activation='relu'),
            layers.Dropout(0.2),
            layers.Dense(32, activation='relu'),
            layers.Dense(1, activation='sigmoid')
        ])
        
        model.compile(
            optimizer=keras.optimizers.Adam(learning_rate=0.001),
            loss='binary_crossentropy',
            metrics=['accuracy', keras.metrics.Precision(), keras.metrics.Recall()]
        )
        
        return model
    
    def create_lstm_model(self, sequence_length, n_features):
        """Create LSTM for temporal pattern detection"""
        model = keras.Sequential([
            layers.LSTM(128, return_sequences=True, input_shape=(sequence_length, n_features)),
            layers.Dropout(0.3),
            layers.LSTM(64, return_sequences=False),
            layers.Dropout(0.3),
            layers.Dense(32, activation='relu'),
            layers.Dense(1, activation='sigmoid')
        ])
        
        model.compile(
            optimizer='adam',
            loss='binary_crossentropy',
            metrics=['accuracy']
        )
        
        return model
    
    def train_all_models(self, X_train, y_train, X_test, y_test):
        """Train all models and compare performance"""
        results = {}
        
        # Scale features
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        # Train Ensemble Model
        print("Training Ensemble Model...")
        ensemble = self.create_ensemble_model()
        ensemble.fit(X_train_scaled, y_train)
        ensemble_score = ensemble.score(X_test_scaled, y_test)
        results['ensemble'] = ensemble_score
        self.models['ensemble'] = ensemble
        print(f"Ensemble Accuracy: {ensemble_score:.4f}")
        
        # Train Deep Learning Model
        print("\nTraining Deep Learning Model...")
        dl_model = self.create_deep_learning_model(X_train_scaled.shape[1])
        history = dl_model.fit(
            X_train_scaled, y_train,
            validation_split=0.2,
            epochs=50,
            batch_size=128,
            verbose=1,
            callbacks=[keras.callbacks.EarlyStopping(patience=5, restore_best_weights=True)]
        )
        dl_score = dl_model.evaluate(X_test_scaled, y_test, verbose=0)[1]
        results['deep_learning'] = dl_score
        self.models['deep_learning'] = dl_model
        print(f"Deep Learning Accuracy: {dl_score:.4f}")
        
        # Select best model
        self.best_model = max(results, key=results.get)
        print(f"\nBest Model: {self.best_model} with accuracy {results[self.best_model]:.4f}")
        
        return results
    
    def predict(self, X):
        """Predict using best model"""
        X_scaled = self.scaler.transform(X)
        return self.models[self.best_model].predict(X_scaled)
    
    def predict_proba(self, X):
        """Get prediction probabilities"""
        X_scaled = self.scaler.transform(X)
        if self.best_model == 'deep_learning':
            return self.models[self.best_model].predict(X_scaled)
        return self.models[self.best_model].predict_proba(X_scaled)
    
    def save_models(self, path='models/'):
        """Save all trained models"""
        import os
        os.makedirs(path, exist_ok=True)
        
        # Save ensemble
        joblib.dump(self.models.get('ensemble'), f'{path}ensemble_model.pkl')
        
        # Save deep learning
        if 'deep_learning' in self.models:
            self.models['deep_learning'].save(f'{path}deep_learning_model.h5')
        
        # Save scaler
        joblib.dump(self.scaler, f'{path}scaler.pkl')
        
        # Save best model name
        with open(f'{path}best_model.txt', 'w') as f:
            f.write(self.best_model)
    
    def load_models(self, path='models/'):
        """Load saved models"""
        self.models['ensemble'] = joblib.load(f'{path}ensemble_model.pkl')
        
        try:
            self.models['deep_learning'] = keras.models.load_model(f'{path}deep_learning_model.h5')
        except:
            pass
        
        self.scaler = joblib.load(f'{path}scaler.pkl')
        
        with open(f'{path}best_model.txt', 'r') as f:
            self.best_model = f.read().strip()

class AnomalyDetector:
    """Isolation Forest for anomaly detection"""
    def __init__(self):
        from sklearn.ensemble import IsolationForest
        self.model = IsolationForest(contamination=0.1, random_state=42, n_jobs=-1)
    
    def fit(self, X):
        self.model.fit(X)
    
    def predict(self, X):
        # Returns -1 for anomalies, 1 for normal
        return self.model.predict(X)
    
    def score_samples(self, X):
        # Returns anomaly score
        return self.model.score_samples(X)