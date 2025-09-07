import os
import logging
import numpy as np
import tensorflow as tf
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import Dataset, DataLoader
import pickle
from sklearn.preprocessing import StandardScaler
from datetime import datetime, timedelta
import hashlib
import struct

class TensorFlowMalwareDetector:
    """Advanced TensorFlow-based malware detection model"""
    
    def __init__(self):
        self.model = None
        self.scaler = StandardScaler()
        self.model_path = 'models/tensorflow_malware_detector.h5'
        self.scaler_path = 'models/tensorflow_scaler.pkl'
        self.is_trained = False
        
        # Create models directory
        os.makedirs('models', exist_ok=True)
        
        # Try to load existing model
        self.load_model()
        
        # If no model exists, create a new one
        if not self.is_trained:
            self.create_deep_learning_model()
    
    def create_deep_learning_model(self):
        """Create a deep neural network for malware detection"""
        try:
            # Define the neural network architecture
            self.model = tf.keras.Sequential([
                tf.keras.layers.Dense(512, activation='relu', input_shape=(20,)),
                tf.keras.layers.Dropout(0.3),
                tf.keras.layers.BatchNormalization(),
                
                tf.keras.layers.Dense(256, activation='relu'),
                tf.keras.layers.Dropout(0.3),
                tf.keras.layers.BatchNormalization(),
                
                tf.keras.layers.Dense(128, activation='relu'),
                tf.keras.layers.Dropout(0.2),
                tf.keras.layers.BatchNormalization(),
                
                tf.keras.layers.Dense(64, activation='relu'),
                tf.keras.layers.Dropout(0.2),
                
                tf.keras.layers.Dense(32, activation='relu'),
                tf.keras.layers.Dense(1, activation='sigmoid')
            ])
            
            # Compile the model
            self.model.compile(
                optimizer=tf.keras.optimizers.Adam(learning_rate=0.001),
                loss='binary_crossentropy',
                metrics=['accuracy', 'precision', 'recall']
            )
            
            # Train with synthetic data for demonstration
            self.train_with_synthetic_data()
            
        except Exception as e:
            logging.error(f"Error creating TensorFlow model: {str(e)}")
            # Fallback to simple model
            self.create_simple_model()
    
    def train_with_synthetic_data(self):
        """Train the model with synthetic malware data"""
        try:
            # Generate synthetic training data
            X_benign = np.random.normal(0.3, 0.2, (5000, 20))
            X_malware = np.random.normal(0.7, 0.3, (2000, 20))
            
            X = np.vstack([X_benign, X_malware])
            y = np.hstack([np.zeros(5000), np.ones(2000)])
            
            # Add some feature engineering
            X = self._engineer_features(X)
            
            # Normalize the data
            X_scaled = self.scaler.fit_transform(X)
            
            # Split data
            split_idx = int(0.8 * len(X_scaled))
            X_train, X_val = X_scaled[:split_idx], X_scaled[split_idx:]
            y_train, y_val = y[:split_idx], y[split_idx:]
            
            # Define callbacks
            early_stopping = tf.keras.callbacks.EarlyStopping(
                monitor='val_loss', patience=10, restore_best_weights=True
            )
            
            reduce_lr = tf.keras.callbacks.ReduceLROnPlateau(
                monitor='val_loss', factor=0.2, patience=5, min_lr=0.0001
            )
            
            # Train the model
            history = self.model.fit(
                X_train, y_train,
                epochs=100,
                batch_size=32,
                validation_data=(X_val, y_val),
                callbacks=[early_stopping, reduce_lr],
                verbose=0
            )
            
            # Evaluate model
            val_loss, val_accuracy, val_precision, val_recall = self.model.evaluate(
                X_val, y_val, verbose=0
            )
            
            logging.info(f"TensorFlow model trained - Accuracy: {val_accuracy:.3f}, "
                        f"Precision: {val_precision:.3f}, Recall: {val_recall:.3f}")
            
            self.is_trained = True
            self.save_model()
            
        except Exception as e:
            logging.error(f"Error training TensorFlow model: {str(e)}")
    
    def _engineer_features(self, X):
        """Engineer additional features from raw data"""
        # Add polynomial features
        X_poly = np.column_stack([
            X,
            X[:, 0] * X[:, 1],  # interaction features
            X[:, 2] * X[:, 3],
            np.sum(X**2, axis=1, keepdims=True),  # sum of squares
            np.std(X, axis=1, keepdims=True),     # standard deviation
        ])
        return X_poly
    
    def extract_advanced_features(self, file_path):
        """Extract advanced features for deep learning model"""
        try:
            features = []
            
            with open(file_path, 'rb') as f:
                data = f.read()
            
            # Basic statistical features
            features.extend([
                len(data),
                np.mean([b for b in data]),
                np.std([b for b in data]),
                len(set(data)) / 256.0,  # byte diversity
                data.count(0) / len(data) if len(data) > 0 else 0,  # null byte ratio
            ])
            
            # Entropy features
            entropy = self._calculate_shannon_entropy(data)
            features.append(entropy)
            
            # N-gram analysis
            bigram_entropy = self._calculate_ngram_entropy(data, 2)
            trigram_entropy = self._calculate_ngram_entropy(data, 3)
            features.extend([bigram_entropy, trigram_entropy])
            
            # PE header features (if applicable)
            pe_features = self._extract_pe_features(data)
            features.extend(pe_features)
            
            # String analysis features
            string_features = self._extract_string_features(data)
            features.extend(string_features)
            
            # Pad or truncate to expected feature size
            target_size = 20
            if len(features) < target_size:
                features.extend([0.0] * (target_size - len(features)))
            else:
                features = features[:target_size]
            
            return np.array(features, dtype=np.float32)
            
        except Exception as e:
            logging.error(f"Error extracting advanced features: {str(e)}")
            return np.zeros(20, dtype=np.float32)
    
    def _calculate_shannon_entropy(self, data):
        """Calculate Shannon entropy of byte sequence"""
        if len(data) == 0:
            return 0.0
        
        byte_counts = np.bincount(data, minlength=256)
        probabilities = byte_counts / len(data)
        probabilities = probabilities[probabilities > 0]
        
        return -np.sum(probabilities * np.log2(probabilities))
    
    def _calculate_ngram_entropy(self, data, n):
        """Calculate n-gram entropy"""
        if len(data) < n:
            return 0.0
        
        ngrams = {}
        for i in range(len(data) - n + 1):
            ngram = tuple(data[i:i+n])
            ngrams[ngram] = ngrams.get(ngram, 0) + 1
        
        total_ngrams = len(data) - n + 1
        entropy = 0.0
        for count in ngrams.values():
            prob = count / total_ngrams
            entropy -= prob * np.log2(prob)
        
        return entropy
    
    def _extract_pe_features(self, data):
        """Extract PE-specific features"""
        features = [0.0] * 5  # Default values
        
        try:
            if len(data) < 64:
                return features
            
            # Check for MZ signature
            if data[:2] == b'MZ':
                features[0] = 1.0
                
                # Get PE offset
                pe_offset = struct.unpack('<L', data[60:64])[0]
                if pe_offset < len(data) - 4:
                    # Check for PE signature
                    if data[pe_offset:pe_offset+4] == b'PE\x00\x00':
                        features[1] = 1.0
                        
                        # Extract more PE features if possible
                        if pe_offset + 24 < len(data):
                            # Machine type
                            machine = struct.unpack('<H', data[pe_offset+4:pe_offset+6])[0]
                            features[2] = machine / 65535.0
                            
                            # Number of sections
                            sections = struct.unpack('<H', data[pe_offset+6:pe_offset+8])[0]
                            features[3] = min(sections / 50.0, 1.0)
                            
                            # Timestamp
                            timestamp = struct.unpack('<L', data[pe_offset+8:pe_offset+12])[0]
                            features[4] = min(timestamp / 2147483647.0, 1.0)
        
        except:
            pass
        
        return features
    
    def _extract_string_features(self, data):
        """Extract string-based features"""
        features = [0.0] * 5
        
        try:
            # Extract printable strings
            strings = []
            current_string = b""
            
            for byte in data:
                if 32 <= byte <= 126:  # Printable ASCII
                    current_string += bytes([byte])
                else:
                    if len(current_string) >= 4:
                        strings.append(current_string.decode('ascii'))
                    current_string = b""
            
            if len(current_string) >= 4:
                strings.append(current_string.decode('ascii'))
            
            # String-based features
            features[0] = len(strings) / 1000.0  # Total strings (normalized)
            
            if strings:
                avg_length = np.mean([len(s) for s in strings])
                features[1] = min(avg_length / 50.0, 1.0)  # Average string length
                
                # Check for suspicious strings
                suspicious_keywords = [
                    'virus', 'trojan', 'malware', 'keylog', 'backdoor',
                    'exploit', 'payload', 'shellcode', 'rootkit', 'botnet'
                ]
                
                suspicious_count = sum(
                    1 for s in strings 
                    for keyword in suspicious_keywords 
                    if keyword in s.lower()
                )
                features[2] = min(suspicious_count / 10.0, 1.0)
                
                # URL/domain patterns
                url_count = sum(1 for s in strings if 'http' in s.lower() or '.com' in s.lower())
                features[3] = min(url_count / 10.0, 1.0)
                
                # Cryptographic patterns
                crypto_count = sum(1 for s in strings if len(s) > 20 and s.isalnum())
                features[4] = min(crypto_count / 10.0, 1.0)
        
        except:
            pass
        
        return features
    
    def predict(self, file_path):
        """Predict malware probability using TensorFlow model"""
        if not self.is_trained or self.model is None:
            return 0.5
        
        try:
            features = self.extract_advanced_features(file_path)
            features_scaled = self.scaler.transform(features.reshape(1, -1))
            
            prediction = self.model.predict(features_scaled, verbose=0)[0][0]
            return float(prediction)
            
        except Exception as e:
            logging.error(f"Error in TensorFlow prediction: {str(e)}")
            return 0.5
    
    def save_model(self):
        """Save the trained model and scaler"""
        try:
            if self.model:
                self.model.save(self.model_path)
            
            with open(self.scaler_path, 'wb') as f:
                pickle.dump(self.scaler, f)
            
            logging.info("TensorFlow model and scaler saved successfully")
        except Exception as e:
            logging.error(f"Error saving TensorFlow model: {str(e)}")
    
    def load_model(self):
        """Load trained model and scaler"""
        try:
            if os.path.exists(self.model_path) and os.path.exists(self.scaler_path):
                self.model = tf.keras.models.load_model(self.model_path)
                
                with open(self.scaler_path, 'rb') as f:
                    self.scaler = pickle.load(f)
                
                self.is_trained = True
                logging.info("TensorFlow model and scaler loaded successfully")
                return True
        except Exception as e:
            logging.error(f"Error loading TensorFlow model: {str(e)}")
        
        return False


class PyTorchMalwareDetector(nn.Module):
    """Advanced PyTorch-based malware detection model"""
    
    def __init__(self, input_size=20):
        super(PyTorchMalwareDetector, self).__init__()
        
        self.network = nn.Sequential(
            nn.Linear(input_size, 512),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.BatchNorm1d(512),
            
            nn.Linear(512, 256),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.BatchNorm1d(256),
            
            nn.Linear(256, 128),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.BatchNorm1d(128),
            
            nn.Linear(128, 64),
            nn.ReLU(),
            nn.Dropout(0.2),
            
            nn.Linear(64, 32),
            nn.ReLU(),
            nn.Linear(32, 1),
            nn.Sigmoid()
        )
    
    def forward(self, x):
        return self.network(x)


class PyTorchMalwareDetectorWrapper:
    """Wrapper class for PyTorch malware detection model"""
    
    def __init__(self):
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        self.model = PyTorchMalwareDetector().to(self.device)
        self.scaler = StandardScaler()
        self.model_path = 'models/pytorch_malware_detector.pth'
        self.scaler_path = 'models/pytorch_scaler.pkl'
        self.is_trained = False
        
        # Create models directory
        os.makedirs('models', exist_ok=True)
        
        # Try to load existing model
        self.load_model()
        
        # If no model exists, create and train a new one
        if not self.is_trained:
            self.train_model()
    
    def train_model(self):
        """Train the PyTorch model with synthetic data"""
        try:
            # Generate synthetic data
            X_benign = np.random.normal(0.3, 0.2, (5000, 20))
            X_malware = np.random.normal(0.7, 0.3, (2000, 20))
            
            X = np.vstack([X_benign, X_malware])
            y = np.hstack([np.zeros(5000), np.ones(2000)])
            
            # Normalize data
            X_scaled = self.scaler.fit_transform(X)
            
            # Convert to tensors
            X_tensor = torch.FloatTensor(X_scaled).to(self.device)
            y_tensor = torch.FloatTensor(y).to(self.device)
            
            # Split data
            split_idx = int(0.8 * len(X_tensor))
            X_train, X_val = X_tensor[:split_idx], X_tensor[split_idx:]
            y_train, y_val = y_tensor[:split_idx], y_tensor[split_idx:]
            
            # Training parameters
            criterion = nn.BCELoss()
            optimizer = torch.optim.Adam(self.model.parameters(), lr=0.001)
            scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(
                optimizer, 'min', patience=10, factor=0.5
            )
            
            # Training loop
            self.model.train()
            best_val_loss = float('inf')
            patience = 15
            patience_counter = 0
            
            for epoch in range(200):
                # Training
                optimizer.zero_grad()
                outputs = self.model(X_train).squeeze()
                loss = criterion(outputs, y_train)
                loss.backward()
                optimizer.step()
                
                # Validation
                self.model.eval()
                with torch.no_grad():
                    val_outputs = self.model(X_val).squeeze()
                    val_loss = criterion(val_outputs, y_val)
                    val_accuracy = ((val_outputs > 0.5) == (y_val > 0.5)).float().mean()
                
                scheduler.step(val_loss)
                
                # Early stopping
                if val_loss < best_val_loss:
                    best_val_loss = val_loss
                    patience_counter = 0
                    # Save best model
                    torch.save(self.model.state_dict(), self.model_path)
                else:
                    patience_counter += 1
                    if patience_counter >= patience:
                        break
                
                self.model.train()
            
            # Load best model
            self.model.load_state_dict(torch.load(self.model_path, map_location=self.device))
            
            logging.info(f"PyTorch model trained - Final validation accuracy: {val_accuracy:.3f}")
            
            self.is_trained = True
            self.save_scaler()
            
        except Exception as e:
            logging.error(f"Error training PyTorch model: {str(e)}")
    
    def extract_features(self, file_path):
        """Extract features using the same method as TensorFlow model"""
        tf_detector = TensorFlowMalwareDetector()
        return tf_detector.extract_advanced_features(file_path)
    
    def predict(self, file_path):
        """Predict malware probability using PyTorch model"""
        if not self.is_trained:
            return 0.5
        
        try:
            self.model.eval()
            features = self.extract_features(file_path)
            features_scaled = self.scaler.transform(features.reshape(1, -1))
            
            with torch.no_grad():
                features_tensor = torch.FloatTensor(features_scaled).to(self.device)
                prediction = self.model(features_tensor).cpu().numpy()[0][0]
            
            return float(prediction)
            
        except Exception as e:
            logging.error(f"Error in PyTorch prediction: {str(e)}")
            return 0.5
    
    def save_scaler(self):
        """Save the scaler"""
        try:
            with open(self.scaler_path, 'wb') as f:
                pickle.dump(self.scaler, f)
            logging.info("PyTorch scaler saved successfully")
        except Exception as e:
            logging.error(f"Error saving PyTorch scaler: {str(e)}")
    
    def load_model(self):
        """Load trained model and scaler"""
        try:
            if os.path.exists(self.model_path) and os.path.exists(self.scaler_path):
                self.model.load_state_dict(torch.load(self.model_path, map_location=self.device))
                
                with open(self.scaler_path, 'rb') as f:
                    self.scaler = pickle.load(f)
                
                self.is_trained = True
                logging.info("PyTorch model and scaler loaded successfully")
                return True
        except Exception as e:
            logging.error(f"Error loading PyTorch model: {str(e)}")
        
        return False


class EnsembleMalwareDetector:
    """Ensemble model combining TensorFlow, PyTorch, and traditional ML"""
    
    def __init__(self):
        self.tf_detector = TensorFlowMalwareDetector()
        self.pytorch_detector = PyTorchMalwareDetectorWrapper()
        
        # Import the existing scikit-learn detector
        from ml_models import malware_detector as sklearn_detector
        self.sklearn_detector = sklearn_detector
    
    def predict(self, file_path):
        """Make ensemble prediction using all three models"""
        try:
            # Get predictions from all models
            tf_prediction = self.tf_detector.predict(file_path)
            pytorch_prediction = self.pytorch_detector.predict(file_path)
            
            # For sklearn detector, extract features and predict
            features = self.sklearn_detector.extract_features(file_path)
            sklearn_prediction = self.sklearn_detector.predict(features)
            
            # Ensemble weights (can be tuned based on model performance)
            weights = [0.4, 0.4, 0.2]  # TensorFlow, PyTorch, sklearn
            predictions = [tf_prediction, pytorch_prediction, sklearn_prediction]
            
            # Weighted average
            ensemble_prediction = sum(w * p for w, p in zip(weights, predictions))
            
            return min(max(ensemble_prediction, 0.0), 1.0)  # Clamp to [0,1]
            
        except Exception as e:
            logging.error(f"Error in ensemble prediction: {str(e)}")
            return 0.5
    
    def get_detailed_predictions(self, file_path):
        """Get detailed predictions from all models for analysis"""
        try:
            tf_prediction = self.tf_detector.predict(file_path)
            pytorch_prediction = self.pytorch_detector.predict(file_path)
            
            features = self.sklearn_detector.extract_features(file_path)
            sklearn_prediction = self.sklearn_detector.predict(features)
            
            ensemble_prediction = self.predict(file_path)
            
            return {
                'tensorflow': tf_prediction,
                'pytorch': pytorch_prediction,
                'sklearn': sklearn_prediction,
                'ensemble': ensemble_prediction
            }
            
        except Exception as e:
            logging.error(f"Error getting detailed predictions: {str(e)}")
            return {
                'tensorflow': 0.5,
                'pytorch': 0.5,
                'sklearn': 0.5,
                'ensemble': 0.5
            }


# Initialize the ensemble detector
import os

# Allow disabling deep learning components via environment for dev/Windows
if os.environ.get('ENABLE_DEEP_LEARNING', 'true').lower() == 'true':
    ensemble_detector = EnsembleMalwareDetector()
else:
    class _DisabledDetector:
        def predict(self, features):
            return 0.0
        def extract_features(self, *args, **kwargs):
            return []
    ensemble_detector = _DisabledDetector()