import pickle
import os
import logging
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import hashlib
import struct

class MalwareDetector:
    """Machine learning model for malware detection"""
    
    def __init__(self):
        self.model = None
        self.vectorizer = None
        self.model_path = 'models/malware_detector.pkl'
        self.vectorizer_path = 'models/vectorizer.pkl'
        self.is_trained = False
        
        # Create models directory
        os.makedirs('models', exist_ok=True)
        
        # Try to load existing model
        self.load_model()
        
        # If no model exists, create a basic one
        if not self.is_trained:
            self.create_basic_model()
    
    def extract_features(self, file_path):
        """Extract features from a file for ML analysis"""
        try:
            features = {}
            
            # File size
            file_size = os.path.getsize(file_path)
            features['file_size'] = file_size
            
            # File extension
            _, ext = os.path.splitext(file_path)
            features['extension'] = ext.lower()
            
            # Entropy calculation
            with open(file_path, 'rb') as f:
                data = f.read()
                entropy = self.calculate_entropy(data)
                features['entropy'] = entropy
            
            # PE header analysis (for executables)
            if ext.lower() in ['.exe', '.dll', '.scr']:
                pe_features = self.analyze_pe_header(data)
                features.update(pe_features)
            
            # String analysis
            strings = self.extract_strings(data)
            features['string_count'] = len(strings)
            features['suspicious_strings'] = self.count_suspicious_strings(strings)
            
            return features
            
        except Exception as e:
            logging.error(f"Error extracting features: {str(e)}")
            return {}
    
    def calculate_entropy(self, data):
        """Calculate Shannon entropy of data"""
        if len(data) == 0:
            return 0
        
        entropy = 0
        for i in range(256):
            p_x = float(data.count(bytes([i]))) / len(data)
            if p_x > 0:
                entropy += - p_x * np.log2(p_x)
        
        return entropy
    
    def analyze_pe_header(self, data):
        """Analyze PE header for Windows executables"""
        features = {}
        
        try:
            # Check for PE signature
            if len(data) < 64:
                return features
            
            # DOS header
            dos_header = struct.unpack('<H', data[0:2])[0]
            features['dos_signature'] = dos_header == 0x5A4D  # MZ
            
            if len(data) > 60:
                pe_offset = struct.unpack('<L', data[60:64])[0]
                if pe_offset < len(data) - 4:
                    pe_signature = struct.unpack('<L', data[pe_offset:pe_offset+4])[0]
                    features['pe_signature'] = pe_signature == 0x00004550  # PE\0\0
            
        except Exception as e:
            logging.error(f"Error analyzing PE header: {str(e)}")
        
        return features
    
    def extract_strings(self, data, min_length=4):
        """Extract ASCII strings from binary data"""
        strings = []
        current_string = ""
        
        for byte in data:
            if 32 <= byte <= 126:  # Printable ASCII
                current_string += chr(byte)
            else:
                if len(current_string) >= min_length:
                    strings.append(current_string)
                current_string = ""
        
        if len(current_string) >= min_length:
            strings.append(current_string)
        
        return strings
    
    def count_suspicious_strings(self, strings):
        """Count suspicious strings that might indicate malware"""
        suspicious_keywords = [
            'virus', 'trojan', 'malware', 'keylog', 'backdoor',
            'exploit', 'payload', 'shellcode', 'rootkit', 'botnet',
            'encrypt', 'decrypt', 'ransom', 'bitcoin', 'cryptocurrency'
        ]
        
        count = 0
        for string in strings:
            string_lower = string.lower()
            for keyword in suspicious_keywords:
                if keyword in string_lower:
                    count += 1
                    break
        
        return count
    
    def create_basic_model(self):
        """Create a basic ML model for malware detection"""
        logging.info("Creating basic malware detection model...")
        
        # Create synthetic training data for demonstration
        # In production, this would use real malware samples
        X_features = []
        y_labels = []
        
        # Generate synthetic features for benign files
        for _ in range(1000):
            features = {
                'file_size': np.random.normal(50000, 20000),
                'entropy': np.random.normal(5.0, 1.0),
                'string_count': np.random.normal(100, 30),
                'suspicious_strings': np.random.poisson(0.5),
                'dos_signature': 1,
                'pe_signature': 1
            }
            X_features.append(list(features.values()))
            y_labels.append(0)  # Benign
        
        # Generate synthetic features for malicious files
        for _ in range(500):
            features = {
                'file_size': np.random.normal(30000, 15000),
                'entropy': np.random.normal(7.5, 0.5),
                'string_count': np.random.normal(50, 20),
                'suspicious_strings': np.random.poisson(3),
                'dos_signature': 1,
                'pe_signature': 1
            }
            X_features.append(list(features.values()))
            y_labels.append(1)  # Malicious
        
        X = np.array(X_features)
        y = np.array(y_labels)
        
        # Train the model
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        
        self.model = RandomForestClassifier(n_estimators=100, random_state=42)
        self.model.fit(X_train, y_train)
        
        # Test accuracy
        y_pred = self.model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        logging.info(f"Model trained with accuracy: {accuracy:.2f}")
        
        self.is_trained = True
        self.save_model()
    
    def predict(self, features):
        """Predict if file is malicious based on features"""
        if not self.is_trained or self.model is None:
            return 0.5  # Neutral score if model not available
        
        try:
            # Convert features to the expected format
            feature_vector = [
                features.get('file_size', 0),
                features.get('entropy', 0),
                features.get('string_count', 0),
                features.get('suspicious_strings', 0),
                int(features.get('dos_signature', False)),
                int(features.get('pe_signature', False))
            ]
            
            X = np.array([feature_vector])
            
            # Get probability prediction
            probabilities = self.model.predict_proba(X)
            malicious_probability = probabilities[0][1]
            
            return malicious_probability
            
        except Exception as e:
            logging.error(f"Error in prediction: {str(e)}")
            return 0.5
    
    def save_model(self):
        """Save the trained model to disk"""
        try:
            with open(self.model_path, 'wb') as f:
                pickle.dump(self.model, f)
            logging.info("Model saved successfully")
        except Exception as e:
            logging.error(f"Error saving model: {str(e)}")
    
    def load_model(self):
        """Load a trained model from disk"""
        try:
            if os.path.exists(self.model_path):
                with open(self.model_path, 'rb') as f:
                    self.model = pickle.load(f)
                self.is_trained = True
                logging.info("Model loaded successfully")
                return True
        except Exception as e:
            logging.error(f"Error loading model: {str(e)}")
        
        return False

# Singleton instance
malware_detector = MalwareDetector()
