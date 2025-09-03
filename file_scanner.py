import os
import hashlib
import logging
from datetime import datetime
import magic
from ml_models import malware_detector

class FileScanner:
    """File scanning and analysis component"""
    
    def __init__(self):
        self.max_file_size = 100 * 1024 * 1024  # 100MB
        self.supported_extensions = {
            '.exe', '.dll', '.scr', '.bat', '.cmd', '.com', '.pif',
            '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
            '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2',
            '.js', '.jar', '.apk', '.ipa'
        }
    
    def scan_file(self, file_path, filename):
        """Perform comprehensive file scanning"""
        try:
            result = {
                'filename': filename,
                'file_path': file_path,
                'file_hash': '',
                'file_size': 0,
                'file_type': '',
                'risk_score': 0.0,
                'threat_level': 'safe',
                'detection_details': [],
                'scan_timestamp': datetime.utcnow().isoformat()
            }
            
            # Basic file information
            file_stats = os.stat(file_path)
            result['file_size'] = file_stats.st_size
            
            # Calculate file hash
            result['file_hash'] = self.calculate_file_hash(file_path)
            
            # Detect file type
            result['file_type'] = self.detect_file_type(file_path)
            
            # Perform various security checks
            checks = [
                self.check_file_size,
                self.check_file_extension,
                self.check_file_signature,
                self.check_with_ml_model,
                self.check_suspicious_patterns
            ]
            
            threat_indicators = []
            total_risk = 0.0
            
            for check in checks:
                check_result = check(file_path, filename, result)
                if check_result['is_threat']:
                    threat_indicators.append(check_result['reason'])
                    total_risk += check_result['risk_weight']
            
            # Calculate final risk score
            result['risk_score'] = min(total_risk, 1.0)
            
            # Determine threat level
            if result['risk_score'] >= 0.8:
                result['threat_level'] = 'malicious'
            elif result['risk_score'] >= 0.4:
                result['threat_level'] = 'suspicious'
            else:
                result['threat_level'] = 'safe'
            
            result['detection_details'] = threat_indicators
            
            logging.info(f"File scan completed: {filename} - {result['threat_level']} (score: {result['risk_score']:.2f})")
            
            return result
            
        except Exception as e:
            logging.error(f"Error scanning file {filename}: {str(e)}")
            return {
                'filename': filename,
                'file_path': file_path,
                'file_hash': '',
                'file_size': 0,
                'file_type': 'unknown',
                'risk_score': 0.5,
                'threat_level': 'unknown',
                'detection_details': ['Error during scanning'],
                'scan_timestamp': datetime.utcnow().isoformat()
            }
    
    def calculate_file_hash(self, file_path):
        """Calculate SHA-256 hash of the file"""
        try:
            sha256_hash = hashlib.sha256()
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(chunk)
            return sha256_hash.hexdigest()
        except Exception as e:
            logging.error(f"Error calculating file hash: {str(e)}")
            return ""
    
    def detect_file_type(self, file_path):
        """Detect file type using magic numbers"""
        try:
            # Try to use python-magic if available
            try:
                mime_type = magic.from_file(file_path, mime=True)
                return mime_type
            except:
                # Fallback to simple extension-based detection
                _, ext = os.path.splitext(file_path)
                return f"file/{ext[1:]}" if ext else "unknown"
        except Exception as e:
            logging.error(f"Error detecting file type: {str(e)}")
            return "unknown"
    
    def check_file_size(self, file_path, filename, result):
        """Check if file size is suspicious"""
        file_size = result['file_size']
        
        # Very large files might be suspicious
        if file_size > 50 * 1024 * 1024:  # 50MB
            return {
                'is_threat': True,
                'reason': f'Unusually large file size: {file_size / (1024*1024):.1f}MB',
                'risk_weight': 0.2
            }
        
        # Very small executable files might be packed/suspicious
        _, ext = os.path.splitext(filename)
        if ext.lower() in ['.exe', '.dll'] and file_size < 10240:  # 10KB
            return {
                'is_threat': True,
                'reason': 'Unusually small executable file',
                'risk_weight': 0.3
            }
        
        return {'is_threat': False, 'reason': '', 'risk_weight': 0.0}
    
    def check_file_extension(self, file_path, filename, result):
        """Check file extension for suspicious patterns"""
        _, ext = os.path.splitext(filename)
        ext = ext.lower()
        
        # High-risk extensions
        high_risk_extensions = ['.exe', '.scr', '.bat', '.cmd', '.com', '.pif']
        if ext in high_risk_extensions:
            return {
                'is_threat': True,
                'reason': f'High-risk file extension: {ext}',
                'risk_weight': 0.4
            }
        
        # Double extensions (e.g., .pdf.exe)
        if filename.count('.') > 1:
            parts = filename.split('.')
            if len(parts) >= 3 and parts[-1].lower() in high_risk_extensions:
                return {
                    'is_threat': True,
                    'reason': 'Suspicious double extension detected',
                    'risk_weight': 0.6
                }
        
        return {'is_threat': False, 'reason': '', 'risk_weight': 0.0}
    
    def check_file_signature(self, file_path, filename, result):
        """Check file signature/magic bytes"""
        try:
            with open(file_path, 'rb') as f:
                header = f.read(16)
            
            # Check for PE executables
            if len(header) >= 2 and header[:2] == b'MZ':
                return {
                    'is_threat': True,
                    'reason': 'Windows executable detected',
                    'risk_weight': 0.3
                }
            
            # Check for script files disguised with different extensions
            script_signatures = [
                (b'#!/bin/bash', 'Bash script'),
                (b'#!/bin/sh', 'Shell script'),
                (b'@echo off', 'Batch script'),
                (b'<script', 'HTML/JavaScript')
            ]
            
            for signature, description in script_signatures:
                if header.startswith(signature):
                    _, ext = os.path.splitext(filename)
                    if ext.lower() not in ['.sh', '.bat', '.cmd', '.html', '.js']:
                        return {
                            'is_threat': True,
                            'reason': f'{description} with non-script extension',
                            'risk_weight': 0.5
                        }
            
            return {'is_threat': False, 'reason': '', 'risk_weight': 0.0}
            
        except Exception as e:
            logging.error(f"Error checking file signature: {str(e)}")
            return {'is_threat': False, 'reason': '', 'risk_weight': 0.0}
    
    def check_with_ml_model(self, file_path, filename, result):
        """Use machine learning model for malware detection"""
        try:
            # Extract features for ML model
            features = malware_detector.extract_features(file_path)
            
            # Get prediction from ML model
            malware_probability = malware_detector.predict(features)
            
            if malware_probability > 0.7:
                return {
                    'is_threat': True,
                    'reason': f'ML model detected malware (confidence: {malware_probability:.2f})',
                    'risk_weight': malware_probability
                }
            elif malware_probability > 0.4:
                return {
                    'is_threat': True,
                    'reason': f'ML model flagged as suspicious (confidence: {malware_probability:.2f})',
                    'risk_weight': malware_probability * 0.7
                }
            
            return {'is_threat': False, 'reason': '', 'risk_weight': 0.0}
            
        except Exception as e:
            logging.error(f"Error in ML model check: {str(e)}")
            return {'is_threat': False, 'reason': '', 'risk_weight': 0.0}
    
    def check_suspicious_patterns(self, file_path, filename, result):
        """Check for suspicious patterns in filename and content"""
        suspicious_indicators = []
        risk_weight = 0.0
        
        # Suspicious filename patterns
        suspicious_names = [
            'invoice', 'receipt', 'payment', 'statement', 'urgent',
            'security', 'update', 'patch', 'install', 'setup'
        ]
        
        filename_lower = filename.lower()
        for name in suspicious_names:
            if name in filename_lower:
                suspicious_indicators.append(f'Suspicious filename pattern: {name}')
                risk_weight += 0.1
        
        # Check for suspicious file content (first 1KB)
        try:
            with open(file_path, 'rb') as f:
                content = f.read(1024).decode('utf-8', errors='ignore')
            
            suspicious_strings = [
                'powershell', 'cmd.exe', 'wget', 'curl', 'download',
                'exploit', 'payload', 'backdoor', 'trojan'
            ]
            
            content_lower = content.lower()
            for string in suspicious_strings:
                if string in content_lower:
                    suspicious_indicators.append(f'Suspicious content: {string}')
                    risk_weight += 0.2
                    
        except Exception:
            pass  # Content analysis failed, continue without it
        
        if suspicious_indicators:
            return {
                'is_threat': True,
                'reason': '; '.join(suspicious_indicators),
                'risk_weight': min(risk_weight, 0.8)
            }
        
        return {'is_threat': False, 'reason': '', 'risk_weight': 0.0}
