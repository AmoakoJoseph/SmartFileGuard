import os
import logging
import json
import time
import hashlib
from datetime import datetime, timedelta
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Dict, List, Any, Optional
import numpy as np
from app import db
from db_models import ScanResult, URLScan, ActivityLog

@dataclass
class BehavioralPattern:
    """Represents a behavioral pattern detected in malware analysis"""
    pattern_type: str
    confidence: float
    description: str
    indicators: List[str]
    timestamp: datetime
    risk_level: str  # 'low', 'medium', 'high', 'critical'

class BehavioralAnalysisEngine:
    """Advanced behavioral analysis engine for malware detection"""
    
    def __init__(self):
        self.pattern_cache = {}
        self.time_window = timedelta(hours=24)  # Analysis window
        self.min_confidence = 0.3
        
        # Behavioral patterns database
        self.behavioral_patterns = {
            'rapid_scanning': {
                'description': 'Rapid consecutive file scanning behavior',
                'indicators': ['multiple_files', 'short_intervals'],
                'risk_multiplier': 1.2
            },
            'suspicious_extensions': {
                'description': 'Files with suspicious or misleading extensions',
                'indicators': ['double_extension', 'executable_disguised'],
                'risk_multiplier': 1.8
            },
            'network_indicators': {
                'description': 'Network-based suspicious behavior patterns',
                'indicators': ['multiple_urls', 'suspicious_domains'],
                'risk_multiplier': 1.5
            },
            'time_based_patterns': {
                'description': 'Temporal patterns indicating coordinated attacks',
                'indicators': ['burst_activity', 'off_hours_activity'],
                'risk_multiplier': 1.3
            },
            'evasion_techniques': {
                'description': 'File characteristics indicating evasion attempts',
                'indicators': ['packed_executable', 'entropy_anomalies'],
                'risk_multiplier': 2.0
            }
        }
        
        # Threat intelligence patterns
        self.threat_patterns = {
            'apt_indicators': [
                'targeted_filename', 'specific_payload', 'persistence_mechanism'
            ],
            'ransomware_patterns': [
                'encryption_behavior', 'file_extension_changes', 'ransom_notes'
            ],
            'trojan_characteristics': [
                'backdoor_functionality', 'data_exfiltration', 'remote_access'
            ],
            'rootkit_behavior': [
                'system_modification', 'stealth_techniques', 'privilege_escalation'
            ]
        }
    
    def analyze_file_behavior(self, file_path: str, scan_results: Dict[str, Any]) -> List[BehavioralPattern]:
        """Analyze individual file behavior patterns"""
        patterns = []
        
        try:
            # Static analysis patterns
            static_patterns = self._analyze_static_behavior(file_path, scan_results)
            patterns.extend(static_patterns)
            
            # File metadata analysis
            metadata_patterns = self._analyze_file_metadata(file_path, scan_results)
            patterns.extend(metadata_patterns)
            
            # Content-based behavioral analysis
            content_patterns = self._analyze_file_content(file_path)
            patterns.extend(content_patterns)
            
            return patterns
            
        except Exception as e:
            logging.error(f"Error in file behavior analysis: {str(e)}")
            return []
    
    def analyze_system_behavior(self, time_window: timedelta = None) -> List[BehavioralPattern]:
        """Analyze system-wide behavioral patterns"""
        if time_window is None:
            time_window = self.time_window
        
        patterns = []
        
        try:
            cutoff_time = datetime.utcnow() - time_window
            
            # Get recent scan data
            recent_scans = ScanResult.query.filter(
                ScanResult.scan_timestamp >= cutoff_time
            ).all()
            
            recent_url_scans = URLScan.query.filter(
                URLScan.scan_timestamp >= cutoff_time
            ).all()
            
            recent_activities = ActivityLog.query.filter(
                ActivityLog.timestamp >= cutoff_time
            ).all()
            
            # Analyze scanning patterns
            scan_patterns = self._analyze_scanning_patterns(recent_scans)
            patterns.extend(scan_patterns)
            
            # Analyze URL access patterns
            url_patterns = self._analyze_url_patterns(recent_url_scans)
            patterns.extend(url_patterns)
            
            # Analyze activity patterns
            activity_patterns = self._analyze_activity_patterns(recent_activities)
            patterns.extend(activity_patterns)
            
            # Cross-reference patterns for correlation
            correlated_patterns = self._correlate_patterns(patterns)
            patterns.extend(correlated_patterns)
            
            return patterns
            
        except Exception as e:
            logging.error(f"Error in system behavior analysis: {str(e)}")
            return []
    
    def _analyze_static_behavior(self, file_path: str, scan_results: Dict[str, Any]) -> List[BehavioralPattern]:
        """Analyze static file characteristics for behavioral patterns"""
        patterns = []
        
        try:
            filename = os.path.basename(file_path)
            file_size = scan_results.get('file_size', 0)
            
            # Check for suspicious file extensions
            if self._has_suspicious_extension(filename):
                patterns.append(BehavioralPattern(
                    pattern_type='suspicious_extensions',
                    confidence=0.8,
                    description='File has suspicious or misleading extension',
                    indicators=['double_extension', 'executable_disguised'],
                    timestamp=datetime.utcnow(),
                    risk_level='high'
                ))
            
            # Check for size-based anomalies
            if self._has_size_anomaly(file_size, filename):
                patterns.append(BehavioralPattern(
                    pattern_type='size_anomaly',
                    confidence=0.6,
                    description='File size is anomalous for its type',
                    indicators=['unusual_size'],
                    timestamp=datetime.utcnow(),
                    risk_level='medium'
                ))
            
            # Check for packing indicators
            if self._is_potentially_packed(scan_results):
                patterns.append(BehavioralPattern(
                    pattern_type='evasion_techniques',
                    confidence=0.7,
                    description='File shows signs of packing or obfuscation',
                    indicators=['packed_executable', 'entropy_anomalies'],
                    timestamp=datetime.utcnow(),
                    risk_level='high'
                ))
            
        except Exception as e:
            logging.error(f"Error in static behavior analysis: {str(e)}")
        
        return patterns
    
    def _analyze_file_metadata(self, file_path: str, scan_results: Dict[str, Any]) -> List[BehavioralPattern]:
        """Analyze file metadata for behavioral indicators"""
        patterns = []
        
        try:
            # Check creation/modification times
            stat = os.stat(file_path)
            creation_time = datetime.fromtimestamp(stat.st_ctime)
            modification_time = datetime.fromtimestamp(stat.st_mtime)
            
            # Check for temporal anomalies
            if self._has_temporal_anomaly(creation_time, modification_time):
                patterns.append(BehavioralPattern(
                    pattern_type='time_based_patterns',
                    confidence=0.5,
                    description='File timestamps show suspicious patterns',
                    indicators=['temporal_anomaly'],
                    timestamp=datetime.utcnow(),
                    risk_level='medium'
                ))
            
        except Exception as e:
            logging.error(f"Error in metadata analysis: {str(e)}")
        
        return patterns
    
    def _analyze_file_content(self, file_path: str) -> List[BehavioralPattern]:
        """Analyze file content for behavioral patterns"""
        patterns = []
        
        try:
            with open(file_path, 'rb') as f:
                content = f.read(8192)  # Read first 8KB
            
            # Check for embedded scripts or executables
            if self._has_embedded_code(content):
                patterns.append(BehavioralPattern(
                    pattern_type='evasion_techniques',
                    confidence=0.8,
                    description='File contains embedded executable code',
                    indicators=['embedded_code'],
                    timestamp=datetime.utcnow(),
                    risk_level='high'
                ))
            
            # Check for suspicious strings
            suspicious_strings = self._extract_suspicious_strings(content)
            if suspicious_strings:
                patterns.append(BehavioralPattern(
                    pattern_type='content_indicators',
                    confidence=0.6,
                    description=f'File contains suspicious strings: {", ".join(suspicious_strings[:3])}',
                    indicators=suspicious_strings,
                    timestamp=datetime.utcnow(),
                    risk_level='medium'
                ))
            
        except Exception as e:
            logging.error(f"Error in content analysis: {str(e)}")
        
        return patterns
    
    def _analyze_scanning_patterns(self, scans: List[ScanResult]) -> List[BehavioralPattern]:
        """Analyze file scanning patterns for behavioral indicators"""
        patterns = []
        
        try:
            if len(scans) < 2:
                return patterns
            
            # Group scans by time intervals
            scan_times = [scan.scan_timestamp for scan in scans]
            scan_times.sort()
            
            # Check for rapid scanning
            rapid_scans = []
            for i in range(1, len(scan_times)):
                time_diff = scan_times[i] - scan_times[i-1]
                if time_diff.total_seconds() < 10:  # Less than 10 seconds apart
                    rapid_scans.append((scan_times[i-1], scan_times[i]))
            
            if len(rapid_scans) >= 3:
                patterns.append(BehavioralPattern(
                    pattern_type='rapid_scanning',
                    confidence=0.7,
                    description=f'Detected {len(rapid_scans)} rapid scan sequences',
                    indicators=['multiple_files', 'short_intervals'],
                    timestamp=datetime.utcnow(),
                    risk_level='medium'
                ))
            
            # Check for burst activity
            hourly_counts = defaultdict(int)
            for scan_time in scan_times:
                hour_key = scan_time.replace(minute=0, second=0, microsecond=0)
                hourly_counts[hour_key] += 1
            
            max_hourly = max(hourly_counts.values()) if hourly_counts else 0
            if max_hourly >= 10:
                patterns.append(BehavioralPattern(
                    pattern_type='time_based_patterns',
                    confidence=0.6,
                    description=f'Detected burst activity: {max_hourly} scans in one hour',
                    indicators=['burst_activity'],
                    timestamp=datetime.utcnow(),
                    risk_level='medium'
                ))
            
        except Exception as e:
            logging.error(f"Error analyzing scanning patterns: {str(e)}")
        
        return patterns
    
    def _analyze_url_patterns(self, url_scans: List[URLScan]) -> List[BehavioralPattern]:
        """Analyze URL scanning patterns for behavioral indicators"""
        patterns = []
        
        try:
            if not url_scans:
                return patterns
            
            # Analyze domain patterns
            domains = [scan.domain for scan in url_scans]
            domain_counts = defaultdict(int)
            for domain in domains:
                domain_counts[domain] += 1
            
            # Check for suspicious domain patterns
            suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq']
            suspicious_domains = [
                domain for domain in domains 
                if any(domain.endswith(tld) for tld in suspicious_tlds)
            ]
            
            if len(suspicious_domains) >= 2:
                patterns.append(BehavioralPattern(
                    pattern_type='network_indicators',
                    confidence=0.8,
                    description=f'Multiple scans of suspicious domains: {len(suspicious_domains)}',
                    indicators=['suspicious_domains'],
                    timestamp=datetime.utcnow(),
                    risk_level='high'
                ))
            
            # Check for domain generation algorithm (DGA) patterns
            if self._detect_dga_pattern(domains):
                patterns.append(BehavioralPattern(
                    pattern_type='network_indicators',
                    confidence=0.9,
                    description='Potential domain generation algorithm (DGA) pattern detected',
                    indicators=['dga_pattern'],
                    timestamp=datetime.utcnow(),
                    risk_level='critical'
                ))
            
        except Exception as e:
            logging.error(f"Error analyzing URL patterns: {str(e)}")
        
        return patterns
    
    def _analyze_activity_patterns(self, activities: List[ActivityLog]) -> List[BehavioralPattern]:
        """Analyze activity log patterns for behavioral indicators"""
        patterns = []
        
        try:
            if not activities:
                return patterns
            
            # Analyze activity timing
            activity_hours = [activity.timestamp.hour for activity in activities]
            off_hours_count = sum(1 for hour in activity_hours if hour < 6 or hour > 22)
            
            if off_hours_count > len(activities) * 0.3:  # More than 30% off-hours activity
                patterns.append(BehavioralPattern(
                    pattern_type='time_based_patterns',
                    confidence=0.5,
                    description=f'High off-hours activity: {off_hours_count}/{len(activities)}',
                    indicators=['off_hours_activity'],
                    timestamp=datetime.utcnow(),
                    risk_level='medium'
                ))
            
            # Analyze activity types
            action_counts = defaultdict(int)
            for activity in activities:
                action_counts[activity.action] += 1
            
            # Check for unusual activity ratios
            if action_counts.get('file_scan', 0) > action_counts.get('url_scan', 0) * 10:
                patterns.append(BehavioralPattern(
                    pattern_type='activity_anomaly',
                    confidence=0.6,
                    description='Disproportionate file scanning activity',
                    indicators=['activity_imbalance'],
                    timestamp=datetime.utcnow(),
                    risk_level='medium'
                ))
            
        except Exception as e:
            logging.error(f"Error analyzing activity patterns: {str(e)}")
        
        return patterns
    
    def _correlate_patterns(self, patterns: List[BehavioralPattern]) -> List[BehavioralPattern]:
        """Correlate different behavioral patterns to identify complex threats"""
        correlated_patterns = []
        
        try:
            # Group patterns by type
            pattern_groups = defaultdict(list)
            for pattern in patterns:
                pattern_groups[pattern.pattern_type].append(pattern)
            
            # Check for APT-like behavior
            if (len(pattern_groups.get('evasion_techniques', [])) >= 1 and
                len(pattern_groups.get('time_based_patterns', [])) >= 1 and
                len(pattern_groups.get('network_indicators', [])) >= 1):
                
                correlated_patterns.append(BehavioralPattern(
                    pattern_type='apt_indicators',
                    confidence=0.8,
                    description='Behavior pattern consistent with Advanced Persistent Threat (APT)',
                    indicators=['evasion', 'persistence', 'network_activity'],
                    timestamp=datetime.utcnow(),
                    risk_level='critical'
                ))
            
            # Check for ransomware-like behavior
            if (len(pattern_groups.get('rapid_scanning', [])) >= 1 and
                len(pattern_groups.get('suspicious_extensions', [])) >= 1):
                
                correlated_patterns.append(BehavioralPattern(
                    pattern_type='ransomware_patterns',
                    confidence=0.7,
                    description='Behavior pattern consistent with ransomware activity',
                    indicators=['rapid_file_access', 'suspicious_extensions'],
                    timestamp=datetime.utcnow(),
                    risk_level='critical'
                ))
            
        except Exception as e:
            logging.error(f"Error correlating patterns: {str(e)}")
        
        return correlated_patterns
    
    # Helper methods
    def _has_suspicious_extension(self, filename: str) -> bool:
        """Check if filename has suspicious extension patterns"""
        suspicious_patterns = [
            '.pdf.exe', '.doc.exe', '.jpg.exe', '.txt.scr',
            '.mp3.exe', '.avi.exe', '.zip.exe'
        ]
        
        filename_lower = filename.lower()
        return any(pattern in filename_lower for pattern in suspicious_patterns)
    
    def _has_size_anomaly(self, file_size: int, filename: str) -> bool:
        """Check if file size is anomalous for its apparent type"""
        extension = os.path.splitext(filename)[1].lower()
        
        # Define expected size ranges for different file types
        size_ranges = {
            '.txt': (0, 1024 * 1024),  # 0 to 1MB
            '.jpg': (1024, 10 * 1024 * 1024),  # 1KB to 10MB
            '.pdf': (1024, 50 * 1024 * 1024),  # 1KB to 50MB
            '.exe': (1024, 100 * 1024 * 1024),  # 1KB to 100MB
        }
        
        if extension in size_ranges:
            min_size, max_size = size_ranges[extension]
            return not (min_size <= file_size <= max_size)
        
        return False
    
    def _is_potentially_packed(self, scan_results: Dict[str, Any]) -> bool:
        """Check if file shows signs of packing or obfuscation"""
        # High entropy might indicate packing
        if 'entropy' in scan_results:
            return scan_results['entropy'] > 7.5
        return False
    
    def _has_temporal_anomaly(self, creation_time: datetime, modification_time: datetime) -> bool:
        """Check for suspicious timestamp patterns"""
        # Check if modification time is before creation time
        if modification_time < creation_time:
            return True
        
        # Check if timestamps are too far in the future
        now = datetime.now()
        if creation_time > now or modification_time > now:
            return True
        
        return False
    
    def _has_embedded_code(self, content: bytes) -> bool:
        """Check for embedded executable code in file content"""
        # Look for common executable signatures
        exe_signatures = [
            b'MZ',  # DOS/Windows executable
            b'\x7fELF',  # ELF executable
            b'\xca\xfe\xba\xbe',  # Mach-O executable
            b'#!/bin/',  # Shell script
            b'<script',  # JavaScript
            b'<%',  # Server-side script
        ]
        
        return any(sig in content for sig in exe_signatures)
    
    def _extract_suspicious_strings(self, content: bytes) -> List[str]:
        """Extract suspicious strings from file content"""
        suspicious_keywords = [
            'password', 'admin', 'root', 'backdoor', 'keylog',
            'stealth', 'inject', 'exploit', 'payload', 'shell',
            'trojan', 'virus', 'malware', 'bitcoin', 'crypto'
        ]
        
        try:
            # Convert to string and search for keywords
            content_str = content.decode('utf-8', errors='ignore').lower()
            found_strings = [keyword for keyword in suspicious_keywords if keyword in content_str]
            return found_strings[:5]  # Return up to 5 matches
        except:
            return []
    
    def _detect_dga_pattern(self, domains: List[str]) -> bool:
        """Detect domain generation algorithm patterns"""
        if len(domains) < 3:
            return False
        
        # Check for common DGA characteristics
        dga_indicators = 0
        
        for domain in domains:
            # Remove TLD for analysis
            domain_name = domain.split('.')[0] if '.' in domain else domain
            
            # Check length (DGA domains often have specific lengths)
            if 8 <= len(domain_name) <= 15:
                dga_indicators += 1
            
            # Check for lack of vowels (some DGAs generate consonant-heavy domains)
            vowels = 'aeiou'
            vowel_ratio = sum(1 for char in domain_name.lower() if char in vowels) / len(domain_name)
            if vowel_ratio < 0.2:
                dga_indicators += 1
            
            # Check for randomness (high entropy in domain name)
            if len(set(domain_name)) > len(domain_name) * 0.6:
                dga_indicators += 1
        
        # If more than 60% of domains show DGA indicators, likely DGA
        return dga_indicators > len(domains) * 0.6
    
    def get_behavioral_risk_score(self, patterns: List[BehavioralPattern]) -> float:
        """Calculate overall behavioral risk score based on detected patterns"""
        if not patterns:
            return 0.0
        
        # Weight patterns by risk level and confidence
        risk_weights = {
            'low': 0.2,
            'medium': 0.5,
            'high': 0.8,
            'critical': 1.0
        }
        
        total_score = 0.0
        pattern_count = 0
        
        for pattern in patterns:
            weight = risk_weights.get(pattern.risk_level, 0.5)
            confidence = pattern.confidence
            
            # Get pattern-specific multiplier
            pattern_info = self.behavioral_patterns.get(pattern.pattern_type, {})
            multiplier = pattern_info.get('risk_multiplier', 1.0)
            
            total_score += weight * confidence * multiplier
            pattern_count += 1
        
        if pattern_count == 0:
            return 0.0
        
        # Normalize score and apply diminishing returns
        base_score = total_score / pattern_count
        normalized_score = min(base_score, 1.0)
        
        # Apply pattern diversity bonus
        unique_pattern_types = len(set(p.pattern_type for p in patterns))
        diversity_bonus = min(unique_pattern_types * 0.1, 0.3)
        
        final_score = min(normalized_score + diversity_bonus, 1.0)
        return final_score
    
    def generate_behavioral_report(self, patterns: List[BehavioralPattern]) -> Dict[str, Any]:
        """Generate a comprehensive behavioral analysis report"""
        if not patterns:
            return {
                'overall_risk': 'low',
                'risk_score': 0.0,
                'patterns_detected': 0,
                'summary': 'No behavioral patterns detected',
                'recommendations': ['Continue monitoring for unusual activity']
            }
        
        risk_score = self.get_behavioral_risk_score(patterns)
        
        # Determine overall risk level
        if risk_score >= 0.8:
            overall_risk = 'critical'
        elif risk_score >= 0.6:
            overall_risk = 'high'
        elif risk_score >= 0.4:
            overall_risk = 'medium'
        else:
            overall_risk = 'low'
        
        # Group patterns by type for summary
        pattern_summary = defaultdict(int)
        critical_patterns = []
        
        for pattern in patterns:
            pattern_summary[pattern.pattern_type] += 1
            if pattern.risk_level == 'critical':
                critical_patterns.append(pattern.description)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(patterns, risk_score)
        
        return {
            'overall_risk': overall_risk,
            'risk_score': round(risk_score, 3),
            'patterns_detected': len(patterns),
            'pattern_types': dict(pattern_summary),
            'critical_patterns': critical_patterns,
            'summary': self._generate_summary(patterns, overall_risk),
            'recommendations': recommendations,
            'analysis_timestamp': datetime.utcnow().isoformat()
        }
    
    def _generate_summary(self, patterns: List[BehavioralPattern], risk_level: str) -> str:
        """Generate a human-readable summary of behavioral analysis"""
        if not patterns:
            return "No suspicious behavioral patterns detected"
        
        pattern_types = set(p.pattern_type for p in patterns)
        critical_count = sum(1 for p in patterns if p.risk_level == 'critical')
        
        summary = f"Detected {len(patterns)} behavioral pattern(s) across {len(pattern_types)} categories. "
        
        if critical_count > 0:
            summary += f"{critical_count} critical pattern(s) require immediate attention. "
        
        if 'apt_indicators' in pattern_types:
            summary += "Advanced Persistent Threat (APT) behavior detected. "
        elif 'ransomware_patterns' in pattern_types:
            summary += "Ransomware-like behavior patterns identified. "
        elif 'evasion_techniques' in pattern_types:
            summary += "Evasion techniques detected, indicating sophisticated malware. "
        
        summary += f"Overall risk assessment: {risk_level.upper()}."
        
        return summary
    
    def _generate_recommendations(self, patterns: List[BehavioralPattern], risk_score: float) -> List[str]:
        """Generate security recommendations based on detected patterns"""
        recommendations = []
        
        pattern_types = set(p.pattern_type for p in patterns)
        
        # General recommendations based on risk score
        if risk_score >= 0.8:
            recommendations.append("URGENT: Isolate affected systems immediately")
            recommendations.append("Conduct full system forensics analysis")
            recommendations.append("Review security policies and access controls")
        elif risk_score >= 0.6:
            recommendations.append("Quarantine suspicious files and monitor system closely")
            recommendations.append("Run additional security scans")
            recommendations.append("Review recent system changes and user activities")
        elif risk_score >= 0.4:
            recommendations.append("Continue monitoring and consider additional security measures")
            recommendations.append("Update threat detection signatures")
        
        # Specific recommendations based on pattern types
        if 'rapid_scanning' in pattern_types:
            recommendations.append("Implement rate limiting for file scanning operations")
        
        if 'suspicious_extensions' in pattern_types:
            recommendations.append("Enhance file extension validation and filtering")
        
        if 'network_indicators' in pattern_types:
            recommendations.append("Monitor network traffic for suspicious connections")
            recommendations.append("Consider implementing DNS filtering")
        
        if 'evasion_techniques' in pattern_types:
            recommendations.append("Deploy advanced anti-evasion detection tools")
            recommendations.append("Consider behavior-based detection systems")
        
        if 'apt_indicators' in pattern_types:
            recommendations.append("Engage incident response team immediately")
            recommendations.append("Preserve evidence for forensic analysis")
            recommendations.append("Review and update threat intelligence feeds")
        
        return recommendations


# Initialize the behavioral analysis engine
behavioral_engine = BehavioralAnalysisEngine()