import requests
import json
import logging
import os
from urllib.parse import urlparse
import hashlib
import time

class ThreatIntelligence:
    """Threat intelligence integration for URL and domain analysis"""
    
    def __init__(self):
        # API Keys from environment variables
        self.google_safe_browsing_key = os.environ.get('GOOGLE_SAFE_BROWSING_API_KEY', '')
        self.virustotal_key = os.environ.get('VIRUSTOTAL_API_KEY', '')
        self.phishtank_key = os.environ.get('PHISHTANK_API_KEY', '')
        
        # API endpoints
        self.google_sb_url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
        self.virustotal_url = "https://www.virustotal.com/vtapi/v2/url/report"
        self.phishtank_url = "http://checkurl.phishtank.com/checkurl/"
        
        # Cache for API responses (simple in-memory cache)
        self.cache = {}
        self.cache_ttl = 3600  # 1 hour
    
    def analyze_url(self, url):
        """Analyze URL for threats using multiple threat intelligence sources"""
        try:
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            
            result = {
                'url': url,
                'domain': domain,
                'risk_score': 0.0,
                'threat_level': 'safe',
                'detection_details': [],
                'threat_intel_data': {}
            }
            
            # Check cache first
            cache_key = hashlib.md5(url.encode()).hexdigest()
            if cache_key in self.cache:
                cached_result = self.cache[cache_key]
                if time.time() - cached_result['timestamp'] < self.cache_ttl:
                    return cached_result['data']
            
            threat_sources = []
            
            # Google Safe Browsing check
            if self.google_safe_browsing_key:
                gsb_result = self.check_google_safe_browsing(url)
                if gsb_result['is_threat']:
                    threat_sources.append('Google Safe Browsing')
                    result['threat_intel_data']['google_safe_browsing'] = gsb_result
            
            # VirusTotal check
            if self.virustotal_key:
                vt_result = self.check_virustotal(url)
                if vt_result['is_threat']:
                    threat_sources.append('VirusTotal')
                    result['threat_intel_data']['virustotal'] = vt_result
            
            # PhishTank check
            if self.phishtank_key:
                pt_result = self.check_phishtank(url)
                if pt_result['is_threat']:
                    threat_sources.append('PhishTank')
                    result['threat_intel_data']['phishtank'] = pt_result
            
            # Basic URL analysis (heuristics)
            heuristic_result = self.analyze_url_heuristics(url)
            if heuristic_result['suspicious']:
                result['detection_details'].extend(heuristic_result['reasons'])
            
            # Calculate risk score and threat level
            threat_count = len(threat_sources)
            heuristic_score = heuristic_result.get('score', 0)
            
            if threat_count >= 2:
                result['risk_score'] = 0.9 + (threat_count * 0.02)
                result['threat_level'] = 'malicious'
            elif threat_count == 1:
                result['risk_score'] = 0.7 + heuristic_score
                result['threat_level'] = 'suspicious'
            elif heuristic_score > 0.3:
                result['risk_score'] = heuristic_score
                result['threat_level'] = 'suspicious'
            else:
                result['risk_score'] = 0.1 + heuristic_score
                result['threat_level'] = 'safe'
            
            # Ensure risk score doesn't exceed 1.0
            result['risk_score'] = min(result['risk_score'], 1.0)
            
            if threat_sources:
                result['detection_details'].append(f"Flagged by: {', '.join(threat_sources)}")
            
            # Cache the result
            self.cache[cache_key] = {
                'data': result,
                'timestamp': time.time()
            }
            
            return result
            
        except Exception as e:
            logging.error(f"Error analyzing URL {url}: {str(e)}")
            return {
                'url': url,
                'domain': urlparse(url).netloc,
                'risk_score': 0.5,
                'threat_level': 'unknown',
                'detection_details': ['Error during analysis'],
                'threat_intel_data': {}
            }
    
    def check_google_safe_browsing(self, url):
        """Check URL against Google Safe Browsing API"""
        try:
            if not self.google_safe_browsing_key:
                return {'is_threat': False, 'details': 'API key not configured'}
            
            payload = {
                "client": {
                    "clientId": "SmartFileGuardian",
                    "clientVersion": "1.0"
                },
                "threatInfo": {
                    "threatTypes": [
                        "MALWARE",
                        "SOCIAL_ENGINEERING",
                        "UNWANTED_SOFTWARE",
                        "POTENTIALLY_HARMFUL_APPLICATION"
                    ],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}]
                }
            }
            
            response = requests.post(
                f"{self.google_sb_url}?key={self.google_safe_browsing_key}",
                json=payload,
                timeout=10
            )
            
            if response.status_code == 200:
                result = response.json()
                is_threat = 'matches' in result and len(result['matches']) > 0
                return {
                    'is_threat': is_threat,
                    'details': result if is_threat else 'Clean',
                    'source': 'Google Safe Browsing'
                }
            else:
                logging.warning(f"Google Safe Browsing API error: {response.status_code}")
                return {'is_threat': False, 'details': 'API error'}
            
        except Exception as e:
            logging.error(f"Google Safe Browsing check error: {str(e)}")
            return {'is_threat': False, 'details': 'Check failed'}
    
    def check_virustotal(self, url):
        """Check URL against VirusTotal API with enhanced v3 support"""
        try:
            if not self.virustotal_key:
                return {'is_threat': False, 'details': 'API key not configured'}
            
            # Try v3 API first, fallback to v2
            result = self.check_virustotal_v3_url(url)
            if result.get('api_success'):
                return result
            
            return self.check_virustotal_v2_url(url)
            
        except Exception as e:
            logging.error(f"VirusTotal check error: {str(e)}")
            return {'is_threat': False, 'details': 'Check failed'}
    
    def check_virustotal_v3_url(self, url):
        """Check URL using VirusTotal v3 API"""
        try:
            import base64
            
            # Encode URL for v3 API
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            
            headers = {
                'x-apikey': self.virustotal_key,
                'Content-Type': 'application/json'
            }
            
            # Get analysis results
            analysis_url = f"{self.virustotal_url_v3}/{url_id}"
            response = requests.get(analysis_url, headers=headers, timeout=15)
            
            if response.status_code == 200:
                data = response.json()
                
                if 'data' in data and 'attributes' in data['data']:
                    attributes = data['data']['attributes']
                    stats = attributes.get('last_analysis_stats', {})
                    
                    malicious = stats.get('malicious', 0)
                    suspicious = stats.get('suspicious', 0)
                    harmless = stats.get('harmless', 0)
                    undetected = stats.get('undetected', 0)
                    total_scans = malicious + suspicious + harmless + undetected
                    
                    # Get threat engine details
                    engines_data = attributes.get('last_analysis_results', {})
                    threat_engines = []
                    for name, result in engines_data.items():
                        if result.get('category') in ['malicious', 'suspicious']:
                            engine_result = result.get('result', 'flagged')
                            threat_engines.append(f"{name}: {engine_result}")
                    
                    is_threat = malicious > 0 or suspicious > 3
                    threat_score = (malicious + suspicious * 0.5) / max(total_scans, 1)
                    
                    return {
                        'api_success': True,
                        'is_threat': is_threat,
                        'details': f'VT v3: {malicious} malicious, {suspicious} suspicious ({total_scans} engines)',
                        'malicious_count': malicious,
                        'suspicious_count': suspicious,
                        'harmless_count': harmless,
                        'total_engines': total_scans,
                        'threat_score': threat_score,
                        'threat_engines': threat_engines[:5],  # Top 5 engines
                        'scan_date': attributes.get('last_analysis_date', ''),
                        'reputation': attributes.get('reputation', 0),
                        'source': 'VirusTotal v3'
                    }
            
            # If URL not found, try submitting for analysis
            elif response.status_code == 404:
                submit_result = self.submit_url_to_virustotal(url)
                if submit_result.get('success'):
                    return {
                        'api_success': True,
                        'is_threat': False,
                        'details': 'URL submitted for analysis - check back later',
                        'analysis_id': submit_result.get('analysis_id'),
                        'source': 'VirusTotal v3'
                    }
            
            return {'api_success': False}
                
        except Exception as e:
            logging.error(f"VirusTotal v3 API error: {str(e)}")
            return {'api_success': False}
    
    def check_virustotal_v2_url(self, url):
        """Fallback to VirusTotal v2 API for URL checking"""
        try:
            params = {
                'apikey': self.virustotal_key,
                'resource': url
            }
            
            response = requests.get(self.virustotal_url, params=params, timeout=10)
            
            if response.status_code == 200:
                result = response.json()
                
                if result.get('response_code') == 1:
                    positives = result.get('positives', 0)
                    total = result.get('total', 0)
                    
                    return {
                        'api_success': True,
                        'is_threat': positives > 0,
                        'details': f'VT v2: {positives}/{total} engines detected threats',
                        'positives': positives,
                        'total': total,
                        'threat_score': positives / max(total, 1),
                        'source': 'VirusTotal v2'
                    }
                else:
                    return {
                        'api_success': True,
                        'is_threat': False,
                        'details': 'URL not found in VirusTotal database'
                    }
            else:
                logging.warning(f"VirusTotal v2 API error: {response.status_code}")
                return {'api_success': False}
                
        except Exception as e:
            logging.error(f"VirusTotal v2 API error: {str(e)}")
            return {'api_success': False}
    
    def submit_url_to_virustotal(self, url):
        """Submit URL to VirusTotal for analysis"""
        try:
            headers = {
                'x-apikey': self.virustotal_key,
                'Content-Type': 'application/json'
            }
            
            submit_data = {'url': url}
            response = requests.post(self.virustotal_url_v3, json=submit_data, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                analysis_id = data.get('data', {}).get('id', '')
                
                return {
                    'success': True,
                    'analysis_id': analysis_id,
                    'details': 'URL submitted for analysis'
                }
            else:
                return {
                    'success': False,
                    'details': f'Submit failed: {response.status_code}'
                }
                
        except Exception as e:
            logging.error(f"VirusTotal URL submit error: {str(e)}")
            return {'success': False, 'details': f'Submit error: {str(e)}'}
    
    def check_phishtank(self, url):
        """Check URL against PhishTank API"""
        try:
            if not self.phishtank_key:
                return {'is_threat': False, 'details': 'API key not configured'}
            
            data = {
                'url': url,
                'format': 'json',
                'app_key': self.phishtank_key
            }
            
            response = requests.post(self.phishtank_url, data=data, timeout=10)
            
            if response.status_code == 200:
                result = response.json()
                
                if result.get('results'):
                    is_phish = result['results'].get('in_database', False)
                    return {
                        'is_threat': is_phish,
                        'details': 'Phishing site detected' if is_phish else 'Not in phishing database',
                        'source': 'PhishTank'
                    }
                else:
                    return {'is_threat': False, 'details': 'Not found in PhishTank database'}
            else:
                logging.warning(f"PhishTank API error: {response.status_code}")
                return {'is_threat': False, 'details': 'API error'}
            
        except Exception as e:
            logging.error(f"PhishTank check error: {str(e)}")
            return {'is_threat': False, 'details': 'Check failed'}
    
    def analyze_url_heuristics(self, url):
        """Perform heuristic analysis of URL structure"""
        suspicious_reasons = []
        score = 0.0
        
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            path = parsed.path.lower()
            
            # Check for suspicious domain patterns
            if len(domain.split('.')) > 4:
                suspicious_reasons.append("Suspicious subdomain structure")
                score += 0.2
            
            # Check for suspicious TLDs
            suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.bit']
            if any(domain.endswith(tld) for tld in suspicious_tlds):
                suspicious_reasons.append("Suspicious top-level domain")
                score += 0.3
            
            # Check for IP addresses instead of domains
            import re
            ip_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
            if re.match(ip_pattern, domain):
                suspicious_reasons.append("Using IP address instead of domain")
                score += 0.4
            
            # Check for suspicious keywords in URL
            suspicious_keywords = [
                'login', 'verify', 'secure', 'update', 'confirm',
                'account', 'suspended', 'limited', 'paypal', 'bank'
            ]
            
            url_lower = url.lower()
            found_keywords = [kw for kw in suspicious_keywords if kw in url_lower]
            if found_keywords:
                suspicious_reasons.append(f"Contains suspicious keywords: {', '.join(found_keywords)}")
                score += len(found_keywords) * 0.1
            
            # Check for URL shortening services
            shortening_services = [
                'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'short.link',
                'ow.ly', 'is.gd', 'buff.ly'
            ]
            
            if any(service in domain for service in shortening_services):
                suspicious_reasons.append("URL shortening service detected")
                score += 0.2
            
            # Check for excessive URL length
            if len(url) > 200:
                suspicious_reasons.append("Unusually long URL")
                score += 0.1
            
            return {
                'suspicious': len(suspicious_reasons) > 0,
                'reasons': suspicious_reasons,
                'score': min(score, 1.0)
            }
            
        except Exception as e:
            logging.error(f"Error in heuristic analysis: {str(e)}")
            return {'suspicious': False, 'reasons': [], 'score': 0.0}
    
    def check_virustotal_file_hash(self, file_hash):
        """Check file hash against VirusTotal using v3 API"""
        try:
            if not self.virustotal_key or not file_hash:
                return {'is_threat': False, 'details': 'API key or hash not available'}
            
            headers = {'x-apikey': self.virustotal_key}
            
            # Check file hash
            analysis_url = f"{self.virustotal_file_v3}/{file_hash}"
            response = requests.get(analysis_url, headers=headers, timeout=15)
            
            if response.status_code == 200:
                data = response.json()
                
                if 'data' in data and 'attributes' in data['data']:
                    attributes = data['data']['attributes']
                    stats = attributes.get('last_analysis_stats', {})
                    
                    malicious = stats.get('malicious', 0)
                    suspicious = stats.get('suspicious', 0)
                    undetected = stats.get('undetected', 0)
                    harmless = stats.get('harmless', 0)
                    total_scans = malicious + suspicious + undetected + harmless
                    
                    # Get threat names from engines
                    engines_data = attributes.get('last_analysis_results', {})
                    threat_names = []
                    threat_engines = []
                    
                    for engine, result in engines_data.items():
                        if result.get('category') == 'malicious':
                            threat_result = result.get('result', 'malware')
                            if threat_result and threat_result.lower() not in ['none', 'null']:
                                threat_names.append(threat_result)
                                threat_engines.append(f"{engine}: {threat_result}")
                    
                    is_threat = malicious > 0
                    threat_score = malicious / max(total_scans, 1)
                    
                    # Get file metadata
                    file_type = attributes.get('type_description', 'Unknown')
                    file_size = attributes.get('size', 0)
                    first_seen = attributes.get('first_submission_date', '')
                    
                    # Extract unique threat families
                    unique_threats = list(set(threat_names))[:5]  # Top 5 unique threats
                    
                    result = {
                        'is_threat': is_threat,
                        'details': f'VT File: {malicious}/{total_scans} engines detected malware',
                        'malicious_count': malicious,
                        'suspicious_count': suspicious,
                        'harmless_count': harmless,
                        'total_engines': total_scans,
                        'threat_score': threat_score,
                        'threat_names': unique_threats,
                        'threat_engines': threat_engines[:5],
                        'file_type': file_type,
                        'file_size': file_size,
                        'first_seen': first_seen,
                        'reputation': attributes.get('reputation', 0),
                        'scan_date': attributes.get('last_analysis_date', ''),
                        'source': 'VirusTotal File Analysis'
                    }
                    
                    # Add severity assessment
                    if malicious > 10:
                        result['severity'] = 'critical'
                    elif malicious > 5:
                        result['severity'] = 'high'
                    elif malicious > 0:
                        result['severity'] = 'medium'
                    elif suspicious > 5:
                        result['severity'] = 'low'
                    else:
                        result['severity'] = 'clean'
                    
                    return result
                    
            elif response.status_code == 404:
                return {
                    'is_threat': False,
                    'details': 'File hash not found in VirusTotal database',
                    'hash_unknown': True,
                    'recommendation': 'consider_upload'
                }
            else:
                return {
                    'is_threat': False,
                    'details': f'VirusTotal API error: {response.status_code}'
                }
                
        except Exception as e:
            logging.error(f"VirusTotal file hash API error: {str(e)}")
            return {'is_threat': False, 'details': f'Error: {str(e)}'}
    
    def analyze_file_with_virustotal(self, file_path, file_hash):
        """Comprehensive file analysis using VirusTotal"""
        try:
            result = {
                'virustotal_analysis': None,
                'recommendation': 'unknown',
                'enhanced_data': {}
            }
            
            # Check if file hash exists in VT database
            logging.info(f"Checking file hash in VirusTotal: {file_hash[:16]}...")
            vt_result = self.check_virustotal_file_hash(file_hash)
            result['virustotal_analysis'] = vt_result
            
            if vt_result.get('hash_unknown', False):
                result['recommendation'] = 'hash_unknown'
                result['enhanced_data']['can_upload'] = os.path.exists(file_path) and os.path.getsize(file_path) <= 32 * 1024 * 1024
            else:
                # File exists in VT database
                malicious_count = vt_result.get('malicious_count', 0)
                suspicious_count = vt_result.get('suspicious_count', 0)
                severity = vt_result.get('severity', 'unknown')
                
                if malicious_count > 0:
                    if severity in ['critical', 'high']:
                        result['recommendation'] = 'quarantine_immediately'
                    else:
                        result['recommendation'] = 'quarantine_recommended'
                    
                    # Add threat intelligence
                    result['enhanced_data'].update({
                        'threat_families': vt_result.get('threat_names', []),
                        'detection_engines': vt_result.get('threat_engines', []),
                        'threat_severity': severity
                    })
                elif suspicious_count > 5:
                    result['recommendation'] = 'suspicious_monitor'
                    result['enhanced_data']['suspicious_engines'] = suspicious_count
                else:
                    result['recommendation'] = 'likely_safe'
                    result['enhanced_data']['clean_reputation'] = vt_result.get('reputation', 0)
                
                # Add file intelligence
                result['enhanced_data'].update({
                    'file_type': vt_result.get('file_type', 'Unknown'),
                    'first_seen': vt_result.get('first_seen', ''),
                    'total_engines': vt_result.get('total_engines', 0)
                })
            
            return result
            
        except Exception as e:
            logging.error(f"Error in VirusTotal file analysis: {str(e)}")
            return {
                'virustotal_analysis': {'error': str(e)},
                'recommendation': 'analysis_error'
            }
