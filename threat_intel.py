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
        """Check URL against VirusTotal API"""
        try:
            if not self.virustotal_key:
                return {'is_threat': False, 'details': 'API key not configured'}
            
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
                    
                    is_threat = positives > 0
                    return {
                        'is_threat': is_threat,
                        'details': f"{positives}/{total} engines detected threats" if is_threat else 'Clean',
                        'positives': positives,
                        'total': total,
                        'source': 'VirusTotal'
                    }
                else:
                    return {'is_threat': False, 'details': 'Not found in VirusTotal database'}
            else:
                logging.warning(f"VirusTotal API error: {response.status_code}")
                return {'is_threat': False, 'details': 'API error'}
            
        except Exception as e:
            logging.error(f"VirusTotal check error: {str(e)}")
            return {'is_threat': False, 'details': 'Check failed'}
    
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
