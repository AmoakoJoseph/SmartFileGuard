import os
import logging
import json
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from enum import Enum
from app import db
from db_models import ScanResult, URLScan, ActivityLog, QuarantineItem

class ConsentType(Enum):
    """Types of user consent"""
    DATA_PROCESSING = "data_processing"
    ANALYTICS = "analytics"
    MARKETING = "marketing"
    THIRD_PARTY_SHARING = "third_party_sharing"

class DataCategory(Enum):
    """Categories of personal data"""
    SCAN_DATA = "scan_data"
    ACTIVITY_LOGS = "activity_logs"
    IP_ADDRESSES = "ip_addresses"
    USER_AGENTS = "user_agents"
    FILE_METADATA = "file_metadata"

@dataclass
class UserConsent:
    """User consent record"""
    user_id: str
    consent_type: ConsentType
    granted: bool
    timestamp: datetime
    ip_address: str
    version: str  # Privacy policy version
    expires_at: Optional[datetime] = None

@dataclass
class DataRetentionPolicy:
    """Data retention policy definition"""
    category: DataCategory
    retention_days: int
    deletion_method: str
    exceptions: List[str]

@dataclass
class PrivacyRequest:
    """Privacy-related user request"""
    request_id: str
    user_identifier: str  # IP address or user ID
    request_type: str  # access, deletion, portability
    status: str
    created_at: datetime
    processed_at: Optional[datetime]
    data_provided: Optional[str]

class GDPRComplianceManager:
    """GDPR/CCPA compliance management system"""
    
    def __init__(self):
        self.consent_storage_path = 'data/consent_records.json'
        self.privacy_requests_path = 'data/privacy_requests.json'
        self.data_exports_path = 'data/exports'
        
        # Create necessary directories
        os.makedirs('data', exist_ok=True)
        os.makedirs(self.data_exports_path, exist_ok=True)
        
        # Default data retention policies
        self.retention_policies = {
            DataCategory.SCAN_DATA: DataRetentionPolicy(
                category=DataCategory.SCAN_DATA,
                retention_days=90,
                deletion_method='permanent',
                exceptions=['legal_hold', 'security_investigation']
            ),
            DataCategory.ACTIVITY_LOGS: DataRetentionPolicy(
                category=DataCategory.ACTIVITY_LOGS,
                retention_days=365,
                deletion_method='anonymization',
                exceptions=['security_investigation', 'compliance_audit']
            ),
            DataCategory.IP_ADDRESSES: DataRetentionPolicy(
                category=DataCategory.IP_ADDRESSES,
                retention_days=30,
                deletion_method='anonymization',
                exceptions=['security_investigation']
            ),
            DataCategory.USER_AGENTS: DataRetentionPolicy(
                category=DataCategory.USER_AGENTS,
                retention_days=30,
                deletion_method='anonymization',
                exceptions=['security_investigation']
            ),
            DataCategory.FILE_METADATA: DataRetentionPolicy(
                category=DataCategory.FILE_METADATA,
                retention_days=180,
                deletion_method='permanent',
                exceptions=['quarantine_required']
            )
        }
        
        # Privacy policy versions
        self.current_privacy_version = os.environ.get('PRIVACY_POLICY_VERSION', '1.0')
        
        # Load existing consent records and privacy requests
        self.consent_records = self._load_consent_records()
        self.privacy_requests = self._load_privacy_requests()
    
    def record_consent(self, user_id: str, consent_type: ConsentType, 
                      granted: bool, ip_address: str, 
                      expires_at: Optional[datetime] = None) -> bool:
        """Record user consent"""
        try:
            consent = UserConsent(
                user_id=user_id,
                consent_type=consent_type,
                granted=granted,
                timestamp=datetime.utcnow(),
                ip_address=self._anonymize_ip(ip_address),
                version=self.current_privacy_version,
                expires_at=expires_at
            )
            
            # Store consent record
            consent_key = f"{user_id}_{consent_type.value}"
            self.consent_records[consent_key] = asdict(consent)
            
            # Save to file
            self._save_consent_records()
            
            logging.info(f"Consent recorded: {user_id} - {consent_type.value} - {granted}")
            return True
            
        except Exception as e:
            logging.error(f"Error recording consent: {str(e)}")
            return False
    
    def check_consent(self, user_id: str, consent_type: ConsentType) -> bool:
        """Check if user has granted specific consent"""
        try:
            consent_key = f"{user_id}_{consent_type.value}"
            consent_record = self.consent_records.get(consent_key)
            
            if not consent_record:
                return False
            
            # Check if consent is still valid
            if consent_record.get('expires_at'):
                expires_at = datetime.fromisoformat(consent_record['expires_at'])
                if datetime.utcnow() > expires_at:
                    return False
            
            return consent_record.get('granted', False)
            
        except Exception as e:
            logging.error(f"Error checking consent: {str(e)}")
            return False
    
    def handle_data_access_request(self, user_identifier: str) -> str:
        """Handle user request for data access (GDPR Article 15)"""
        try:
            request_id = self._generate_request_id()
            
            # Create privacy request record
            privacy_request = PrivacyRequest(
                request_id=request_id,
                user_identifier=self._anonymize_ip(user_identifier),
                request_type='data_access',
                status='processing',
                created_at=datetime.utcnow(),
                processed_at=None,
                data_provided=None
            )
            
            # Store request
            self.privacy_requests[request_id] = asdict(privacy_request)
            self._save_privacy_requests()
            
            # Collect user data
            user_data = self._collect_user_data(user_identifier)
            
            # Export data to file
            export_filename = f"data_export_{request_id}.json"
            export_path = os.path.join(self.data_exports_path, export_filename)
            
            with open(export_path, 'w') as f:
                json.dump(user_data, f, indent=2, default=str)
            
            # Update request status
            privacy_request.status = 'completed'
            privacy_request.processed_at = datetime.utcnow()
            privacy_request.data_provided = export_path
            
            self.privacy_requests[request_id] = asdict(privacy_request)
            self._save_privacy_requests()
            
            logging.info(f"Data access request completed: {request_id}")
            return request_id
            
        except Exception as e:
            logging.error(f"Error handling data access request: {str(e)}")
            return None
    
    def handle_data_deletion_request(self, user_identifier: str) -> str:
        """Handle user request for data deletion (GDPR Article 17)"""
        try:
            request_id = self._generate_request_id()
            
            # Create privacy request record
            privacy_request = PrivacyRequest(
                request_id=request_id,
                user_identifier=self._anonymize_ip(user_identifier),
                request_type='data_deletion',
                status='processing',
                created_at=datetime.utcnow(),
                processed_at=None,
                data_provided=None
            )
            
            # Store request
            self.privacy_requests[request_id] = asdict(privacy_request)
            self._save_privacy_requests()
            
            # Perform data deletion
            deletion_summary = self._delete_user_data(user_identifier)
            
            # Update request status
            privacy_request.status = 'completed'
            privacy_request.processed_at = datetime.utcnow()
            privacy_request.data_provided = json.dumps(deletion_summary)
            
            self.privacy_requests[request_id] = asdict(privacy_request)
            self._save_privacy_requests()
            
            logging.info(f"Data deletion request completed: {request_id}")
            return request_id
            
        except Exception as e:
            logging.error(f"Error handling data deletion request: {str(e)}")
            return None
    
    def handle_data_portability_request(self, user_identifier: str) -> str:
        """Handle user request for data portability (GDPR Article 20)"""
        try:
            request_id = self._generate_request_id()
            
            # Create privacy request record
            privacy_request = PrivacyRequest(
                request_id=request_id,
                user_identifier=self._anonymize_ip(user_identifier),
                request_type='data_portability',
                status='processing',
                created_at=datetime.utcnow(),
                processed_at=None,
                data_provided=None
            )
            
            # Store request
            self.privacy_requests[request_id] = asdict(privacy_request)
            self._save_privacy_requests()
            
            # Collect portable data
            portable_data = self._collect_portable_data(user_identifier)
            
            # Export in machine-readable format (JSON)
            export_filename = f"portable_data_{request_id}.json"
            export_path = os.path.join(self.data_exports_path, export_filename)
            
            with open(export_path, 'w') as f:
                json.dump(portable_data, f, indent=2, default=str)
            
            # Update request status
            privacy_request.status = 'completed'
            privacy_request.processed_at = datetime.utcnow()
            privacy_request.data_provided = export_path
            
            self.privacy_requests[request_id] = asdict(privacy_request)
            self._save_privacy_requests()
            
            logging.info(f"Data portability request completed: {request_id}")
            return request_id
            
        except Exception as e:
            logging.error(f"Error handling data portability request: {str(e)}")
            return None
    
    def run_automated_data_cleanup(self) -> Dict[str, int]:
        """Run automated data cleanup based on retention policies"""
        cleanup_summary = {
            'scan_results_deleted': 0,
            'url_scans_deleted': 0,
            'activity_logs_anonymized': 0,
            'quarantine_items_reviewed': 0
        }
        
        try:
            current_time = datetime.utcnow()
            
            # Clean up scan results
            scan_retention_days = self.retention_policies[DataCategory.SCAN_DATA].retention_days
            scan_cutoff = current_time - timedelta(days=scan_retention_days)
            
            old_scans = ScanResult.query.filter(
                ScanResult.scan_timestamp < scan_cutoff,
                ScanResult.quarantined == False  # Don't delete quarantined files
            ).all()
            
            for scan in old_scans:
                db.session.delete(scan)
                cleanup_summary['scan_results_deleted'] += 1
            
            # Clean up URL scans
            old_url_scans = URLScan.query.filter(
                URLScan.scan_timestamp < scan_cutoff
            ).all()
            
            for url_scan in old_url_scans:
                db.session.delete(url_scan)
                cleanup_summary['url_scans_deleted'] += 1
            
            # Anonymize old activity logs
            log_retention_days = self.retention_policies[DataCategory.ACTIVITY_LOGS].retention_days
            log_cutoff = current_time - timedelta(days=log_retention_days)
            
            old_logs = ActivityLog.query.filter(
                ActivityLog.timestamp < log_cutoff
            ).all()
            
            for log in old_logs:
                # Anonymize IP addresses and user agents
                if log.ip_address:
                    log.ip_address = self._anonymize_ip(log.ip_address)
                if log.user_agent:
                    log.user_agent = "anonymized"
                cleanup_summary['activity_logs_anonymized'] += 1
            
            # Review quarantine items (don't auto-delete, just log)
            quarantine_items = QuarantineItem.query.filter(
                QuarantineItem.quarantine_timestamp < scan_cutoff,
                QuarantineItem.deleted == False
            ).all()
            
            cleanup_summary['quarantine_items_reviewed'] = len(quarantine_items)
            
            # Commit changes
            db.session.commit()
            
            logging.info(f"Automated data cleanup completed: {cleanup_summary}")
            
        except Exception as e:
            logging.error(f"Error in automated data cleanup: {str(e)}")
            db.session.rollback()
        
        return cleanup_summary
    
    def generate_privacy_report(self) -> Dict[str, Any]:
        """Generate privacy compliance report"""
        try:
            current_time = datetime.utcnow()
            
            # Count active consent records
            active_consents = {}
            for consent_type in ConsentType:
                active_consents[consent_type.value] = sum(
                    1 for record in self.consent_records.values()
                    if record.get('consent_type') == consent_type.value and record.get('granted')
                )
            
            # Count privacy requests by type and status
            request_stats = {}
            for request_type in ['data_access', 'data_deletion', 'data_portability']:
                request_stats[request_type] = {
                    'total': 0,
                    'completed': 0,
                    'processing': 0
                }
            
            for request in self.privacy_requests.values():
                req_type = request.get('request_type', 'unknown')
                if req_type in request_stats:
                    request_stats[req_type]['total'] += 1
                    status = request.get('status', 'unknown')
                    if status in request_stats[req_type]:
                        request_stats[req_type][status] += 1
            
            # Data retention compliance
            retention_status = {}
            for category, policy in self.retention_policies.items():
                cutoff_date = current_time - timedelta(days=policy.retention_days)
                
                if category == DataCategory.SCAN_DATA:
                    old_records = ScanResult.query.filter(
                        ScanResult.scan_timestamp < cutoff_date
                    ).count()
                elif category == DataCategory.ACTIVITY_LOGS:
                    old_records = ActivityLog.query.filter(
                        ActivityLog.timestamp < cutoff_date
                    ).count()
                else:
                    old_records = 0
                
                retention_status[category.value] = {
                    'policy_days': policy.retention_days,
                    'old_records_count': old_records,
                    'deletion_method': policy.deletion_method
                }
            
            report = {
                'report_generated': current_time.isoformat(),
                'privacy_policy_version': self.current_privacy_version,
                'active_consents': active_consents,
                'privacy_requests': request_stats,
                'data_retention': retention_status,
                'compliance_status': 'compliant' if all(
                    status['old_records_count'] == 0 
                    for status in retention_status.values()
                ) else 'requires_attention'
            }
            
            return report
            
        except Exception as e:
            logging.error(f"Error generating privacy report: {str(e)}")
            return {'error': str(e)}
    
    def _collect_user_data(self, user_identifier: str) -> Dict[str, Any]:
        """Collect all data associated with a user identifier"""
        data = {
            'user_identifier': self._anonymize_ip(user_identifier),
            'data_collected_at': datetime.utcnow().isoformat(),
            'scan_results': [],
            'url_scans': [],
            'activity_logs': [],
            'consent_records': []
        }
        
        try:
            # Collect scan results
            scans = ScanResult.query.all()  # In real app, filter by user
            for scan in scans:
                data['scan_results'].append({
                    'filename': scan.filename,
                    'scan_timestamp': scan.scan_timestamp.isoformat(),
                    'threat_level': scan.threat_level,
                    'risk_score': scan.risk_score
                })
            
            # Collect URL scans
            url_scans = URLScan.query.all()  # In real app, filter by user
            for url_scan in url_scans:
                data['url_scans'].append({
                    'url': url_scan.url,
                    'scan_timestamp': url_scan.scan_timestamp.isoformat(),
                    'threat_level': url_scan.threat_level,
                    'risk_score': url_scan.risk_score
                })
            
            # Collect activity logs (anonymized)
            activities = ActivityLog.query.filter(
                ActivityLog.ip_address == user_identifier
            ).all()
            
            for activity in activities:
                data['activity_logs'].append({
                    'action': activity.action,
                    'timestamp': activity.timestamp.isoformat(),
                    'success': activity.success
                })
            
            # Collect consent records
            for consent_record in self.consent_records.values():
                if consent_record.get('user_id') == user_identifier:
                    data['consent_records'].append(consent_record)
            
        except Exception as e:
            logging.error(f"Error collecting user data: {str(e)}")
            data['error'] = str(e)
        
        return data
    
    def _collect_portable_data(self, user_identifier: str) -> Dict[str, Any]:
        """Collect user data in portable format"""
        # For portability, include only user-provided data, not system-generated
        data = {
            'user_identifier': self._anonymize_ip(user_identifier),
            'export_format': 'JSON',
            'export_date': datetime.utcnow().isoformat(),
            'files_scanned': [],
            'urls_analyzed': []
        }
        
        try:
            # Include only basic scan information (files submitted by user)
            scans = ScanResult.query.all()  # In real app, filter by user
            for scan in scans:
                data['files_scanned'].append({
                    'filename': scan.filename,
                    'scan_date': scan.scan_timestamp.isoformat(),
                    'file_size': scan.file_size
                })
            
            # Include URLs submitted by user
            url_scans = URLScan.query.all()  # In real app, filter by user
            for url_scan in url_scans:
                data['urls_analyzed'].append({
                    'url': url_scan.url,
                    'scan_date': url_scan.scan_timestamp.isoformat(),
                    'domain': url_scan.domain
                })
            
        except Exception as e:
            logging.error(f"Error collecting portable data: {str(e)}")
            data['error'] = str(e)
        
        return data
    
    def _delete_user_data(self, user_identifier: str) -> Dict[str, int]:
        """Delete all data associated with a user identifier"""
        deletion_summary = {
            'scan_results_deleted': 0,
            'url_scans_deleted': 0,
            'activity_logs_anonymized': 0,
            'consent_records_removed': 0
        }
        
        try:
            # Delete scan results (except quarantined items)
            scans_to_delete = ScanResult.query.filter(
                ScanResult.quarantined == False
            ).all()  # In real app, filter by user
            
            for scan in scans_to_delete:
                db.session.delete(scan)
                deletion_summary['scan_results_deleted'] += 1
            
            # Delete URL scans
            url_scans_to_delete = URLScan.query.all()  # In real app, filter by user
            for url_scan in url_scans_to_delete:
                db.session.delete(url_scan)
                deletion_summary['url_scans_deleted'] += 1
            
            # Anonymize activity logs
            activities = ActivityLog.query.filter(
                ActivityLog.ip_address == user_identifier
            ).all()
            
            for activity in activities:
                activity.ip_address = self._anonymize_ip(activity.ip_address)
                activity.user_agent = "anonymized"
                deletion_summary['activity_logs_anonymized'] += 1
            
            # Remove consent records
            consent_keys_to_remove = [
                key for key, record in self.consent_records.items()
                if record.get('user_id') == user_identifier
            ]
            
            for key in consent_keys_to_remove:
                del self.consent_records[key]
                deletion_summary['consent_records_removed'] += 1
            
            # Save changes
            db.session.commit()
            self._save_consent_records()
            
        except Exception as e:
            logging.error(f"Error deleting user data: {str(e)}")
            db.session.rollback()
            deletion_summary['error'] = str(e)
        
        return deletion_summary
    
    def _anonymize_ip(self, ip_address: str) -> str:
        """Anonymize IP address for privacy compliance"""
        if not ip_address:
            return "unknown"
        
        # For IPv4, zero out the last octet
        if '.' in ip_address:
            parts = ip_address.split('.')
            if len(parts) == 4:
                return f"{parts[0]}.{parts[1]}.{parts[2]}.0"
        
        # For IPv6, zero out the last 64 bits
        if ':' in ip_address:
            parts = ip_address.split(':')
            if len(parts) >= 4:
                return ':'.join(parts[:4]) + '::0'
        
        # Fallback to hash
        return hashlib.sha256(ip_address.encode()).hexdigest()[:16]
    
    def _generate_request_id(self) -> str:
        """Generate unique request ID"""
        timestamp = datetime.utcnow().strftime('%Y%m%d%H%M%S')
        random_part = hashlib.md5(os.urandom(16)).hexdigest()[:8]
        return f"PR_{timestamp}_{random_part}"
    
    def _load_consent_records(self) -> Dict[str, Any]:
        """Load consent records from file"""
        try:
            if os.path.exists(self.consent_storage_path):
                with open(self.consent_storage_path, 'r') as f:
                    return json.load(f)
        except Exception as e:
            logging.error(f"Error loading consent records: {str(e)}")
        
        return {}
    
    def _save_consent_records(self) -> bool:
        """Save consent records to file"""
        try:
            with open(self.consent_storage_path, 'w') as f:
                json.dump(self.consent_records, f, indent=2, default=str)
            return True
        except Exception as e:
            logging.error(f"Error saving consent records: {str(e)}")
            return False
    
    def _load_privacy_requests(self) -> Dict[str, Any]:
        """Load privacy requests from file"""
        try:
            if os.path.exists(self.privacy_requests_path):
                with open(self.privacy_requests_path, 'r') as f:
                    return json.load(f)
        except Exception as e:
            logging.error(f"Error loading privacy requests: {str(e)}")
        
        return {}
    
    def _save_privacy_requests(self) -> bool:
        """Save privacy requests to file"""
        try:
            with open(self.privacy_requests_path, 'w') as f:
                json.dump(self.privacy_requests, f, indent=2, default=str)
            return True
        except Exception as e:
            logging.error(f"Error saving privacy requests: {str(e)}")
            return False


# Initialize the GDPR compliance manager
gdpr_manager = GDPRComplianceManager()