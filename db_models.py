from datetime import datetime
from app import db
from sqlalchemy import Column, Integer, String, DateTime, Text, Float, Boolean, LargeBinary


class ScanResult(db.Model):
    __tablename__ = 'scan_results'
    
    id = Column(Integer, primary_key=True)
    filename = Column(String(255), nullable=False)
    file_hash = Column(String(64), nullable=False)
    file_size = Column(Integer, nullable=False)
    scan_type = Column(String(50), nullable=False)  # 'file' or 'url'
    risk_score = Column(Float, nullable=False)
    threat_level = Column(String(50), nullable=False)  # 'safe', 'suspicious', 'malicious'
    detection_details = Column(Text)
    scan_timestamp = Column(DateTime, default=datetime.utcnow)
    quarantined = Column(Boolean, default=False)
    original_path = Column(String(500))
    quarantine_path = Column(String(500))


class URLScan(db.Model):
    __tablename__ = 'url_scans'
    
    id = Column(Integer, primary_key=True)
    url = Column(Text, nullable=False)
    domain = Column(String(255), nullable=False)
    risk_score = Column(Float, nullable=False)
    threat_level = Column(String(50), nullable=False)
    detection_details = Column(Text)
    scan_timestamp = Column(DateTime, default=datetime.utcnow)
    threat_intel_data = Column(Text)


class QuarantineItem(db.Model):
    __tablename__ = 'quarantine_items'
    
    id = Column(Integer, primary_key=True)
    scan_result_id = Column(Integer, db.ForeignKey('scan_results.id'), nullable=False)
    filename = Column(String(255), nullable=False)
    original_path = Column(String(500), nullable=False)
    quarantine_path = Column(String(500), nullable=False)
    quarantine_timestamp = Column(DateTime, default=datetime.utcnow)
    restored = Column(Boolean, default=False)
    restored_timestamp = Column(DateTime)
    deleted = Column(Boolean, default=False)
    deleted_timestamp = Column(DateTime)


class ActivityLog(db.Model):
    __tablename__ = 'activity_logs'
    
    id = Column(Integer, primary_key=True)
    action = Column(String(100), nullable=False)
    details = Column(Text)
    timestamp = Column(DateTime, default=datetime.utcnow)
    ip_address = Column(String(45))
    user_agent = Column(Text)
    success = Column(Boolean, default=True)


class SystemMetrics(db.Model):
    __tablename__ = 'system_metrics'
    
    id = Column(Integer, primary_key=True)
    metric_name = Column(String(100), nullable=False)
    metric_value = Column(Float, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)


