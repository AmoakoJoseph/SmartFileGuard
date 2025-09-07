import os
import logging
from datetime import datetime
from app import db
from db_models import ActivityLog, SystemMetrics

def allowed_file(filename):
    """Check if file extension is allowed for upload"""
    allowed_extensions = {
        'exe', 'dll', 'scr', 'bat', 'cmd', 'com', 'pif',
        'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx',
        'zip', 'rar', '7z', 'tar', 'gz', 'bz2',
        'js', 'jar', 'apk', 'ipa', 'txt', 'rtf'
    }
    
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in allowed_extensions

def log_activity(action, details, ip_address=None, user_agent=None, success=True):
    """Log user activity and system events"""
    try:
        activity = ActivityLog(
            action=action,
            details=details,
            ip_address=ip_address,
            user_agent=user_agent,
            success=success
        )
        
        db.session.add(activity)
        db.session.commit()
        
        logging.info(f"Activity logged: {action} - {details}")
        
    except Exception as e:
        logging.error(f"Error logging activity: {str(e)}")
        db.session.rollback()

def calculate_risk_score(threat_indicators):
    """Calculate overall risk score from multiple threat indicators"""
    if not threat_indicators:
        return 0.0
    
    # Weighted average of threat indicators
    total_weight = sum(indicator.get('weight', 1.0) for indicator in threat_indicators)
    weighted_score = sum(
        indicator.get('score', 0.0) * indicator.get('weight', 1.0) 
        for indicator in threat_indicators
    )
    
    if total_weight == 0:
        return 0.0
    
    return min(weighted_score / total_weight, 1.0)

def record_system_metric(metric_name, metric_value):
    """Record system performance metrics"""
    try:
        metric = SystemMetrics(
            metric_name=metric_name,
            metric_value=metric_value
        )
        
        db.session.add(metric)
        db.session.commit()
        
    except Exception as e:
        logging.error(f"Error recording system metric: {str(e)}")
        db.session.rollback()

def get_file_size_human(size_bytes):
    """Convert file size to human readable format"""
    if size_bytes == 0:
        return "0 B"
    
    size_names = ["B", "KB", "MB", "GB", "TB"]
    i = 0
    while size_bytes >= 1024 and i < len(size_names) - 1:
        size_bytes /= 1024.0
        i += 1
    
    return f"{size_bytes:.1f} {size_names[i]}"

def sanitize_filename(filename):
    """Sanitize filename to prevent path traversal attacks"""
    # Remove path components and dangerous characters
    filename = os.path.basename(filename)
    filename = "".join(c for c in filename if c.isalnum() or c in (' ', '.', '_', '-'))
    filename = filename.strip()
    
    # Prevent empty filenames
    if not filename:
        filename = "unknown_file"
    
    return filename

def validate_url(url):
    """Basic URL validation"""
    import re
    
    url_pattern = re.compile(
        r'^https?://'  # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain...
        r'localhost|'  # localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    
    return bool(url_pattern.match(url))

def get_threat_level_color(threat_level):
    """Get Bootstrap color class for threat level"""
    color_map = {
        'safe': 'success',
        'suspicious': 'warning',
        'malicious': 'danger',
        'unknown': 'secondary'
    }
    return color_map.get(threat_level, 'secondary')

def get_threat_level_icon(threat_level):
    """Get Font Awesome icon for threat level"""
    icon_map = {
        'safe': 'fa-shield-alt',
        'suspicious': 'fa-exclamation-triangle',
        'malicious': 'fa-skull-crossbones',
        'unknown': 'fa-question-circle'
    }
    return icon_map.get(threat_level, 'fa-question-circle')

def format_timestamp(timestamp):
    """Format timestamp for display"""
    if isinstance(timestamp, str):
        timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
    
    return timestamp.strftime("%Y-%m-%d %H:%M:%S")

def clean_old_uploads(max_age_hours=24):
    """Clean up old uploaded files"""
    try:
        upload_folder = 'uploads'
        if not os.path.exists(upload_folder):
            return 0
        
        cutoff_time = datetime.now().timestamp() - (max_age_hours * 3600)
        cleaned_count = 0
        
        for filename in os.listdir(upload_folder):
            filepath = os.path.join(upload_folder, filename)
            if os.path.isfile(filepath):
                file_time = os.path.getmtime(filepath)
                if file_time < cutoff_time:
                    try:
                        os.remove(filepath)
                        cleaned_count += 1
                    except Exception as e:
                        logging.error(f"Error removing old file {filepath}: {str(e)}")
        
        logging.info(f"Cleaned up {cleaned_count} old upload files")
        return cleaned_count
        
    except Exception as e:
        logging.error(f"Error cleaning old uploads: {str(e)}")
        return 0
