from flask import render_template, request, jsonify, flash, redirect, url_for, send_file
from werkzeug.utils import secure_filename
import os
import logging
from datetime import datetime, timedelta

from app import app, db
from models import ScanResult, URLScan, QuarantineItem, ActivityLog, SystemMetrics
from file_scanner import FileScanner
from threat_intel import ThreatIntelligence
from quarantine import QuarantineManager
from utils import log_activity, calculate_risk_score, allowed_file

# Initialize components
file_scanner = FileScanner()
threat_intel = ThreatIntelligence()
quarantine_manager = QuarantineManager()

@app.route('/')
def index():
    """Main dashboard page"""
    # Get recent scan statistics
    total_scans = ScanResult.query.count() + URLScan.query.count()
    recent_scans = ScanResult.query.order_by(ScanResult.scan_timestamp.desc()).limit(5).all()
    quarantine_count = QuarantineItem.query.filter_by(deleted=False, restored=False).count()
    
    # Get threat level distribution
    safe_count = ScanResult.query.filter_by(threat_level='safe').count()
    suspicious_count = ScanResult.query.filter_by(threat_level='suspicious').count()
    malicious_count = ScanResult.query.filter_by(threat_level='malicious').count()
    
    stats = {
        'total_scans': total_scans,
        'quarantine_count': quarantine_count,
        'safe_count': safe_count,
        'suspicious_count': suspicious_count,
        'malicious_count': malicious_count
    }
    
    return render_template('index.html', stats=stats, recent_scans=recent_scans)

@app.route('/upload', methods=['POST'])
def upload_file():
    """Handle file upload and scanning"""
    try:
        if 'files' not in request.files:
            flash('No files selected', 'error')
            return redirect(url_for('index'))
        
        files = request.files.getlist('files')
        scan_results = []
        
        for file in files:
            if file and file.filename and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
                
                # Scan the file
                scan_result = file_scanner.scan_file(filepath, filename)
                
                # Save scan result to database
                db_result = ScanResult(
                    filename=scan_result['filename'],
                    file_hash=scan_result['file_hash'],
                    file_size=scan_result['file_size'],
                    scan_type='file',
                    risk_score=scan_result['risk_score'],
                    threat_level=scan_result['threat_level'],
                    detection_details=scan_result['detection_details'],
                    original_path=filepath
                )
                
                db.session.add(db_result)
                db.session.commit()
                
                # Quarantine if malicious
                if scan_result['threat_level'] == 'malicious':
                    quarantine_manager.quarantine_file(filepath, db_result.id)
                    db_result.quarantined = True
                    db.session.commit()
                
                scan_results.append(scan_result)
                
                # Log activity
                log_activity('file_scan', f'Scanned file: {filename}', request.remote_addr, request.user_agent.string)
        
        return render_template('scan_results.html', results=scan_results, scan_type='file')
        
    except Exception as e:
        logging.error(f"Error in file upload: {str(e)}")
        flash('An error occurred during file scanning', 'error')
        return redirect(url_for('index'))

@app.route('/scan-url', methods=['POST'])
def scan_url():
    """Handle URL scanning"""
    try:
        url = request.form.get('url', '').strip()
        
        if not url:
            flash('Please enter a URL', 'error')
            return redirect(url_for('index'))
        
        # Scan the URL
        scan_result = threat_intel.analyze_url(url)
        
        # Save scan result to database
        db_result = URLScan(
            url=scan_result['url'],
            domain=scan_result['domain'],
            risk_score=scan_result['risk_score'],
            threat_level=scan_result['threat_level'],
            detection_details=scan_result['detection_details'],
            threat_intel_data=scan_result.get('threat_intel_data', '')
        )
        
        db.session.add(db_result)
        db.session.commit()
        
        # Log activity
        log_activity('url_scan', f'Scanned URL: {url}', request.remote_addr, request.user_agent.string)
        
        return render_template('scan_results.html', results=[scan_result], scan_type='url')
        
    except Exception as e:
        logging.error(f"Error in URL scan: {str(e)}")
        flash('An error occurred during URL scanning', 'error')
        return redirect(url_for('index'))

@app.route('/quarantine')
def quarantine():
    """Display quarantine management page"""
    quarantine_items = db.session.query(QuarantineItem, ScanResult).join(
        ScanResult, QuarantineItem.scan_result_id == ScanResult.id
    ).filter(QuarantineItem.deleted == False, QuarantineItem.restored == False).all()
    
    return render_template('quarantine.html', quarantine_items=quarantine_items)

@app.route('/quarantine/restore/<int:item_id>')
def restore_file(item_id):
    """Restore a file from quarantine"""
    try:
        quarantine_item = QuarantineItem.query.get_or_404(item_id)
        
        if quarantine_manager.restore_file(quarantine_item.quarantine_path, quarantine_item.original_path):
            quarantine_item.restored = True
            quarantine_item.restored_timestamp = datetime.utcnow()
            db.session.commit()
            
            # Update scan result
            scan_result = ScanResult.query.get(quarantine_item.scan_result_id)
            scan_result.quarantined = False
            db.session.commit()
            
            flash('File restored successfully', 'success')
            log_activity('file_restore', f'Restored file: {quarantine_item.filename}', request.remote_addr, request.user_agent.string)
        else:
            flash('Failed to restore file', 'error')
            
    except Exception as e:
        logging.error(f"Error restoring file: {str(e)}")
        flash('An error occurred while restoring the file', 'error')
    
    return redirect(url_for('quarantine'))

@app.route('/quarantine/delete/<int:item_id>')
def delete_file(item_id):
    """Permanently delete a quarantined file"""
    try:
        quarantine_item = QuarantineItem.query.get_or_404(item_id)
        
        if quarantine_manager.delete_file(quarantine_item.quarantine_path):
            quarantine_item.deleted = True
            quarantine_item.deleted_timestamp = datetime.utcnow()
            db.session.commit()
            
            flash('File deleted permanently', 'success')
            log_activity('file_delete', f'Deleted file: {quarantine_item.filename}', request.remote_addr, request.user_agent.string)
        else:
            flash('Failed to delete file', 'error')
            
    except Exception as e:
        logging.error(f"Error deleting file: {str(e)}")
        flash('An error occurred while deleting the file', 'error')
    
    return redirect(url_for('quarantine'))

@app.route('/history')
def history():
    """Display scan history"""
    page = request.args.get('page', 1, type=int)
    per_page = 20
    
    file_scans = ScanResult.query.order_by(ScanResult.scan_timestamp.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    url_scans = URLScan.query.order_by(URLScan.scan_timestamp.desc()).limit(per_page).all()
    
    return render_template('history.html', file_scans=file_scans, url_scans=url_scans)

@app.route('/monitoring')
def monitoring():
    """Display system monitoring dashboard"""
    # Get recent activity logs
    recent_logs = ActivityLog.query.order_by(ActivityLog.timestamp.desc()).limit(50).all()
    
    # Get system metrics for the last 24 hours
    yesterday = datetime.utcnow() - timedelta(days=1)
    metrics = SystemMetrics.query.filter(SystemMetrics.timestamp >= yesterday).all()
    
    # Calculate performance stats
    total_scans_today = ScanResult.query.filter(ScanResult.scan_timestamp >= yesterday).count()
    url_scans_today = URLScan.query.filter(URLScan.scan_timestamp >= yesterday).count()
    
    # Threat detection accuracy (simplified calculation)
    total_files = ScanResult.query.count()
    detected_threats = ScanResult.query.filter(ScanResult.threat_level.in_(['suspicious', 'malicious'])).count()
    detection_rate = (detected_threats / total_files * 100) if total_files > 0 else 0
    
    stats = {
        'total_scans_today': total_scans_today + url_scans_today,
        'detection_rate': round(detection_rate, 2),
        'system_health': 'Good'  # Simplified for MVP
    }
    
    return render_template('monitoring.html', logs=recent_logs, metrics=metrics, stats=stats)

@app.route('/api/scan-status/<int:scan_id>')
def scan_status(scan_id):
    """API endpoint to check scan status"""
    scan_result = ScanResult.query.get_or_404(scan_id)
    return jsonify({
        'id': scan_result.id,
        'filename': scan_result.filename,
        'threat_level': scan_result.threat_level,
        'risk_score': scan_result.risk_score,
        'status': 'complete'
    })

@app.errorhandler(413)
def too_large(e):
    flash('File too large. Maximum size is 100MB.', 'error')
    return redirect(url_for('index'))

@app.errorhandler(404)
def not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def server_error(e):
    logging.error(f"Server error: {str(e)}")
    return render_template('500.html'), 500
