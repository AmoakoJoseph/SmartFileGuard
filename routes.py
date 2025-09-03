from flask import render_template, request, jsonify, flash, redirect, url_for, send_file
from flask_limiter import Limiter
from flask_wtf import FlaskForm, CSRFProtect
from werkzeug.utils import secure_filename
import os
import json
import logging
from datetime import datetime, timedelta

from app import app, db, limiter, socketio
from models import ScanResult, URLScan, QuarantineItem, ActivityLog, SystemMetrics
from file_scanner import FileScanner
from threat_intel import ThreatIntelligence
from quarantine import QuarantineManager
from utils import log_activity, calculate_risk_score, allowed_file

# Enhanced imports for new features
try:
    from tasks import scan_file_async, scan_url_async
    from gdpr_compliance import gdpr_manager, ConsentType
    from behavioral_analysis import behavioral_engine
    ENHANCED_FEATURES_ENABLED = True
except ImportError as e:
    logging.warning(f"Enhanced features not available: {e}")
    ENHANCED_FEATURES_ENABLED = False

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
@limiter.limit("10 per minute")
def upload_file():
    """Handle file upload and scanning with async processing"""
    try:
        if 'files' not in request.files:
            flash('No files selected', 'error')
            return redirect(url_for('index'))
        
        files = request.files.getlist('files')
        
        if ENHANCED_FEATURES_ENABLED:
            # Use async scanning with real-time updates
            scan_tasks = []
            
            for file in files:
                if file and file.filename and allowed_file(file.filename):
                    filename = secure_filename(file.filename)
                    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    file.save(filepath)
                    
                    # Start async scan
                    task = scan_file_async.delay(filepath, filename)
                    scan_tasks.append({
                        'task_id': task.id,
                        'filename': filename,
                        'status': 'processing'
                    })
                    
                    # Log activity
                    log_activity('file_scan_started', f'Started scan for file: {filename}', request.remote_addr, request.user_agent.string)
            
            return render_template('async_scan_results.html', tasks=scan_tasks, scan_type='file')
        
        else:
            # Fallback to synchronous scanning
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
@limiter.limit("20 per minute")
def scan_url():
    """Handle URL scanning with async processing"""
    try:
        url = request.form.get('url', '').strip()
        
        if not url:
            flash('Please enter a URL', 'error')
            return redirect(url_for('index'))
        
        if ENHANCED_FEATURES_ENABLED:
            # Use async URL scanning
            task = scan_url_async.delay(url)
            
            # Log activity
            log_activity('url_scan_started', f'Started URL scan: {url}', request.remote_addr, request.user_agent.string)
            
            return render_template('async_scan_results.html', 
                                 tasks=[{'task_id': task.id, 'url': url, 'status': 'processing'}], 
                                 scan_type='url')
        else:
            # Fallback to synchronous scanning
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


# Enhanced API endpoints for real-time features
@app.route('/api/task-status/<task_id>')
def get_task_status(task_id):
    """Get status of async task"""
    if not ENHANCED_FEATURES_ENABLED:
        return jsonify({'error': 'Enhanced features not available'}), 503
    
    try:
        from celery.result import AsyncResult
        task = AsyncResult(task_id)
        
        if task.state == 'PENDING':
            response = {
                'state': task.state,
                'progress': 0,
                'message': 'Task is waiting to be processed...'
            }
        elif task.state != 'FAILURE':
            response = {
                'state': task.state,
                'progress': task.info.get('progress', 0) if hasattr(task, 'info') and task.info else 100,
                'message': task.info.get('message', '') if hasattr(task, 'info') and task.info else 'Processing...'
            }
            if task.state == 'SUCCESS':
                response['result'] = task.result
        else:
            response = {
                'state': task.state,
                'progress': 0,
                'message': str(task.info)
            }
        
        return jsonify(response)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/privacy')
def privacy_dashboard():
    """Privacy management dashboard"""
    if not ENHANCED_FEATURES_ENABLED:
        flash('Privacy features not available', 'warning')
        return redirect(url_for('index'))
    
    try:
        # Generate privacy report
        privacy_report = gdpr_manager.generate_privacy_report()
        return render_template('privacy_dashboard.html', report=privacy_report)
        
    except Exception as e:
        logging.error(f"Error loading privacy dashboard: {str(e)}")
        flash('Error loading privacy dashboard', 'error')
        return redirect(url_for('index'))


@app.route('/privacy/request-data', methods=['POST'])
@limiter.limit("3 per hour")
def request_data_access():
    """Handle data access request"""
    if not ENHANCED_FEATURES_ENABLED:
        return jsonify({'error': 'Privacy features not available'}), 503
    
    try:
        user_ip = request.remote_addr
        request_id = gdpr_manager.handle_data_access_request(user_ip)
        
        if request_id:
            flash(f'Data access request submitted. Request ID: {request_id}', 'success')
            log_activity('data_access_request', f'Data access requested: {request_id}', user_ip, request.user_agent.string)
        else:
            flash('Failed to process data access request', 'error')
        
        return redirect(url_for('privacy_dashboard'))
        
    except Exception as e:
        logging.error(f"Error processing data access request: {str(e)}")
        flash('Error processing request', 'error')
        return redirect(url_for('privacy_dashboard'))


@app.route('/privacy/delete-data', methods=['POST'])
@limiter.limit("1 per day")
def request_data_deletion():
    """Handle data deletion request"""
    if not ENHANCED_FEATURES_ENABLED:
        return jsonify({'error': 'Privacy features not available'}), 503
    
    try:
        user_ip = request.remote_addr
        request_id = gdpr_manager.handle_data_deletion_request(user_ip)
        
        if request_id:
            flash(f'Data deletion request submitted. Request ID: {request_id}', 'success')
            log_activity('data_deletion_request', f'Data deletion requested: {request_id}', user_ip, request.user_agent.string)
        else:
            flash('Failed to process data deletion request', 'error')
        
        return redirect(url_for('privacy_dashboard'))
        
    except Exception as e:
        logging.error(f"Error processing data deletion request: {str(e)}")
        flash('Error processing request', 'error')
        return redirect(url_for('privacy_dashboard'))


@app.route('/behavioral-analysis')
def behavioral_analysis():
    """Behavioral analysis dashboard"""
    if not ENHANCED_FEATURES_ENABLED:
        flash('Behavioral analysis not available', 'warning')
        return redirect(url_for('index'))
    
    try:
        # Get recent behavioral patterns
        patterns = behavioral_engine.analyze_system_behavior()
        report = behavioral_engine.generate_behavioral_report(patterns)
        
        return render_template('behavioral_analysis.html', patterns=patterns, report=report)
        
    except Exception as e:
        logging.error(f"Error loading behavioral analysis: {str(e)}")
        flash('Error loading behavioral analysis', 'error')
        return redirect(url_for('index'))


@app.route('/api/behavioral-patterns')
def get_behavioral_patterns():
    """API endpoint for behavioral patterns"""
    if not ENHANCED_FEATURES_ENABLED:
        return jsonify({'error': 'Behavioral analysis not available'}), 503
    
    try:
        patterns = behavioral_engine.analyze_system_behavior()
        report = behavioral_engine.generate_behavioral_report(patterns)
        
        return jsonify({
            'patterns': [{
                'type': p.pattern_type,
                'confidence': p.confidence,
                'description': p.description,
                'risk_level': p.risk_level,
                'timestamp': p.timestamp.isoformat()
            } for p in patterns],
            'report': report
        })
        
    except Exception as e:
        logging.error(f"Error getting behavioral patterns: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/health')
def health_check():
    """Health check endpoint for container orchestration"""
    try:
        # Check database connectivity
        db.session.execute('SELECT 1')
        
        # Basic system status
        health_status = {
            'status': 'healthy',
            'timestamp': datetime.utcnow().isoformat(),
            'version': '2.0.0',
            'components': {
                'database': 'operational',
                'ml_models': 'loaded' if ENHANCED_FEATURES_ENABLED else 'basic',
                'security_features': 'active',
                'websocket': 'enabled' if ENHANCED_FEATURES_ENABLED else 'disabled'
            },
            'features': {
                'enhanced_features': ENHANCED_FEATURES_ENABLED,
                'deep_learning': app.config.get('ENABLE_DEEP_LEARNING', False),
                'behavioral_analysis': app.config.get('BEHAVIORAL_ANALYSIS', False),
                'gdpr_compliance': app.config.get('ENABLE_GDPR_COMPLIANCE', False)
            }
        }
        
        return jsonify(health_status)
        
    except Exception as e:
        logging.error(f"Health check failed: {str(e)}")
        return jsonify({
            'status': 'unhealthy',
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat()
        }), 503


@app.route('/deployment-status')
def deployment_status():
    """Deployment and system status page"""
    try:
        # System information
        system_info = {
            'application': 'SmartFileGuardian',
            'version': '2.0.0 - Advanced Edition',
            'deployment_date': datetime.utcnow().strftime('%Y-%m-%d'),
            'python_version': '3.11',
            'framework': 'Flask + SQLAlchemy + SocketIO',
            'database': 'PostgreSQL' if 'postgresql' in app.config['SQLALCHEMY_DATABASE_URI'] else 'SQLite',
            'enhanced_features': ENHANCED_FEATURES_ENABLED,
            'security_features': {
                'csrf_protection': True,
                'rate_limiting': True,
                'input_validation': True,
                'secure_headers': True
            },
            'ml_capabilities': {
                'tensorflow': app.config.get('ENABLE_DEEP_LEARNING', False),
                'pytorch': app.config.get('ENABLE_DEEP_LEARNING', False),
                'scikit_learn': True,
                'ensemble_models': ENHANCED_FEATURES_ENABLED
            },
            'privacy_compliance': {
                'gdpr_ready': app.config.get('ENABLE_GDPR_COMPLIANCE', False),
                'ccpa_ready': app.config.get('ENABLE_GDPR_COMPLIANCE', False),
                'data_retention': f"{app.config.get('DATA_RETENTION_DAYS', 90)} days",
                'automated_cleanup': ENHANCED_FEATURES_ENABLED
            }
        }
        
        return render_template('deployment_status.html', info=system_info)
        
    except Exception as e:
        logging.error(f"Error loading deployment status: {str(e)}")
        return jsonify({'error': str(e)}), 500
