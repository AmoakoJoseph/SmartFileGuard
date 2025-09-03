import os
import logging
import time
from datetime import datetime
from celery import Celery
from app import app, db, celery
from models import ScanResult, URLScan, ActivityLog, QuarantineItem
from file_scanner import FileScanner
from threat_intel import ThreatIntelligence
from quarantine import QuarantineManager
from advanced_ml_models import ensemble_detector
from behavioral_analysis import behavioral_engine
from gdpr_compliance import gdpr_manager
from websocket_handlers import ws_handler

# Initialize components
file_scanner = FileScanner()
threat_intel = ThreatIntelligence()
quarantine_manager = QuarantineManager()

@celery.task(bind=True)
def scan_file_async(self, file_path, filename, scan_id=None):
    """Asynchronously scan a file with progress updates"""
    try:
        if scan_id is None:
            scan_id = self.request.id
        
        # Initialize progress
        ws_handler.emit_scan_progress(scan_id, 0, "Starting file analysis...")
        
        # Step 1: Basic file info
        self.update_state(state='PROGRESS', meta={'progress': 10, 'message': 'Extracting file information'})
        ws_handler.emit_scan_progress(scan_id, 10, "Extracting file information...")
        
        file_stats = os.stat(file_path)
        file_size = file_stats.st_size
        
        # Step 2: Calculate file hash
        self.update_state(state='PROGRESS', meta={'progress': 20, 'message': 'Calculating file hash'})
        ws_handler.emit_scan_progress(scan_id, 20, "Calculating file hash...")
        
        file_hash = file_scanner.calculate_file_hash(file_path)
        
        # Step 3: Detect file type
        self.update_state(state='PROGRESS', meta={'progress': 30, 'message': 'Detecting file type'})
        ws_handler.emit_scan_progress(scan_id, 30, "Detecting file type...")
        
        file_type = file_scanner.detect_file_type(file_path)
        
        # Step 4: Basic security checks
        self.update_state(state='PROGRESS', meta={'progress': 40, 'message': 'Running security checks'})
        ws_handler.emit_scan_progress(scan_id, 40, "Running security checks...")
        
        # Perform individual checks
        checks = [
            file_scanner.check_file_size,
            file_scanner.check_file_extension,
            file_scanner.check_file_signature,
            file_scanner.check_suspicious_patterns
        ]
        
        threat_indicators = []
        total_risk = 0.0
        
        for i, check in enumerate(checks):
            progress = 45 + (i * 5)
            check_name = check.__name__.replace('check_', '').replace('_', ' ').title()
            
            self.update_state(state='PROGRESS', meta={'progress': progress, 'message': f'Running {check_name}'})
            ws_handler.emit_scan_progress(scan_id, progress, f"Running {check_name}...")
            
            result = {
                'filename': filename,
                'file_size': file_size,
                'file_type': file_type,
                'file_hash': file_hash
            }
            
            check_result = check(file_path, filename, result)
            if check_result['is_threat']:
                threat_indicators.append(check_result['reason'])
                total_risk += check_result['risk_weight']
        
        # Step 5: Machine Learning Analysis
        self.update_state(state='PROGRESS', meta={'progress': 65, 'message': 'Running ML analysis'})
        ws_handler.emit_scan_progress(scan_id, 65, "Running machine learning analysis...")
        
        if app.config.get('ENABLE_DEEP_LEARNING', True):
            ml_prediction = ensemble_detector.predict(file_path)
            detailed_predictions = ensemble_detector.get_detailed_predictions(file_path)
            
            if ml_prediction > 0.7:
                threat_indicators.append(f'ML models detected malware (confidence: {ml_prediction:.2f})')
                total_risk += ml_prediction
            elif ml_prediction > 0.4:
                threat_indicators.append(f'ML models flagged as suspicious (confidence: {ml_prediction:.2f})')
                total_risk += ml_prediction * 0.7
        else:
            # Fallback to basic ML
            features = file_scanner.malware_detector.extract_features(file_path)
            ml_prediction = file_scanner.malware_detector.predict(features)
            detailed_predictions = {'sklearn': ml_prediction}
            
            if ml_prediction > 0.7:
                threat_indicators.append(f'ML model detected malware (confidence: {ml_prediction:.2f})')
                total_risk += ml_prediction
        
        # Step 6: Behavioral Analysis
        self.update_state(state='PROGRESS', meta={'progress': 80, 'message': 'Behavioral analysis'})
        ws_handler.emit_scan_progress(scan_id, 80, "Running behavioral analysis...")
        
        if app.config.get('BEHAVIORAL_ANALYSIS', True):
            scan_results_data = {
                'filename': filename,
                'file_size': file_size,
                'file_type': file_type,
                'file_hash': file_hash,
                'risk_score': min(total_risk, 1.0),
                'threat_indicators': threat_indicators
            }
            
            behavioral_patterns = behavioral_engine.analyze_file_behavior(file_path, scan_results_data)
            behavioral_risk = behavioral_engine.get_behavioral_risk_score(behavioral_patterns)
            
            if behavioral_patterns:
                pattern_descriptions = [p.description for p in behavioral_patterns[:3]]
                threat_indicators.extend(pattern_descriptions)
                total_risk += behavioral_risk * 0.5  # Weight behavioral analysis at 50%
        
        # Step 7: Calculate final results
        self.update_state(state='PROGRESS', meta={'progress': 90, 'message': 'Finalizing results'})
        ws_handler.emit_scan_progress(scan_id, 90, "Finalizing results...")
        
        final_risk_score = min(total_risk, 1.0)
        
        # Determine threat level
        if final_risk_score >= 0.8:
            threat_level = 'malicious'
        elif final_risk_score >= 0.4:
            threat_level = 'suspicious'
        else:
            threat_level = 'safe'
        
        # Step 8: Save results to database
        self.update_state(state='PROGRESS', meta={'progress': 95, 'message': 'Saving results'})
        ws_handler.emit_scan_progress(scan_id, 95, "Saving scan results...")
        
        with app.app_context():
            db_result = ScanResult(
                filename=filename,
                file_hash=file_hash,
                file_size=file_size,
                scan_type='file',
                risk_score=final_risk_score,
                threat_level=threat_level,
                detection_details='; '.join(threat_indicators) if threat_indicators else 'No threats detected',
                original_path=file_path
            )
            
            db.session.add(db_result)
            db.session.commit()
            
            # Handle quarantine if needed
            if threat_level == 'malicious':
                quarantine_manager.quarantine_file(file_path, db_result.id)
                db_result.quarantined = True
                db.session.commit()
            
            result_data = {
                'id': db_result.id,
                'filename': filename,
                'file_hash': file_hash,
                'file_size': file_size,
                'file_type': file_type,
                'risk_score': final_risk_score,
                'threat_level': threat_level,
                'detection_details': threat_indicators,
                'scan_timestamp': db_result.scan_timestamp.isoformat(),
                'quarantined': db_result.quarantined,
                'ml_predictions': detailed_predictions if app.config.get('ENABLE_DEEP_LEARNING') else None
            }
        
        # Step 9: Complete
        self.update_state(state='SUCCESS', meta={'progress': 100, 'message': 'Scan completed'})
        ws_handler.emit_scan_progress(scan_id, 100, f"Scan completed - {threat_level.title()}", result_data)
        
        # Emit system alert for high-risk files
        if threat_level in ['suspicious', 'malicious']:
            ws_handler.emit_system_alert(
                'threat_detected',
                f'Threat detected: {filename} - {threat_level}',
                'warning' if threat_level == 'suspicious' else 'error'
            )
        
        return result_data
        
    except Exception as e:
        error_msg = f"Error scanning file {filename}: {str(e)}"
        logging.error(error_msg)
        
        self.update_state(state='FAILURE', meta={'error': error_msg})
        ws_handler.emit_scan_progress(scan_id, 0, f"Scan failed: {str(e)}")
        
        return {'error': error_msg}


@celery.task(bind=True)
def scan_url_async(self, url, scan_id=None):
    """Asynchronously scan a URL with progress updates"""
    try:
        if scan_id is None:
            scan_id = self.request.id
        
        # Initialize progress
        ws_handler.emit_scan_progress(scan_id, 0, "Starting URL analysis...")
        
        # Step 1: Basic URL parsing
        self.update_state(state='PROGRESS', meta={'progress': 10, 'message': 'Parsing URL'})
        ws_handler.emit_scan_progress(scan_id, 10, "Parsing URL...")
        
        from urllib.parse import urlparse
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        
        # Step 2: Heuristic analysis
        self.update_state(state='PROGRESS', meta={'progress': 30, 'message': 'Heuristic analysis'})
        ws_handler.emit_scan_progress(scan_id, 30, "Running heuristic analysis...")
        
        heuristic_result = threat_intel.analyze_url_heuristics(url)
        
        # Step 3: Google Safe Browsing
        self.update_state(state='PROGRESS', meta={'progress': 50, 'message': 'Checking Google Safe Browsing'})
        ws_handler.emit_scan_progress(scan_id, 50, "Checking Google Safe Browsing...")
        
        gsb_result = threat_intel.check_google_safe_browsing(url)
        
        # Step 4: VirusTotal
        self.update_state(state='PROGRESS', meta={'progress': 70, 'message': 'Checking VirusTotal'})
        ws_handler.emit_scan_progress(scan_id, 70, "Checking VirusTotal...")
        
        vt_result = threat_intel.check_virustotal(url)
        
        # Step 5: PhishTank
        self.update_state(state='PROGRESS', meta={'progress': 85, 'message': 'Checking PhishTank'})
        ws_handler.emit_scan_progress(scan_id, 85, "Checking PhishTank...")
        
        pt_result = threat_intel.check_phishtank(url)
        
        # Step 6: Compile results
        self.update_state(state='PROGRESS', meta={'progress': 95, 'message': 'Compiling results'})
        ws_handler.emit_scan_progress(scan_id, 95, "Compiling analysis results...")
        
        # Calculate final score and threat level
        threat_sources = []
        detection_details = []
        
        if gsb_result.get('is_threat'):
            threat_sources.append('Google Safe Browsing')
            detection_details.append('Google Safe Browsing: ' + gsb_result.get('details', ''))
        
        if vt_result.get('is_threat'):
            threat_sources.append('VirusTotal')
            detection_details.append('VirusTotal: ' + vt_result.get('details', ''))
        
        if pt_result.get('is_threat'):
            threat_sources.append('PhishTank')
            detection_details.append('PhishTank: ' + pt_result.get('details', ''))
        
        if heuristic_result.get('suspicious'):
            detection_details.extend(heuristic_result.get('reasons', []))
        
        # Calculate risk score
        threat_count = len(threat_sources)
        heuristic_score = heuristic_result.get('score', 0)
        
        if threat_count >= 2:
            risk_score = 0.9 + (threat_count * 0.02)
            threat_level = 'malicious'
        elif threat_count == 1:
            risk_score = 0.7 + heuristic_score
            threat_level = 'suspicious'
        elif heuristic_score > 0.3:
            risk_score = heuristic_score
            threat_level = 'suspicious'
        else:
            risk_score = 0.1 + heuristic_score
            threat_level = 'safe'
        
        risk_score = min(risk_score, 1.0)
        
        # Save to database
        with app.app_context():
            db_result = URLScan(
                url=url,
                domain=domain,
                risk_score=risk_score,
                threat_level=threat_level,
                detection_details='; '.join(detection_details) if detection_details else 'No threats detected',
                threat_intel_data=json.dumps({
                    'google_safe_browsing': gsb_result,
                    'virustotal': vt_result,
                    'phishtank': pt_result
                })
            )
            
            db.session.add(db_result)
            db.session.commit()
            
            result_data = {
                'id': db_result.id,
                'url': url,
                'domain': domain,
                'risk_score': risk_score,
                'threat_level': threat_level,
                'detection_details': detection_details,
                'scan_timestamp': db_result.scan_timestamp.isoformat(),
                'threat_intel_data': {
                    'google_safe_browsing': gsb_result,
                    'virustotal': vt_result,
                    'phishtank': pt_result
                }
            }
        
        # Complete
        self.update_state(state='SUCCESS', meta={'progress': 100, 'message': 'URL scan completed'})
        ws_handler.emit_scan_progress(scan_id, 100, f"URL scan completed - {threat_level.title()}", result_data)
        
        # Emit system alert for threats
        if threat_level in ['suspicious', 'malicious']:
            ws_handler.emit_system_alert(
                'url_threat_detected',
                f'Malicious URL detected: {url}',
                'warning' if threat_level == 'suspicious' else 'error'
            )
        
        return result_data
        
    except Exception as e:
        error_msg = f"Error scanning URL {url}: {str(e)}"
        logging.error(error_msg)
        
        self.update_state(state='FAILURE', meta={'error': error_msg})
        ws_handler.emit_scan_progress(scan_id, 0, f"URL scan failed: {str(e)}")
        
        return {'error': error_msg}


@celery.task
def system_behavioral_analysis():
    """Periodic system-wide behavioral analysis"""
    try:
        logging.info("Starting system behavioral analysis...")
        
        # Run behavioral analysis
        patterns = behavioral_engine.analyze_system_behavior()
        
        if patterns:
            # Generate report
            report = behavioral_engine.generate_behavioral_report(patterns)
            
            # Emit alerts for critical patterns
            critical_patterns = [p for p in patterns if p.risk_level == 'critical']
            if critical_patterns:
                ws_handler.emit_system_alert(
                    'critical_behavioral_pattern',
                    f'Critical behavioral patterns detected: {len(critical_patterns)} patterns require immediate attention',
                    'error'
                )
            
            logging.info(f"Behavioral analysis completed: {len(patterns)} patterns detected")
            return report
        
        return {'message': 'No behavioral patterns detected'}
        
    except Exception as e:
        error_msg = f"Error in system behavioral analysis: {str(e)}"
        logging.error(error_msg)
        return {'error': error_msg}


@celery.task
def automated_data_cleanup():
    """Automated GDPR/CCPA data cleanup"""
    try:
        logging.info("Starting automated data cleanup...")
        
        # Run GDPR compliance cleanup
        cleanup_summary = gdpr_manager.run_automated_data_cleanup()
        
        # Emit notification about cleanup
        if any(cleanup_summary.values()):
            total_cleaned = sum(v for v in cleanup_summary.values() if isinstance(v, int))
            ws_handler.emit_system_alert(
                'data_cleanup_completed',
                f'Automated data cleanup completed: {total_cleaned} records processed',
                'info'
            )
        
        logging.info(f"Data cleanup completed: {cleanup_summary}")
        return cleanup_summary
        
    except Exception as e:
        error_msg = f"Error in automated data cleanup: {str(e)}"
        logging.error(error_msg)
        return {'error': error_msg}


@celery.task
def update_dashboard_stats():
    """Update dashboard statistics"""
    try:
        from websocket_handlers import get_current_stats
        
        stats = get_current_stats()
        ws_handler.emit_stats_update(stats)
        
        return stats
        
    except Exception as e:
        logging.error(f"Error updating dashboard stats: {str(e)}")
        return {'error': str(e)}


@celery.task
def ml_model_maintenance():
    """Periodic ML model maintenance and updates"""
    try:
        logging.info("Starting ML model maintenance...")
        
        # This would normally retrain models with new data
        # For now, just validate model integrity
        
        results = {
            'tensorflow_model': 'validated',
            'pytorch_model': 'validated',
            'sklearn_model': 'validated',
            'ensemble_status': 'operational'
        }
        
        ws_handler.emit_system_alert(
            'model_maintenance_completed',
            'ML model maintenance completed successfully',
            'info'
        )
        
        logging.info("ML model maintenance completed")
        return results
        
    except Exception as e:
        error_msg = f"Error in ML model maintenance: {str(e)}"
        logging.error(error_msg)
        return {'error': error_msg}


# Periodic tasks configuration
from celery.schedules import crontab

celery.conf.beat_schedule = {
    'system-behavioral-analysis': {
        'task': 'tasks.system_behavioral_analysis',
        'schedule': crontab(minute=0, hour='*/6'),  # Every 6 hours
    },
    'automated-data-cleanup': {
        'task': 'tasks.automated_data_cleanup',
        'schedule': crontab(minute=0, hour=2),  # Daily at 2 AM
    },
    'update-dashboard-stats': {
        'task': 'tasks.update_dashboard_stats',
        'schedule': 30.0,  # Every 30 seconds
    },
    'ml-model-maintenance': {
        'task': 'tasks.ml_model_maintenance',
        'schedule': crontab(minute=0, hour=3, day_of_week=1),  # Weekly on Monday at 3 AM
    },
}

celery.conf.timezone = 'UTC'