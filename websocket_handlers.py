import logging
import json
import time
from datetime import datetime
from flask import request
from flask_socketio import emit, join_room, leave_room, disconnect
from app import socketio, db
from models import ScanResult, URLScan, ActivityLog
from celery import current_task

class WebSocketHandler:
    """Handle WebSocket connections and real-time updates"""
    
    def __init__(self):
        self.active_connections = {}
        self.scan_progress = {}
    
    def emit_scan_progress(self, scan_id: str, progress: int, message: str, data: dict = None):
        """Emit scan progress update to connected clients"""
        try:
            update_data = {
                'scan_id': scan_id,
                'progress': progress,
                'message': message,
                'timestamp': datetime.utcnow().isoformat(),
                'data': data or {}
            }
            
            socketio.emit('scan_progress', update_data, room=f'scan_{scan_id}')
            
            # Store progress for disconnected clients
            self.scan_progress[scan_id] = update_data
            
        except Exception as e:
            logging.error(f"Error emitting scan progress: {str(e)}")
    
    def emit_system_alert(self, alert_type: str, message: str, severity: str = 'info'):
        """Emit system-wide alerts"""
        try:
            alert_data = {
                'type': alert_type,
                'message': message,
                'severity': severity,
                'timestamp': datetime.utcnow().isoformat()
            }
            
            socketio.emit('system_alert', alert_data, broadcast=True)
            
        except Exception as e:
            logging.error(f"Error emitting system alert: {str(e)}")
    
    def emit_stats_update(self, stats: dict):
        """Emit dashboard statistics update"""
        try:
            stats_data = {
                'stats': stats,
                'timestamp': datetime.utcnow().isoformat()
            }
            
            socketio.emit('stats_update', stats_data, room='dashboard')
            
        except Exception as e:
            logging.error(f"Error emitting stats update: {str(e)}")


# Initialize WebSocket handler
ws_handler = WebSocketHandler()


@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    try:
        client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
        session_id = request.sid
        
        ws_handler.active_connections[session_id] = {
            'ip': client_ip,
            'connected_at': datetime.utcnow(),
            'rooms': []
        }
        
        logging.info(f"WebSocket client connected: {session_id} from {client_ip}")
        
        # Send initial connection confirmation
        emit('connection_confirmed', {
            'session_id': session_id,
            'server_time': datetime.utcnow().isoformat(),
            'message': 'Connected to SmartFileGuardian real-time updates'
        })
        
    except Exception as e:
        logging.error(f"Error handling WebSocket connect: {str(e)}")


@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    try:
        session_id = request.sid
        
        if session_id in ws_handler.active_connections:
            connection_info = ws_handler.active_connections[session_id]
            client_ip = connection_info['ip']
            
            # Leave all rooms
            for room in connection_info['rooms']:
                leave_room(room)
            
            del ws_handler.active_connections[session_id]
            
            logging.info(f"WebSocket client disconnected: {session_id} from {client_ip}")
        
    except Exception as e:
        logging.error(f"Error handling WebSocket disconnect: {str(e)}")


@socketio.on('join_scan_room')
def handle_join_scan_room(data):
    """Allow client to join a specific scan room for updates"""
    try:
        scan_id = data.get('scan_id')
        if not scan_id:
            emit('error', {'message': 'Scan ID required'})
            return
        
        room = f'scan_{scan_id}'
        join_room(room)
        
        session_id = request.sid
        if session_id in ws_handler.active_connections:
            ws_handler.active_connections[session_id]['rooms'].append(room)
        
        # Send any existing progress for this scan
        if scan_id in ws_handler.scan_progress:
            emit('scan_progress', ws_handler.scan_progress[scan_id])
        
        emit('joined_room', {'room': room, 'scan_id': scan_id})
        logging.info(f"Client {session_id} joined scan room: {room}")
        
    except Exception as e:
        logging.error(f"Error joining scan room: {str(e)}")
        emit('error', {'message': 'Failed to join scan room'})


@socketio.on('leave_scan_room')
def handle_leave_scan_room(data):
    """Allow client to leave a specific scan room"""
    try:
        scan_id = data.get('scan_id')
        if not scan_id:
            emit('error', {'message': 'Scan ID required'})
            return
        
        room = f'scan_{scan_id}'
        leave_room(room)
        
        session_id = request.sid
        if session_id in ws_handler.active_connections:
            if room in ws_handler.active_connections[session_id]['rooms']:
                ws_handler.active_connections[session_id]['rooms'].remove(room)
        
        emit('left_room', {'room': room, 'scan_id': scan_id})
        logging.info(f"Client {session_id} left scan room: {room}")
        
    except Exception as e:
        logging.error(f"Error leaving scan room: {str(e)}")
        emit('error', {'message': 'Failed to leave scan room'})


@socketio.on('join_dashboard')
def handle_join_dashboard():
    """Allow client to join dashboard room for stats updates"""
    try:
        join_room('dashboard')
        
        session_id = request.sid
        if session_id in ws_handler.active_connections:
            ws_handler.active_connections[session_id]['rooms'].append('dashboard')
        
        # Send current stats
        stats = get_current_stats()
        emit('stats_update', {
            'stats': stats,
            'timestamp': datetime.utcnow().isoformat()
        })
        
        emit('joined_dashboard', {'message': 'Joined dashboard updates'})
        logging.info(f"Client {session_id} joined dashboard room")
        
    except Exception as e:
        logging.error(f"Error joining dashboard: {str(e)}")
        emit('error', {'message': 'Failed to join dashboard'})


@socketio.on('request_scan_status')
def handle_scan_status_request(data):
    """Handle request for scan status"""
    try:
        scan_id = data.get('scan_id')
        if not scan_id:
            emit('error', {'message': 'Scan ID required'})
            return
        
        # Look up scan result
        scan_result = ScanResult.query.get(scan_id)
        if scan_result:
            status_data = {
                'scan_id': scan_id,
                'status': 'completed',
                'filename': scan_result.filename,
                'threat_level': scan_result.threat_level,
                'risk_score': scan_result.risk_score,
                'scan_timestamp': scan_result.scan_timestamp.isoformat()
            }
        else:
            # Check if scan is in progress
            if scan_id in ws_handler.scan_progress:
                status_data = ws_handler.scan_progress[scan_id]
                status_data['status'] = 'in_progress'
            else:
                status_data = {
                    'scan_id': scan_id,
                    'status': 'not_found',
                    'message': 'Scan not found'
                }
        
        emit('scan_status', status_data)
        
    except Exception as e:
        logging.error(f"Error handling scan status request: {str(e)}")
        emit('error', {'message': 'Failed to get scan status'})


@socketio.on('ping')
def handle_ping():
    """Handle ping from client"""
    emit('pong', {'timestamp': datetime.utcnow().isoformat()})


def get_current_stats():
    """Get current system statistics for dashboard"""
    try:
        total_scans = ScanResult.query.count() + URLScan.query.count()
        
        # Get threat level distribution
        safe_count = ScanResult.query.filter_by(threat_level='safe').count()
        suspicious_count = ScanResult.query.filter_by(threat_level='suspicious').count()
        malicious_count = ScanResult.query.filter_by(threat_level='malicious').count()
        
        # Get quarantine count
        from models import QuarantineItem
        quarantine_count = QuarantineItem.query.filter_by(deleted=False, restored=False).count()
        
        # Get recent activity count (last hour)
        one_hour_ago = datetime.utcnow() - timedelta(hours=1)
        recent_activity = ActivityLog.query.filter(
            ActivityLog.timestamp >= one_hour_ago
        ).count()
        
        return {
            'total_scans': total_scans,
            'safe_count': safe_count,
            'suspicious_count': suspicious_count,
            'malicious_count': malicious_count,
            'quarantine_count': quarantine_count,
            'recent_activity': recent_activity,
            'system_status': 'online'
        }
        
    except Exception as e:
        logging.error(f"Error getting current stats: {str(e)}")
        return {
            'total_scans': 0,
            'safe_count': 0,
            'suspicious_count': 0,
            'malicious_count': 0,
            'quarantine_count': 0,
            'recent_activity': 0,
            'system_status': 'error'
        }