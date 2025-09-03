import os
import shutil
import logging
from datetime import datetime
from app import db
from models import QuarantineItem, ScanResult

class QuarantineManager:
    """Manages quarantine operations for infected files"""
    
    def __init__(self):
        self.quarantine_folder = 'quarantine'
        os.makedirs(self.quarantine_folder, exist_ok=True)
    
    def quarantine_file(self, file_path, scan_result_id):
        """Move a file to quarantine"""
        try:
            if not os.path.exists(file_path):
                logging.error(f"File not found for quarantine: {file_path}")
                return False
            
            # Generate unique quarantine filename
            filename = os.path.basename(file_path)
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            quarantine_filename = f"{timestamp}_{filename}"
            quarantine_path = os.path.join(self.quarantine_folder, quarantine_filename)
            
            # Move file to quarantine
            shutil.move(file_path, quarantine_path)
            
            # Create quarantine record
            quarantine_item = QuarantineItem(
                scan_result_id=scan_result_id,
                filename=filename,
                original_path=file_path,
                quarantine_path=quarantine_path
            )
            
            db.session.add(quarantine_item)
            db.session.commit()
            
            # Update scan result
            scan_result = ScanResult.query.get(scan_result_id)
            if scan_result:
                scan_result.quarantine_path = quarantine_path
                scan_result.quarantined = True
                db.session.commit()
            
            logging.info(f"File quarantined: {filename} -> {quarantine_path}")
            return True
            
        except Exception as e:
            logging.error(f"Error quarantining file {file_path}: {str(e)}")
            db.session.rollback()
            return False
    
    def restore_file(self, quarantine_path, original_path):
        """Restore a file from quarantine to its original location"""
        try:
            if not os.path.exists(quarantine_path):
                logging.error(f"Quarantined file not found: {quarantine_path}")
                return False
            
            # Ensure the original directory exists
            original_dir = os.path.dirname(original_path)
            os.makedirs(original_dir, exist_ok=True)
            
            # If original path exists, create a backup name
            if os.path.exists(original_path):
                base, ext = os.path.splitext(original_path)
                counter = 1
                while os.path.exists(f"{base}_restored_{counter}{ext}"):
                    counter += 1
                original_path = f"{base}_restored_{counter}{ext}"
            
            # Move file back from quarantine
            shutil.move(quarantine_path, original_path)
            
            logging.info(f"File restored from quarantine: {quarantine_path} -> {original_path}")
            return True
            
        except Exception as e:
            logging.error(f"Error restoring file from quarantine: {str(e)}")
            return False
    
    def delete_file(self, quarantine_path):
        """Permanently delete a quarantined file"""
        try:
            if not os.path.exists(quarantine_path):
                logging.warning(f"Quarantined file not found for deletion: {quarantine_path}")
                return True  # Consider it deleted if it doesn't exist
            
            # Permanently delete the file
            os.remove(quarantine_path)
            
            logging.info(f"Quarantined file permanently deleted: {quarantine_path}")
            return True
            
        except Exception as e:
            logging.error(f"Error deleting quarantined file: {str(e)}")
            return False
    
    def list_quarantined_files(self):
        """List all files currently in quarantine"""
        try:
            quarantine_items = db.session.query(QuarantineItem, ScanResult).join(
                ScanResult, QuarantineItem.scan_result_id == ScanResult.id
            ).filter(
                QuarantineItem.deleted == False,
                QuarantineItem.restored == False
            ).all()
            
            return quarantine_items
            
        except Exception as e:
            logging.error(f"Error listing quarantined files: {str(e)}")
            return []
    
    def get_quarantine_statistics(self):
        """Get statistics about quarantined files"""
        try:
            total_quarantined = QuarantineItem.query.count()
            currently_quarantined = QuarantineItem.query.filter_by(
                deleted=False, restored=False
            ).count()
            restored_count = QuarantineItem.query.filter_by(restored=True).count()
            deleted_count = QuarantineItem.query.filter_by(deleted=True).count()
            
            return {
                'total_quarantined': total_quarantined,
                'currently_quarantined': currently_quarantined,
                'restored': restored_count,
                'deleted': deleted_count
            }
            
        except Exception as e:
            logging.error(f"Error getting quarantine statistics: {str(e)}")
            return {
                'total_quarantined': 0,
                'currently_quarantined': 0,
                'restored': 0,
                'deleted': 0
            }
    
    def cleanup_old_quarantine(self, days_old=30):
        """Clean up quarantine files older than specified days"""
        try:
            cutoff_date = datetime.utcnow() - timedelta(days=days_old)
            
            old_items = QuarantineItem.query.filter(
                QuarantineItem.quarantine_timestamp < cutoff_date,
                QuarantineItem.deleted == False
            ).all()
            
            deleted_count = 0
            for item in old_items:
                if self.delete_file(item.quarantine_path):
                    item.deleted = True
                    item.deleted_timestamp = datetime.utcnow()
                    deleted_count += 1
            
            db.session.commit()
            
            logging.info(f"Cleaned up {deleted_count} old quarantine files")
            return deleted_count
            
        except Exception as e:
            logging.error(f"Error cleaning up old quarantine files: {str(e)}")
            db.session.rollback()
            return 0
