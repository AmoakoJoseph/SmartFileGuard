import os
import logging
import redis
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from sqlalchemy.orm import DeclarativeBase
from werkzeug.middleware.proxy_fix import ProxyFix
from celery import Celery

# Configure logging
logging.basicConfig(level=logging.DEBUG)

# Initialize Redis for rate limiting and caching
try:
    redis_client = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)
    redis_client.ping()
except:
    # Fallback to memory-based rate limiting if Redis is not available
    redis_client = None
    logging.warning("Redis not available, using memory-based rate limiting")

class Base(DeclarativeBase):
    pass

db = SQLAlchemy(model_class=Base)

# Create the app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "dev-secret-key-change-in-production")
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Initialize security extensions
csrf = CSRFProtect(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')

# Initialize rate limiter
limiter = Limiter(
    key_func=get_remote_address,
    storage_uri="redis://localhost:6379" if redis_client else "memory://",
    default_limits=["200 per day", "50 per hour"]
)
limiter.init_app(app)

# Configure Celery for background tasks
app.config['CELERY_BROKER_URL'] = 'redis://localhost:6379/0'
app.config['CELERY_RESULT_BACKEND'] = 'redis://localhost:6379/0'

def make_celery(app):
    celery = Celery(
        app.import_name,
        backend=app.config['CELERY_RESULT_BACKEND'],
        broker=app.config['CELERY_BROKER_URL']
    )
    celery.conf.update(app.config)
    return celery

celery = make_celery(app)

# Configure the database
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///smartfileguardian.db")
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}

# Configure upload settings
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB max file size
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['QUARANTINE_FOLDER'] = 'quarantine'

# Security configurations
app.config['WTF_CSRF_TIME_LIMIT'] = 3600  # 1 hour CSRF token validity
app.config['WTF_CSRF_SSL_STRICT'] = False  # For development
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('FLASK_ENV') == 'production'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# GDPR/CCPA compliance settings
app.config['DATA_RETENTION_DAYS'] = int(os.environ.get('DATA_RETENTION_DAYS', '90'))
app.config['ENABLE_GDPR_COMPLIANCE'] = os.environ.get('ENABLE_GDPR_COMPLIANCE', 'true').lower() == 'true'
app.config['PRIVACY_POLICY_VERSION'] = os.environ.get('PRIVACY_POLICY_VERSION', '1.0')

# Advanced ML model settings
app.config['ENABLE_DEEP_LEARNING'] = os.environ.get('ENABLE_DEEP_LEARNING', 'true').lower() == 'true'
app.config['MODEL_UPDATE_INTERVAL'] = int(os.environ.get('MODEL_UPDATE_INTERVAL', '24'))  # hours
app.config['BEHAVIORAL_ANALYSIS'] = os.environ.get('BEHAVIORAL_ANALYSIS', 'true').lower() == 'true'

# Initialize the app with the extension
db.init_app(app)

# Create upload and quarantine directories
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['QUARANTINE_FOLDER'], exist_ok=True)

with app.app_context():
    # Import models to ensure tables are created
    import models
    db.create_all()
    
    # Import enhanced components
    try:
        import websocket_handlers
        import tasks
    except ImportError as e:
        logging.warning(f"Could not import enhanced features: {e}")
    
    # Import routes
    import routes

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
