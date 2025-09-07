# SmartFileGuard v2.0 - Advanced Edition

SmartFileGuard is a comprehensive AI-powered malware detection and threat analysis platform that combines advanced machine learning models, real-time scanning, behavioral analysis, and enterprise-grade security features.

## 🚀 Key Features

### Core Capabilities
- **Multi-Engine File Scanning**: Advanced malware detection using TensorFlow, PyTorch, and scikit-learn models
- **Real-Time URL Analysis**: Comprehensive threat intelligence using Google Safe Browsing, VirusTotal, and PhishTank APIs
- **Smart Quarantine System**: Secure isolation and management of infected files with restoration capabilities
- **Behavioral Analysis Engine**: Advanced pattern detection for sophisticated threat identification

### Advanced Features
- **Real-Time Updates**: WebSocket-powered live scan progress and system monitoring
- **Async Processing**: Celery-based background task processing for scalable operations
- **Enterprise Security**: CSRF protection, rate limiting, input validation, and secure session handling
- **Privacy Compliance**: Full GDPR/CCPA compliance with automated data management
- **Production Ready**: Complete Docker containerization with nginx, PostgreSQL, Redis

## 🏗️ System Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Web Interface │    │  API Endpoints  │    │   WebSocket     │
│   (Bootstrap)   │◄──►│    (Flask)      │◄──►│   Handlers      │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Flask Application Core                       │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌────────────┐ │
│  │File Scanner │ │Threat Intel │ │ML Models    │ │GDPR Manager│ │
│  │             │ │             │ │TF/PyTorch   │ │            │ │
│  └─────────────┘ └─────────────┘ └─────────────┘ └────────────┘ │
└─────────────────────────────────────────────────────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  PostgreSQL DB  │    │  Redis Cache    │    │ Celery Workers  │
│   (Primary)     │    │  (Sessions)     │    │ (Background)    │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## 📋 Prerequisites

### System Requirements
- **Python**: 3.11 or higher
- **Memory**: Minimum 4GB RAM (8GB+ recommended for ML models)
- **Storage**: At least 2GB free space
- **Network**: Internet connection for threat intelligence APIs

### Development Tools
- **IDE**: VS Code, PyCharm, or any Python-compatible IDE
- **Package Manager**: UV (recommended) or pip
- **Database**: PostgreSQL (production) or SQLite (development)
- **Optional**: Docker and Docker Compose for containerized deployment

## 🛠️ Installation & Setup

### Method 1: Local Development Setup

#### 1. Clone the Repository
```bash
git clone <your-repository-url>
cd smartfileguardian
```

#### 2. Install UV Package Manager (Recommended)
```bash
# On macOS/Linux
curl -LsSf https://astral.sh/uv/install.sh | sh

# On Windows
powershell -c "irm https://astral.sh/uv/install.ps1 | iex"
```

#### 3. Create Virtual Environment and Install Dependencies
```bash
# Using UV (Recommended)
uv sync

# Alternative: Using pip
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

#### 4. Environment Configuration
Create a `.env` file in the project root:
```bash
# Database Configuration
DATABASE_URL=sqlite:///smartfileguardian.db
# For PostgreSQL: DATABASE_URL=postgresql://username:password@localhost:5432/smartfileguardian

# Security
SESSION_SECRET=your-super-secret-session-key-change-this
CSRF_SECRET_KEY=your-csrf-secret-key

# Feature Flags
ENABLE_DEEP_LEARNING=true
BEHAVIORAL_ANALYSIS=true
ENABLE_GDPR_COMPLIANCE=true

# Privacy & Compliance
PRIVACY_POLICY_VERSION=1.0
DATA_RETENTION_DAYS=90

# External APIs (Optional - Get free API keys)
GOOGLE_SAFE_BROWSING_API_KEY=your_gsb_api_key
VIRUSTOTAL_API_KEY=your_vt_api_key
PHISHTANK_API_KEY=your_phishtank_api_key

# Redis (Optional - for production)
REDIS_URL=redis://localhost:6379/0

# Model Configuration
MODEL_UPDATE_INTERVAL=24
```

#### 5. Initialize Database
```bash
# The app will automatically create tables on first run
python main.py
```

#### 6. Run the Application
```bash
# Development mode
python main.py

# Production mode with Gunicorn
gunicorn --bind 0.0.0.0:5000 --workers 4 main:app
```

Access the application at `http://localhost:5000`

### Method 2: Docker Deployment (Recommended for Production)

#### 1. Prerequisites
```bash
# Install Docker and Docker Compose
# Visit: https://docs.docker.com/get-docker/
```

#### 2. Configuration
Update `docker-compose.yml` environment variables:
```yaml
environment:
  - SESSION_SECRET=change-this-secret-key-in-production
  - GOOGLE_SAFE_BROWSING_API_KEY=your_api_key
  - VIRUSTOTAL_API_KEY=your_api_key
  - PHISHTANK_API_KEY=your_api_key
```

#### 3. Build and Deploy
```bash
# Build and start all services
docker-compose up -d

# View logs
docker-compose logs -f

# Scale workers (optional)
docker-compose up -d --scale worker=3

# Stop services
docker-compose down
```

#### 4. Access Services
- **Main Application**: http://localhost:5000
- **Flower (Celery Monitoring)**: http://localhost:5555
- **PostgreSQL**: localhost:5432
- **Redis**: localhost:6379

## 🔧 IDE Setup Instructions

### VS Code Setup

#### 1. Install Extensions
```json
{
  "recommendations": [
    "ms-python.python",
    "ms-python.black-formatter",
    "ms-python.isort",
    "ms-python.flake8",
    "bradlc.vscode-tailwindcss",
    "ms-vscode.vscode-json"
  ]
}
```

#### 2. Configure Settings (`.vscode/settings.json`)
```json
{
  "python.defaultInterpreterPath": "./venv/bin/python",
  "python.terminal.activateEnvironment": true,
  "python.formatting.provider": "black",
  "python.linting.enabled": true,
  "python.linting.flake8Enabled": true,
  "files.exclude": {
    "**/__pycache__": true,
    "**/*.pyc": true,
    ".pytest_cache": true,
    ".coverage": true
  }
}
```

#### 3. Debug Configuration (`.vscode/launch.json`)
```json
{
  "version": "0.2.0",
  "configurations": [
    {
      "name": "Flask App",
      "type": "python",
      "request": "launch",
      "program": "main.py",
      "env": {
        "FLASK_ENV": "development",
        "FLASK_DEBUG": "1"
      },
      "args": [],
      "console": "integratedTerminal"
    }
  ]
}
```

### PyCharm Setup

#### 1. Project Configuration
- **File → Open** → Select project directory
- **File → Settings → Project → Python Interpreter**
- Select the virtual environment: `./venv/bin/python`

#### 2. Run Configuration
- **Run → Edit Configurations**
- **Add New → Python**
- **Script path**: `/path/to/main.py`
- **Environment variables**: Add `.env` variables
- **Working directory**: Project root

## 📁 Project Structure

```
smartfileguardian/
├── 📂 app.py                     # Flask application factory
├── 📂 main.py                    # Application entry point
├── 📂 models.py                  # Database models
├── 📂 routes.py                  # Web routes and API endpoints
├── 📂 file_scanner.py            # Core file scanning engine
├── 📂 threat_intel.py            # Threat intelligence integration
├── 📂 quarantine.py              # Quarantine management system
├── 📂 advanced_ml_models.py      # TensorFlow/PyTorch models
├── 📂 behavioral_analysis.py     # Behavioral pattern analysis
├── 📂 gdpr_compliance.py         # Privacy compliance manager
├── 📂 websocket_handlers.py      # Real-time WebSocket handlers
├── 📂 tasks.py                   # Celery background tasks
├── 📂 utils.py                   # Utility functions
├── 📂 templates/                 # Jinja2 HTML templates
│   ├── base.html                # Base template
│   ├── index.html               # Dashboard
│   ├── scan_results.html        # Scan results
│   ├── async_scan_results.html  # Real-time scan results
│   ├── quarantine.html          # Quarantine management
│   └── deployment_status.html   # System status
├── 📂 static/                    # Static assets
│   ├── css/                     # Stylesheets
│   ├── js/                      # JavaScript files
│   └── img/                     # Images
├── 📂 uploads/                   # File upload directory
├── 📂 quarantine/                # Quarantined files
├── 📂 data/                      # Application data
├── 📂 models/                    # ML model files
├── 📂 logs/                      # Application logs
├── 📂 docker-compose.yml         # Docker services configuration
├── 📂 Dockerfile                 # Docker image definition
├── 📂 nginx.conf                 # Nginx configuration
├── 📂 requirements.txt           # Python dependencies
└── 📂 .env.example              # Environment variables template
```

## 🔍 How It Works

### File Scanning Process
1. **File Upload**: User uploads files through web interface
2. **Async Processing**: Files queued for background scanning
3. **Multi-Engine Analysis**:
   - Basic security checks (size, extension, signature)
   - Machine learning classification (TensorFlow, PyTorch, scikit-learn)
   - Behavioral pattern analysis
   - Threat intelligence lookup
4. **Real-Time Updates**: Progress broadcast via WebSocket
5. **Results & Quarantine**: Malicious files automatically quarantined
6. **Reporting**: Detailed analysis results presented to user

### URL Analysis Process
1. **URL Submission**: User enters URL for analysis
2. **Heuristic Analysis**: Pattern-based initial assessment
3. **Threat Intelligence**: 
   - Google Safe Browsing API check
   - VirusTotal reputation lookup  
   - PhishTank phishing database
4. **Risk Scoring**: Weighted threat assessment
5. **Results Display**: Comprehensive threat analysis

### Machine Learning Pipeline
1. **Feature Extraction**: File characteristics, entropy, structure analysis
2. **Ensemble Prediction**: 
   - TensorFlow deep neural network
   - PyTorch convolutional model
   - Scikit-learn random forest
3. **Behavioral Analysis**: Runtime behavior pattern detection
4. **Confidence Scoring**: Weighted ensemble decision
5. **Continuous Learning**: Model updates with new threat data

## 🛡️ Security Features

### Application Security
- **CSRF Protection**: Form-based request validation
- **Rate Limiting**: API and upload rate controls
- **Input Validation**: Comprehensive data sanitization
- **Secure Sessions**: Encrypted session management
- **File Upload Safety**: Extension and content validation

### Privacy & Compliance
- **GDPR Compliance**: 
  - Data access requests
  - Right to deletion
  - Data portability
  - Automated retention policies
- **CCPA Ready**: California privacy law compliance
- **Data Minimization**: Collect only necessary information
- **Anonymization**: IP address and user agent anonymization

## 🔧 Configuration Options

### Environment Variables
```bash
# Core Settings
FLASK_ENV=development|production
DATABASE_URL=database_connection_string
SESSION_SECRET=your_secret_key

# Feature Toggles  
ENABLE_DEEP_LEARNING=true|false
BEHAVIORAL_ANALYSIS=true|false
ENABLE_GDPR_COMPLIANCE=true|false

# Performance
CELERY_BROKER_URL=redis://localhost:6379/0
CELERY_RESULT_BACKEND=redis://localhost:6379/0
MAX_CONTENT_LENGTH=104857600  # 100MB

# Security
UPLOAD_FOLDER=./uploads
QUARANTINE_FOLDER=./quarantine
ALLOWED_EXTENSIONS=txt,pdf,png,jpg,jpeg,gif,doc,docx,zip,exe,dll

# Privacy
DATA_RETENTION_DAYS=90
PRIVACY_POLICY_VERSION=1.0
```

## 📊 Monitoring & Health Checks

### Health Check Endpoint
```bash
curl http://localhost:5000/api/health
```

### Celery Monitoring
Access Flower dashboard at `http://localhost:5555` to monitor:
- Active tasks
- Worker status
- Task history
- Performance metrics

### System Status
Visit `/deployment-status` for comprehensive system information:
- Feature availability
- Database connectivity
- ML model status
- Security configuration

## 🚨 Troubleshooting

### Common Issues

#### Database Connection Error
```bash
# Check PostgreSQL status
sudo service postgresql status

# Reset database
rm smartfileguardian.db  # For SQLite
python -c "from app import db; db.create_all()"
```

#### ML Models Not Loading
```bash
# Check TensorFlow installation
python -c "import tensorflow as tf; print(tf.__version__)"

# Check PyTorch installation  
python -c "import torch; print(torch.__version__)"

# Reinstall ML dependencies
pip install tensorflow torch scikit-learn
```

#### WebSocket Issues
```bash
# Check Redis connection (for production)
redis-cli ping

# Restart application
docker-compose restart app
```

#### File Upload Problems
```bash
# Check upload directory permissions
chmod 755 uploads/
chmod 755 quarantine/

# Check disk space
df -h
```

### Getting Help

1. **Check Logs**: Application logs are in `logs/` directory
2. **Health Check**: Visit `/api/health` for system status
3. **Debug Mode**: Set `FLASK_ENV=development` for detailed errors
4. **Docker Logs**: `docker-compose logs -f app`

## 🔄 Updates & Maintenance

### Updating the Application
```bash
# Pull latest changes
git pull origin main

# Update dependencies
uv sync  # or pip install -r requirements.txt

# Restart services
docker-compose restart
```

### Database Maintenance
```bash
# Backup database
pg_dump smartfileguardian > backup.sql

# Run GDPR cleanup
curl -X POST http://localhost:5000/api/cleanup
```

### Model Updates
- ML models auto-update based on `MODEL_UPDATE_INTERVAL`
- Manual update: restart application to retrain models

## 📈 Performance Optimization

### Production Recommendations
- **Workers**: Scale Celery workers based on CPU cores
- **Database**: Use PostgreSQL with connection pooling
- **Cache**: Enable Redis for session storage
- **Proxy**: Use nginx for static file serving and load balancing
- **Monitoring**: Set up application performance monitoring

### Resource Usage
- **Memory**: 2-8GB depending on ML model complexity
- **CPU**: Multi-core recommended for parallel processing
- **Storage**: Plan for uploaded files and quarantine space
- **Network**: Bandwidth for threat intelligence API calls

## 📜 License & Security

This application is designed for educational and enterprise security purposes. Ensure compliance with:
- Local data protection regulations
- Threat intelligence API terms of service  
- File handling security best practices
- Privacy policy requirements

---

**SmartFileGuard v2.0** - Advanced AI-Powered Malware Detection System
Built with Flask, TensorFlow, PyTorch, and enterprise security in mind.