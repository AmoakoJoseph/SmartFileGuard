# SmartFileGuardian

## Overview

SmartFileGuardian is an AI-powered malware detection web application built with Flask that provides comprehensive threat analysis for files and URLs. The system combines machine learning models with threat intelligence APIs to deliver real-time security scanning, quarantine management, and activity monitoring. It features a responsive web interface with drag-and-drop file uploads, URL analysis, and detailed reporting capabilities for security professionals and end users.

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

### Backend Architecture
The application uses Flask as the web framework with SQLAlchemy ORM for database operations. The backend follows a modular design pattern with separate components for different security functions:

- **File Scanner (`file_scanner.py`)**: Handles file analysis including hash calculation, file type detection, and security checks
- **ML Models (`ml_models.py`)**: Implements machine learning-based malware detection using scikit-learn with feature extraction and entropy calculations
- **Threat Intelligence (`threat_intel.py`)**: Integrates with external APIs (Google Safe Browsing, VirusTotal, PhishTank) for URL and domain reputation analysis
- **Quarantine Manager (`quarantine.py`)**: Manages secure isolation of infected files with restore/delete capabilities

### Database Design
Uses SQLAlchemy with support for both SQLite (development) and PostgreSQL (production). The schema includes:

- **ScanResult**: Stores file scan results with risk scores and threat levels
- **URLScan**: Tracks URL analysis results and threat intelligence data
- **QuarantineItem**: Manages quarantined files with restoration tracking
- **ActivityLog**: Records system events and user actions
- **SystemMetrics**: Monitors performance and health metrics

### Frontend Architecture
Bootstrap-based responsive interface with dark theme support. Uses vanilla JavaScript for drag-and-drop file uploads, real-time progress updates, and dynamic content loading. The interface provides:

- Dashboard with security statistics and recent activity
- File upload with batch processing support
- URL analysis form with validation
- Quarantine management interface
- System monitoring and activity logs

### Security Implementation
- File size limits (100MB) and extension validation
- Secure file handling with quarantine isolation
- Environment-based configuration for API keys
- Session management with configurable secret keys
- Proxy handling for production deployments

## External Dependencies

### Machine Learning Libraries
- **scikit-learn**: Primary ML framework for malware classification models
- **numpy**: Numerical operations for feature extraction
- **python-magic**: File type detection and signature analysis

### Threat Intelligence APIs
- **Google Safe Browsing API**: URL reputation and malware detection
- **VirusTotal API**: File hash and URL analysis
- **PhishTank API**: Phishing URL detection

### Web Framework & Database
- **Flask**: Web application framework with SQLAlchemy ORM
- **SQLite/PostgreSQL**: Database backends for development and production
- **Bootstrap 5**: Frontend UI framework with dark theme
- **Font Awesome**: Icon library for UI elements

### File Processing
- **Werkzeug**: Secure filename handling and file uploads
- **hashlib**: File hash calculations for integrity checking
- **magic**: MIME type detection for uploaded files

### Production Services
- **ProxyFix**: Production deployment with reverse proxy support
- Configurable database connection pooling for scalability
- Environment-based configuration for API keys and secrets