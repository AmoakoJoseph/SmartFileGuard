-- Initialize PostgreSQL database for SmartFileGuardian

-- Create database (this is handled by docker-compose environment variables)
-- CREATE DATABASE smartfileguardian;

-- Create extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";
CREATE EXTENSION IF NOT EXISTS "btree_gin";

-- Create indexes for performance
-- These will be created by SQLAlchemy, but we can add custom ones here

-- Index for frequent scan lookups
-- CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_scan_results_timestamp 
--     ON scan_results (scan_timestamp DESC);
-- CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_scan_results_threat_level 
--     ON scan_results (threat_level);
-- CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_scan_results_hash 
--     ON scan_results (file_hash);

-- Index for URL scans
-- CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_url_scans_timestamp 
--     ON url_scans (scan_timestamp DESC);
-- CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_url_scans_domain 
--     ON url_scans (domain);

-- Index for activity logs
-- CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_activity_logs_timestamp 
--     ON activity_logs (timestamp DESC);
-- CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_activity_logs_action 
--     ON activity_logs (action);

-- Index for quarantine items
-- CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_quarantine_items_timestamp 
--     ON quarantine_items (quarantine_timestamp DESC);

-- Create database user for the application (optional - using default postgres user)
-- CREATE USER smartguardian WITH PASSWORD 'smartguardian';
-- GRANT ALL PRIVILEGES ON DATABASE smartfileguardian TO smartguardian;

-- Set timezone
SET timezone = 'UTC';

-- Performance tunings
ALTER SYSTEM SET shared_preload_libraries = 'pg_stat_statements';
ALTER SYSTEM SET max_connections = '200';
ALTER SYSTEM SET shared_buffers = '256MB';
ALTER SYSTEM SET effective_cache_size = '1GB';
ALTER SYSTEM SET maintenance_work_mem = '64MB';
ALTER SYSTEM SET checkpoint_completion_target = 0.9;
ALTER SYSTEM SET wal_buffers = '16MB';
ALTER SYSTEM SET default_statistics_target = 100;
ALTER SYSTEM SET random_page_cost = 1.1;
ALTER SYSTEM SET effective_io_concurrency = 200;

-- Reload configuration
SELECT pg_reload_conf();