-- SPAIDER PostgreSQL init script
-- Run automatically by docker-entrypoint when starting PostgreSQL

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";   -- trigram search

-- Grant privileges (tables created by SQLAlchemy on startup)
GRANT ALL PRIVILEGES ON DATABASE spaider TO spaider;
