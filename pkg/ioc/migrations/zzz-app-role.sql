-- =========================================================================
-- AegisGate Platform — Application Role for RLS Enforcement (Init Script)
-- =========================================================================
-- This script creates a non-superuser application role (aegisgate_app)
-- that is subject to FORCE RLS policies. The Docker POSTGRES_USER creates
-- a superuser that bypasses all RLS — this separate role ensures RLS
-- policies actually fire for the application.
--
-- Docker initdb scripts run alphabetically, so this file starts with
-- "zzz_" to run after all numbered migrations.
-- =========================================================================

-- Create the application role (non-superuser, no BYPASSRLS)
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aegisgate_app') THEN
        CREATE ROLE aegisgate_app LOGIN PASSWORD 'aegisgate_app_pass' NOSUPERUSER NOBYPASSRLS;
    END IF;
END $$;

-- Grant CREATE on schema (needed for creating temp tables, schema migrations)
GRANT USAGE, CREATE ON SCHEMA public TO aegisgate_app;

-- Grant privileges on ALL existing tables and sequences
-- (migrations already ran, so all tables exist)
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO aegisgate_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO aegisgate_app;

-- Grant default privileges for future tables (created by migrations)
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO aegisgate_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO aegisgate_app;

-- Also grant default privileges for the aegisgate superuser (who creates tables via migrations)
DO $$
BEGIN
    -- Grant default privileges as the aegisgate superuser so future
    -- tables created by migrations are accessible to aegisgate_app
    EXECUTE 'ALTER DEFAULT PRIVILEGES FOR ROLE aegisgate IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO aegisgate_app';
    EXECUTE 'ALTER DEFAULT PRIVILEGES FOR ROLE aegisgate IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO aegisgate_app';
EXCEPTION WHEN OTHERS THEN
    -- Ignore if already set or if role doesn't exist
    RAISE NOTICE 'Default privileges already set or error: %', SQLERRM;
END $$;