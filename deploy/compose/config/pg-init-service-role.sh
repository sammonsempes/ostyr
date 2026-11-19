#!/bin/bash
set -euo pipefail
psql -v ON_ERROR_STOP=1 --username postgres --dbname postgres <<'SQL'
\set service_password `cat /run/pgtls/service_password`
CREATE ROLE ostyr_service LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD :'service_password';
CREATE DATABASE ostyr OWNER ostyr_service;
REVOKE ALL ON DATABASE ostyr FROM PUBLIC;
SQL
