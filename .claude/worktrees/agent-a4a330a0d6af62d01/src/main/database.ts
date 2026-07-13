import Database from 'better-sqlite3';
import path from 'path';
import { app } from 'electron';

let db: Database.Database;

export function initDatabase(): Database.Database {
  const dbPath = path.join(app.getPath('userData'), 'hackme.db');
  db = new Database(dbPath);
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');
  createTables(db);
  return db;
}

function createTables(db: Database.Database) {
  db.exec(`
    CREATE TABLE IF NOT EXISTS projects (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      target_url TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS scans (
      id TEXT PRIMARY KEY,
      project_id TEXT REFERENCES projects(id) ON DELETE CASCADE,
      profile TEXT NOT NULL DEFAULT 'standard',
      status TEXT NOT NULL DEFAULT 'pending',
      target_url TEXT NOT NULL,
      config TEXT,
      started_at DATETIME,
      completed_at DATETIME,
      total_requests INTEGER DEFAULT 0,
      findings_count TEXT DEFAULT '{"critical":0,"high":0,"medium":0,"low":0,"info":0}'
    );

    CREATE TABLE IF NOT EXISTS findings (
      id TEXT PRIMARY KEY,
      scan_id TEXT REFERENCES scans(id) ON DELETE CASCADE,
      module_id TEXT NOT NULL,
      severity TEXT NOT NULL,
      title TEXT NOT NULL,
      description TEXT,
      url TEXT,
      parameter TEXT,
      evidence TEXT,
      remediation TEXT,
      cwe_id TEXT,
      owasp_category TEXT,
      cvss_score REAL,
      false_positive INTEGER DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS endpoints (
      id TEXT PRIMARY KEY,
      scan_id TEXT REFERENCES scans(id) ON DELETE CASCADE,
      url TEXT NOT NULL,
      method TEXT DEFAULT 'GET',
      parameters TEXT,
      response_code INTEGER,
      content_type TEXT,
      technology TEXT
    );

    CREATE TABLE IF NOT EXISTS proxy_history (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      method TEXT NOT NULL,
      url TEXT NOT NULL,
      host TEXT NOT NULL,
      port INTEGER,
      is_https INTEGER DEFAULT 0,
      request_headers TEXT,
      request_body BLOB,
      response_status INTEGER,
      response_headers TEXT,
      response_body BLOB,
      response_length INTEGER,
      content_type TEXT,
      duration_ms INTEGER,
      intercepted INTEGER DEFAULT 0,
      notes TEXT,
      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS proxy_websocket (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      history_id INTEGER REFERENCES proxy_history(id) ON DELETE CASCADE,
      direction TEXT NOT NULL,
      opcode INTEGER,
      payload BLOB,
      payload_length INTEGER,
      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS proxy_scope (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      type TEXT NOT NULL DEFAULT 'include',
      protocol TEXT DEFAULT 'any',
      host_pattern TEXT NOT NULL,
      port TEXT DEFAULT 'any',
      path_pattern TEXT DEFAULT '*'
    );

    CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
    CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
    CREATE INDEX IF NOT EXISTS idx_scans_project ON scans(project_id);
    CREATE TABLE IF NOT EXISTS app_settings (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_proxy_history_host ON proxy_history(host);
    CREATE INDEX IF NOT EXISTS idx_proxy_history_timestamp ON proxy_history(timestamp);
  `);
}

export function getDb(): Database.Database {
  return db;
}
