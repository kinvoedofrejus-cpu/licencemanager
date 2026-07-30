CREATE TABLE IF NOT EXISTS software (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  code TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS clients (
  id TEXT PRIMARY KEY,
  name TEXT,
  email TEXT UNIQUE,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS licenses (
  id TEXT PRIMARY KEY,
  software_id TEXT NOT NULL REFERENCES software(id),
  client_id TEXT REFERENCES clients(id),
  license_key TEXT NOT NULL UNIQUE,
  type TEXT NOT NULL,                     -- mensuel | annuel | vie
  price REAL DEFAULT 0,
  max_devices INTEGER DEFAULT 1,
  status TEXT NOT NULL DEFAULT 'active',  -- active | disabled
  expiration TEXT,                        -- NULL si licence à vie
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS devices (
  id TEXT PRIMARY KEY,
  license_id TEXT NOT NULL REFERENCES licenses(id),
  device_fingerprint TEXT NOT NULL,
  activated_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL,
  UNIQUE(license_id, device_fingerprint)
);
