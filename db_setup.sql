-- KodbankApp Database Setup (Phase 3)
-- Run this in MySQL / MariaDB or let the server auto-create on startup

CREATE DATABASE IF NOT EXISTS kodbankapp;
USE kodbankapp;

-- ── Table 1: bank_users ────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS bank_users (
  customer_id       INT AUTO_INCREMENT PRIMARY KEY,
  customer_name     VARCHAR(100)   NOT NULL,
  customer_password VARCHAR(255)   NOT NULL,
  bank_balance      DECIMAL(15, 2) NOT NULL DEFAULT 0.00,
  customer_email    VARCHAR(150)   NOT NULL UNIQUE,
  account_number    VARCHAR(20)    NOT NULL UNIQUE,         -- e.g. KODBK0000000001
  ifsc_code         VARCHAR(15)    NOT NULL DEFAULT 'KODBK0001'
);

-- ── Table 2: jwt_tokens ───────────────────────────────────────────────────────
-- VARCHAR(512) + index fixes the TEXT lookup performance / reliability issue
CREATE TABLE IF NOT EXISTS jwt_tokens (
  id          INT AUTO_INCREMENT PRIMARY KEY,
  customer_id INT           NOT NULL,
  token       VARCHAR(512)  NOT NULL,
  created_at  DATETIME      NOT NULL DEFAULT NOW(),
  expires_at  DATETIME      NOT NULL,
  is_active   TINYINT(1)    NOT NULL DEFAULT 1,
  INDEX idx_token (token(255)),
  FOREIGN KEY (customer_id) REFERENCES bank_users(customer_id) ON DELETE CASCADE
);
