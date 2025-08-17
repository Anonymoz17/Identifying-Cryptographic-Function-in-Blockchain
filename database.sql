-- create database (once)
CREATE DATABASE IF NOT EXISTS cryptoscope

USE cryptoscope;

-- USERS
CREATE TABLE IF NOT EXISTS users (
  id            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  username      VARCHAR(64)  NOT NULL,
  email         VARCHAR(255) NOT NULL,
  full_name     VARCHAR(255),
  password_hash VARCHAR(255) NOT NULL,
  role          ENUM('admin','user') NOT NULL DEFAULT 'user',
  created_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uq_users_username (username),
  UNIQUE KEY uq_users_email (email)
) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- UPLOADS (files or external links)
CREATE TABLE IF NOT EXISTS uploads (
  id               BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  user_id          BIGINT UNSIGNED NOT NULL,
  kind             ENUM('upload','link') NOT NULL DEFAULT 'upload',
  original_name    VARCHAR(255),
  mime_type        VARCHAR(127),
  size_bytes       BIGINT UNSIGNED,
  storage_provider ENUM('gdrive','s3','local','link') NOT NULL,
  storage_path     VARCHAR(512),
  public_url       VARCHAR(1024),
  checksum         VARCHAR(128),
  status           ENUM('uploaded','processing','done','failed') NOT NULL DEFAULT 'uploaded',
  notes            TEXT,
  created_at       TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at       TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  KEY idx_uploads_userid (user_id),
  KEY idx_uploads_created (created_at),
  CONSTRAINT fk_uploads_user
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
