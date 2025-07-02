<?php
// ============================================
// 1. CONFIG FILE: /public_html/assets/php/config.php
// ============================================

// Database configuration for Hostinger
define('DB_HOST', 'localhost'); // Usually localhost on Hostinger
define('DB_NAME', 'your_database_name');
define('DB_USER', 'your_database_user');
define('DB_PASS', 'your_database_password');

// Security keys (generate unique keys)
define('ENCRYPTION_KEY', 'your-32-character-encryption-key-here');
define('SESSION_NAME', 'RJ_DELIVERY_SESSION');

// File paths
define('UPLOAD_PATH', $_SERVER['DOCUMENT_ROOT'] . '/uploads/profiles/');
define('GUARDMAN_PATH', $_SERVER['DOCUMENT_ROOT'] . '/assets/php/guardman.php');