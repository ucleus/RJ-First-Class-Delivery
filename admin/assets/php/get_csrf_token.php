<?php
// ============================================
// 4. CSRF TOKEN ENDPOINT: /public_html/assets/php/get_csrf_token.php
// ============================================

session_start();
require_once 'guardman.php';

header('Content-Type: application/json');
echo json_encode(['token' => CSRFProtection::generateToken()]);
