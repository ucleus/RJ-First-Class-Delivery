<?php
// ============================================
// 6. SESSION CHECK: /public_html/assets/php/check_session.php
// ============================================

session_start();
header('Content-Type: application/json');

$isLoggedIn = isset($_SESSION['user_id']);
$userData = [];

if ($isLoggedIn) {
    $userData = [
        'id' => $_SESSION['user_id'],
        'email' => $_SESSION['user_email'],
        'name' => $_SESSION['user_name']
    ];
}

echo json_encode([
    'logged_in' => $isLoggedIn,
    'user' => $userData
]);