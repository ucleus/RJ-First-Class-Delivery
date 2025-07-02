<?php
// ============================================
// 5. LOGOUT HANDLER: /public_html/assets/php/logout.php
// ============================================

session_start();
session_destroy();
header('Location: /admin/index.html');
exit;