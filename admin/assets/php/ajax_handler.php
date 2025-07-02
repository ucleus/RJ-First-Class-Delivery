<?php
// ============================================
// 2. AJAX HANDLER: /public_html/assets/php/ajax_handler.php
// ============================================

session_start();
require_once 'config.php';
require_once 'guardman.php';

// Set JSON header
header('Content-Type: application/json');

// Initialize response
$response = ['success' => false, 'message' => ''];

// Get action from request
$action = $_POST['action'] ?? $_GET['action'] ?? '';

try {
    // Initialize database connection
    $db = new SecureDatabase(DB_HOST, DB_NAME, DB_USER, DB_PASS);
    
    switch ($action) {
        case 'register':
            handleRegistration($db);
            break;
            
        case 'login':
            handleLogin($db);
            break;
            
        case 'update_profile':
            handleProfileUpdate($db);
            break;
            
        case 'upload_avatar':
            handleAvatarUpload($db);
            break;
            
        case 'create_booking':
            handleBookingCreation($db);
            break;
            
        case 'get_services':
            handleGetServices($db);
            break;
            
        case 'get_schedule':
            handleGetSchedule($db);
            break;
            
        default:
            throw new Exception('Invalid action');
    }
    
} catch (Exception $e) {
    $response['success'] = false;
    $response['message'] = $e->getMessage();
    http_response_code(400);
}

echo json_encode($response);
exit;

// ============================================
// HANDLER FUNCTIONS
// ============================================

function handleRegistration($db) {
    global $response;
    
    // Verify CSRF token
    if (!CSRFProtection::verifyToken($_POST['csrf_token'] ?? '')) {
        throw new Exception("Invalid security token");
    }
    
    // Validate inputs
    $validatedData = [
        'first_name' => InputValidator::sanitizeText($_POST['first_name'], 50),
        'last_name' => InputValidator::sanitizeText($_POST['last_name'], 50),
        'email' => InputValidator::validateEmail($_POST['email']),
        'phone' => InputValidator::validatePhone($_POST['phone']),
        'address' => InputValidator::sanitizeText($_POST['address'], 255),
        'city' => InputValidator::sanitizeText($_POST['city'], 100),
        'state' => InputValidator::sanitizeText($_POST['state'], 2),
        'zip' => InputValidator::sanitizeText($_POST['zip'], 10),
        'password' => $_POST['password']
    ];
    
    // Check if email already exists
    $stmt = $db->prepare("SELECT customer_id FROM customers WHERE email = ?");
    $stmt->execute([$validatedData['email']]);
    if ($stmt->fetch()) {
        throw new Exception("Email already registered");
    }
    
    // Insert customer
    $customerId = $db->insertCustomer($validatedData);
    
    // Set session
    $_SESSION['user_id'] = $customerId;
    $_SESSION['user_email'] = $validatedData['email'];
    $_SESSION['user_name'] = $validatedData['first_name'] . ' ' . $validatedData['last_name'];
    
    $response['success'] = true;
    $response['message'] = 'Registration successful';
    $response['redirect'] = '/admin/index.html#dashboard';
}

function handleLogin($db) {
    global $response;
    
    // Verify CSRF token
    if (!CSRFProtection::verifyToken($_POST['csrf_token'] ?? '')) {
        throw new Exception("Invalid security token");
    }
    
    $email = InputValidator::validateEmail($_POST['email']);
    $password = $_POST['password'];
    
    // Get user from database
    $stmt = $db->prepare("SELECT customer_id, first_name, last_name, password_hash FROM customers WHERE email = ? AND is_active = 1");
    $stmt->execute([$email]);
    $user = $stmt->fetch();
    
    if (!$user || !password_verify($password, $user['password_hash'])) {
        throw new Exception("Invalid email or password");
    }
    
    // Set session
    $_SESSION['user_id'] = $user['customer_id'];
    $_SESSION['user_email'] = $email;
    $_SESSION['user_name'] = $user['first_name'] . ' ' . $user['last_name'];
    
    // Update last login
    $stmt = $db->prepare("UPDATE customers SET last_login = NOW() WHERE customer_id = ?");
    $stmt->execute([$user['customer_id']]);
    
    $response['success'] = true;
    $response['message'] = 'Login successful';
    $response['redirect'] = '/admin/index.html#dashboard';
}

function handleProfileUpdate($db) {
    global $response;
    
    // Check if logged in
    if (!isset($_SESSION['user_id'])) {
        throw new Exception("Not authenticated");
    }
    
    $field = $_POST['field'] ?? '';
    $value = $_POST['value'] ?? '';
    
    // Validate based on field type
    switch ($field) {
        case 'email':
            $value = InputValidator::validateEmail($value);
            $column = 'email';
            break;
        case 'phone':
            $value = InputValidator::validatePhone($value);
            $column = 'phone';
            break;
        case 'address':
            // For address, we might need multiple fields
            $address = InputValidator::sanitizeText($_POST['address'], 255);
            $city = InputValidator::sanitizeText($_POST['city'], 100);
            $state = InputValidator::sanitizeText($_POST['state'], 2);
            $zip = InputValidator::sanitizeText($_POST['zip'], 10);
            
            $stmt = $db->prepare("UPDATE customers SET address_line1 = ?, city = ?, state = ?, zip_code = ? WHERE customer_id = ?");
            $stmt->execute([$address, $city, $state, $zip, $_SESSION['user_id']]);
            
            $response['success'] = true;
            $response['message'] = 'Address updated successfully';
            return;
        default:
            throw new Exception("Invalid field");
    }
    
    // Update single field
    $stmt = $db->prepare("UPDATE customers SET $column = ? WHERE customer_id = ?");
    $stmt->execute([$value, $_SESSION['user_id']]);
    
    $response['success'] = true;
    $response['message'] = ucfirst($field) . ' updated successfully';
}

function handleAvatarUpload($db) {
    global $response;
    
    // Check if logged in
    if (!isset($_SESSION['user_id'])) {
        throw new Exception("Not authenticated");
    }
    
    // Handle file upload
    $uploader = new SecureFileUpload();
    $filename = $uploader->uploadFile($_FILES['avatar'], $_SESSION['user_id']);
    
    // Update database
    $stmt = $db->prepare("UPDATE customers SET profile_photo = ? WHERE customer_id = ?");
    $stmt->execute([$filename, $_SESSION['user_id']]);
    
    $response['success'] = true;
    $response['message'] = 'Profile photo updated';
    $response['filename'] = $filename;
}

function handleBookingCreation($db) {
    global $response;
    
    // Check if logged in
    if (!isset($_SESSION['user_id'])) {
        throw new Exception("Not authenticated");
    }
    
    // Validate booking data
    $bookingData = [
        'service_id' => filter_var($_POST['service_id'], FILTER_VALIDATE_INT),
        'appointment_date' => InputValidator::sanitizeText($_POST['appointment_date'], 10),
        'appointment_time' => InputValidator::sanitizeText($_POST['appointment_time'], 8),
        'pickup_address' => InputValidator::sanitizeText($_POST['pickup_address'], 255),
        'pickup_city' => InputValidator::sanitizeText($_POST['pickup_city'], 100),
        'pickup_state' => InputValidator::sanitizeText($_POST['pickup_state'], 2),
        'pickup_zip' => InputValidator::sanitizeText($_POST['pickup_zip'], 10),
        'delivery_address' => InputValidator::sanitizeText($_POST['delivery_address'], 255),
        'delivery_city' => InputValidator::sanitizeText($_POST['delivery_city'], 100),
        'delivery_state' => InputValidator::sanitizeText($_POST['delivery_state'], 2),
        'delivery_zip' => InputValidator::sanitizeText($_POST['delivery_zip'], 10),
        'special_instructions' => InputValidator::sanitizeText($_POST['special_instructions'] ?? '', 1000)
    ];
    
    // Generate confirmation number
    $confirmationNumber = 'RJD-' . date('Ymd') . '-' . str_pad(rand(1, 9999), 4, '0', STR_PAD_LEFT);
    
    // Insert booking
    $stmt = $db->prepare("
        INSERT INTO appointments (
            customer_id, service_id, appointment_date, appointment_time,
            pickup_address, pickup_city, pickup_state, pickup_zip,
            delivery_address, delivery_city, delivery_state, delivery_zip,
            special_instructions, confirmation_number, status_id,
            base_price, total_price, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, NOW())
    ");
    
    // Get service price
    $priceStmt = $db->prepare("SELECT base_price FROM services WHERE service_id = ?");
    $priceStmt->execute([$bookingData['service_id']]);
    $servicePrice = $priceStmt->fetchColumn();
    
    $stmt->execute([
        $_SESSION['user_id'],
        $bookingData['service_id'],
        $bookingData['appointment_date'],
        $bookingData['appointment_time'],
        $bookingData['pickup_address'],
        $bookingData['pickup_city'],
        $bookingData['pickup_state'],
        $bookingData['pickup_zip'],
        $bookingData['delivery_address'],
        $bookingData['delivery_city'],
        $bookingData['delivery_state'],
        $bookingData['delivery_zip'],
        $bookingData['special_instructions'],
        $confirmationNumber,
        $servicePrice,
        $servicePrice
    ]);
    
    $response['success'] = true;
    $response['message'] = 'Booking created successfully';
    $response['confirmation_number'] = $confirmationNumber;
    $response['appointment_id'] = $db->lastInsertId();
}
?>