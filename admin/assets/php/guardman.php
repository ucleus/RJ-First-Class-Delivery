<?php
/**
 * Security Implementation for RJ First Class Delivery
 * Server-side form and file upload protection
 */

// ============================================
// 1. CONFIGURATION & SECURITY HEADERS
// ============================================

// Security headers to prevent common attacks
header("X-Content-Type-Options: nosniff");
header("X-Frame-Options: DENY");
header("X-XSS-Protection: 1; mode=block");
header("Strict-Transport-Security: max-age=31536000; includeSubDomains");
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com;");

// Session configuration
ini_set('session.cookie_httponly', 1);
ini_set('session.use_only_cookies', 1);
ini_set('session.cookie_secure', 1);
ini_set('session.cookie_samesite', 'Strict');

// ============================================
// 2. INPUT VALIDATION & SANITIZATION CLASS
// ============================================

class InputValidator {
    
    /**
     * Validate and sanitize email
     */
    public static function validateEmail($email) {
        $email = filter_var($email, FILTER_SANITIZE_EMAIL);
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            throw new Exception("Invalid email format");
        }
        
        // Additional checks for disposable email domains
        $disposableDomains = ['tempmail.com', 'throwaway.email', '10minutemail.com'];
        $domain = substr(strrchr($email, "@"), 1);
        if (in_array($domain, $disposableDomains)) {
            throw new Exception("Disposable email addresses not allowed");
        }
        
        return $email;
    }
    
    /**
     * Validate phone number
     */
    public static function validatePhone($phone) {
        // Remove non-numeric characters
        $phone = preg_replace('/[^0-9]/', '', $phone);
        
        // Check length (US phone numbers)
        if (strlen($phone) !== 10) {
            throw new Exception("Invalid phone number format");
        }
        
        return $phone;
    }
    
    /**
     * Validate and sanitize text input
     */
    public static function sanitizeText($input, $maxLength = 255) {
        // Remove HTML tags
        $input = strip_tags($input);
        
        // Remove special characters that could be used for SQL injection
        $input = htmlspecialchars($input, ENT_QUOTES, 'UTF-8');
        
        // Trim whitespace
        $input = trim($input);
        
        // Check length
        if (strlen($input) > $maxLength) {
            throw new Exception("Input exceeds maximum length");
        }
        
        return $input;
    }
    
    /**
     * Validate address components
     */
    public static function validateAddress($address, $city, $state, $zip) {
        $validatedAddress = [
            'address' => self::sanitizeText($address, 255),
            'city' => self::sanitizeText($city, 100),
            'state' => self::validateState($state),
            'zip' => self::validateZip($zip)
        ];
        
        return $validatedAddress;
    }
    
    /**
     * Validate US state
     */
    private static function validateState($state) {
        $validStates = ['FL', 'NY', 'CA', /* ... add all states */];
        $state = strtoupper(self::sanitizeText($state, 2));
        
        if (!in_array($state, $validStates)) {
            throw new Exception("Invalid state");
        }
        
        return $state;
    }
    
    /**
     * Validate ZIP code
     */
    private static function validateZip($zip) {
        $zip = preg_replace('/[^0-9-]/', '', $zip);
        
        if (!preg_match('/^\d{5}(-\d{4})?$/', $zip)) {
            throw new Exception("Invalid ZIP code format");
        }
        
        return $zip;
    }
}

// ============================================
// 3. FILE UPLOAD SECURITY CLASS
// ============================================

class SecureFileUpload {
    
    private $allowedMimeTypes = [
        'image/jpeg' => 'jpg',
        'image/png' => 'png',
        'image/gif' => 'gif',
        'image/webp' => 'webp'
    ];
    
    private $maxFileSize = 5242880; // 5MB
    private $uploadDirectory = '/secure/uploads/';
    
    /**
     * Validate and process file upload
     */
    public function uploadFile($file, $userId) {
        // Check if file was uploaded
        if (!isset($file['tmp_name']) || !is_uploaded_file($file['tmp_name'])) {
            throw new Exception("No file uploaded");
        }
        
        // Check file size
        if ($file['size'] > $this->maxFileSize) {
            throw new Exception("File size exceeds limit (5MB)");
        }
        
        // Verify MIME type
        $finfo = finfo_open(FILEINFO_MIME_TYPE);
        $mimeType = finfo_file($finfo, $file['tmp_name']);
        finfo_close($finfo);
        
        if (!array_key_exists($mimeType, $this->allowedMimeTypes)) {
            throw new Exception("Invalid file type");
        }
        
        // Additional image validation
        $imageInfo = getimagesize($file['tmp_name']);
        if ($imageInfo === false) {
            throw new Exception("Invalid image file");
        }
        
        // Check image dimensions
        if ($imageInfo[0] > 4000 || $imageInfo[1] > 4000) {
            throw new Exception("Image dimensions too large");
        }
        
        // Scan for malicious content
        $this->scanForMaliciousContent($file['tmp_name']);
        
        // Generate secure filename
        $extension = $this->allowedMimeTypes[$mimeType];
        $filename = $this->generateSecureFilename($userId, $extension);
        
        // Move file to secure directory
        $destination = $_SERVER['DOCUMENT_ROOT'] . $this->uploadDirectory . $filename;
        
        if (!move_uploaded_file($file['tmp_name'], $destination)) {
            throw new Exception("Failed to save file");
        }
        
        // Set proper permissions
        chmod($destination, 0644);
        
        return $filename;
    }
    
    /**
     * Generate secure filename
     */
    private function generateSecureFilename($userId, $extension) {
        // Use random bytes for filename to prevent enumeration
        $randomName = bin2hex(random_bytes(16));
        return "user_{$userId}_{$randomName}.{$extension}";
    }
    
    /**
     * Scan file for malicious content
     */
    private function scanForMaliciousContent($filepath) {
        // Check for PHP code in image
        $content = file_get_contents($filepath);
        $suspiciousPatterns = [
            '<?php',
            '<?=',
            '<script',
            'eval(',
            'base64_decode',
            'system(',
            'exec(',
            'shell_exec('
        ];
        
        foreach ($suspiciousPatterns as $pattern) {
            if (stripos($content, $pattern) !== false) {
                throw new Exception("Suspicious content detected in file");
            }
        }
        
        // Additional check for embedded executables
        $hexPatterns = [
            '4d5a', // PE executable
            '7f454c46', // ELF executable
            '504b0304' // ZIP archive
        ];
        
        $hexContent = bin2hex(substr($content, 0, 4));
        foreach ($hexPatterns as $pattern) {
            if (strpos($hexContent, $pattern) === 0) {
                throw new Exception("Executable content detected");
            }
        }
    }
}

// ============================================
// 4. CSRF PROTECTION
// ============================================

class CSRFProtection {
    
    /**
     * Generate CSRF token
     */
    public static function generateToken() {
        if (empty($_SESSION['csrf_token'])) {
            $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        }
        return $_SESSION['csrf_token'];
    }
    
    /**
     * Verify CSRF token
     */
    public static function verifyToken($token) {
        if (empty($_SESSION['csrf_token']) || empty($token)) {
            return false;
        }
        
        return hash_equals($_SESSION['csrf_token'], $token);
    }
    
    /**
     * Get CSRF field HTML
     */
    public static function getTokenField() {
        $token = self::generateToken();
        return '<input type="hidden" name="csrf_token" value="' . htmlspecialchars($token) . '">';
    }
}

// ============================================
// 5. RATE LIMITING
// ============================================

class RateLimiter {
    
    private $redis; // Assumes Redis connection
    private $maxAttempts = 5;
    private $decayMinutes = 15;
    
    public function __construct($redis) {
        $this->redis = $redis;
    }
    
    /**
     * Check if request should be rate limited
     */
    public function tooManyAttempts($key) {
        $attempts = $this->redis->get($key);
        
        if ($attempts >= $this->maxAttempts) {
            return true;
        }
        
        return false;
    }
    
    /**
     * Increment attempts
     */
    public function hit($key) {
        $attempts = $this->redis->incr($key);
        
        if ($attempts == 1) {
            $this->redis->expire($key, $this->decayMinutes * 60);
        }
        
        return $attempts;
    }
    
    /**
     * Clear attempts
     */
    public function clear($key) {
        $this->redis->del($key);
    }
}

// ============================================
// 6. DATABASE SECURITY CLASS
// ============================================

class SecureDatabase {
    
    private $pdo;
    
    public function __construct($host, $dbname, $username, $password) {
        try {
            $this->pdo = new PDO(
                "mysql:host=$host;dbname=$dbname;charset=utf8mb4",
                $username,
                $password,
                [
                    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                    PDO::ATTR_EMULATE_PREPARES => false,
                    PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES utf8mb4 COLLATE utf8mb4_unicode_ci"
                ]
            );
        } catch (PDOException $e) {
            // Log error securely, don't expose to user
            error_log($e->getMessage());
            throw new Exception("Database connection failed");
        }
    }
    
    /**
     * Insert customer with prepared statements
     */
    public function insertCustomer($data) {
        $sql = "INSERT INTO customers (
                    first_name, last_name, email, phone, 
                    address_line1, city, state, zip_code,
                    password_hash, created_at
                ) VALUES (
                    :first_name, :last_name, :email, :phone,
                    :address, :city, :state, :zip,
                    :password_hash, NOW()
                )";
        
        $stmt = $this->pdo->prepare($sql);
        
        // Hash password securely
        $passwordHash = password_hash($data['password'], PASSWORD_ARGON2ID, [
            'memory_cost' => 65536,
            'time_cost' => 4,
            'threads' => 3
        ]);
        
        $stmt->execute([
            ':first_name' => $data['first_name'],
            ':last_name' => $data['last_name'],
            ':email' => $data['email'],
            ':phone' => $data['phone'],
            ':address' => $data['address'],
            ':city' => $data['city'],
            ':state' => $data['state'],
            ':zip' => $data['zip'],
            ':password_hash' => $passwordHash
        ]);
        
        return $this->pdo->lastInsertId();
    }
}

// ============================================
// 7. ENCRYPTION CLASS FOR SENSITIVE DATA
// ============================================

class DataEncryption {
    
    private $key;
    private $cipher = 'aes-256-gcm';
    
    public function __construct($key) {
        $this->key = $key;
    }
    
    /**
     * Encrypt sensitive data
     */
    public function encrypt($data) {
        $iv = random_bytes(openssl_cipher_iv_length($this->cipher));
        $tag = '';
        
        $encrypted = openssl_encrypt(
            $data,
            $this->cipher,
            $this->key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag
        );
        
        return base64_encode($iv . $tag . $encrypted);
    }
    
    /**
     * Decrypt sensitive data
     */
    public function decrypt($encryptedData) {
        $data = base64_decode($encryptedData);
        $ivLength = openssl_cipher_iv_length($this->cipher);
        $tagLength = 16;
        
        $iv = substr($data, 0, $ivLength);
        $tag = substr($data, $ivLength, $tagLength);
        $encrypted = substr($data, $ivLength + $tagLength);
        
        return openssl_decrypt(
            $encrypted,
            $this->cipher,
            $this->key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag
        );
    }
}

// ============================================
// 8. EXAMPLE IMPLEMENTATION
// ============================================

// Process registration form
try {
    session_start();
    
    // Verify CSRF token
    if (!CSRFProtection::verifyToken($_POST['csrf_token'] ?? '')) {
        throw new Exception("Invalid security token");
    }
    
    // Rate limiting
    $rateLimiter = new RateLimiter($redis);
    $rateLimitKey = 'register_' . $_SERVER['REMOTE_ADDR'];
    
    if ($rateLimiter->tooManyAttempts($rateLimitKey)) {
        throw new Exception("Too many attempts. Please try again later.");
    }
    
    $rateLimiter->hit($rateLimitKey);
    
    // Validate inputs
    $validatedData = [
        'first_name' => InputValidator::sanitizeText($_POST['first_name'], 50),
        'last_name' => InputValidator::sanitizeText($_POST['last_name'], 50),
        'email' => InputValidator::validateEmail($_POST['email']),
        'phone' => InputValidator::validatePhone($_POST['phone']),
        'password' => $_POST['password'] // Will be hashed in database class
    ];
    
    // Validate address
    $address = InputValidator::validateAddress(
        $_POST['address'],
        $_POST['city'],
        $_POST['state'],
        $_POST['zip']
    );
    
    $validatedData = array_merge($validatedData, $address);
    
    // Check password strength
    if (strlen($_POST['password']) < 8 || 
        !preg_match('/[A-Z]/', $_POST['password']) ||
        !preg_match('/[a-z]/', $_POST['password']) ||
        !preg_match('/[0-9]/', $_POST['password'])) {
        throw new Exception("Password must be at least 8 characters with uppercase, lowercase, and numbers");
    }
    
    // Save to database
    $db = new SecureDatabase($host, $dbname, $username, $password);
    $customerId = $db->insertCustomer($validatedData);
    
    // Handle file upload if present
    if (isset($_FILES['profile_photo'])) {
        $fileUploader = new SecureFileUpload();
        $filename = $fileUploader->uploadFile($_FILES['profile_photo'], $customerId);
        // Update customer record with photo
    }
    
    // Clear rate limit on success
    $rateLimiter->clear($rateLimitKey);
    
    // Log successful registration
    error_log("New customer registered: ID $customerId from IP " . $_SERVER['REMOTE_ADDR']);
    
    echo json_encode(['success' => true, 'message' => 'Registration successful']);
    
} catch (Exception $e) {
    http_response_code(400);
    echo json_encode(['success' => false, 'message' => $e->getMessage()]);
}

// ============================================
// 9. ADDITIONAL SECURITY MEASURES
// ============================================

/**
 * WAF Rules (.htaccess)
 */
$htaccessRules = '
# Prevent directory listing
Options -Indexes

# Prevent access to sensitive files
<FilesMatch "\.(env|json|lock|yml|yaml|git|sql)$">
    Order allow,deny
    Deny from all
</FilesMatch>

# Block suspicious user agents
RewriteEngine On
RewriteCond %{HTTP_USER_AGENT} (bot|crawler|spider) [NC]
RewriteRule .* - [F,L]

# Prevent SQL injection attempts
RewriteCond %{QUERY_STRING} (union|select|insert|drop|update|delete) [NC]
RewriteRule .* - [F,L]

# Block access to upload directory
<Directory /secure/uploads>
    Order Deny,Allow
    Deny from all
</Directory>
';

/**
 * Audit logging function
 */
function auditLog($action, $userId, $data = []) {
    $logEntry = [
        'timestamp' => date('Y-m-d H:i:s'),
        'action' => $action,
        'user_id' => $userId,
        'ip_address' => $_SERVER['REMOTE_ADDR'],
        'user_agent' => $_SERVER['HTTP_USER_AGENT'],
        'data' => $data
    ];
    
    // Write to secure log file
    $logFile = '/var/log/rj_delivery_audit.log';
    file_put_contents($logFile, json_encode($logEntry) . PHP_EOL, FILE_APPEND | LOCK_EX);
}

?>