// ============================================
// 3. JAVASCRIPT INTEGRATION: Update your admin/index.html
// ============================================

// Add this JavaScript to your admin/index.html file

// API endpoint
const API_URL = '/assets/php/ajax_handler.php';

// Get CSRF token
async function getCSRFToken() {
    const response = await fetch('/assets/php/get_csrf_token.php');
    const data = await response.json();
    return data.token;
}

// Register function
async function handleRegister(event) {
    event.preventDefault();
    
    const formData = new FormData(event.target);
    formData.append('action', 'register');
    formData.append('csrf_token', await getCSRFToken());
    
    try {
        const response = await fetch(API_URL, {
            method: 'POST',
            body: formData
        });
        
        const data = await response.json();
        
        if (data.success) {
            alert(data.message);
            window.location.href = data.redirect;
        } else {
            alert('Error: ' + data.message);
        }
    } catch (error) {
        alert('Network error. Please try again.');
        console.error(error);
    }
}

// Login function
async function handleLogin(event) {
    event.preventDefault();
    
    const formData = new FormData(event.target);
    formData.append('action', 'login');
    formData.append('csrf_token', await getCSRFToken());
    
    try {
        const response = await fetch(API_URL, {
            method: 'POST',
            body: formData
        });
        
        const data = await response.json();
        
        if (data.success) {
            window.location.href = data.redirect;
        } else {
            alert('Error: ' + data.message);
        }
    } catch (error) {
        alert('Network error. Please try again.');
        console.error(error);
    }
}

// Update profile field
async function saveFieldEdit() {
    const field = document.getElementById('editFieldInput').dataset.field;
    const value = document.getElementById('editFieldInput').value;
    
    const formData = new FormData();
    formData.append('action', 'update_profile');
    formData.append('field', field);
    formData.append('value', value);
    formData.append('csrf_token', await getCSRFToken());
    
    try {
        const response = await fetch(API_URL, {
            method: 'POST',
            body: formData
        });
        
        const data = await response.json();
        
        if (data.success) {
            alert(data.message);
            location.reload();
        } else {
            alert('Error: ' + data.message);
        }
    } catch (error) {
        alert('Network error. Please try again.');
        console.error(error);
    }
}

// Upload avatar
document.getElementById('avatarInput').addEventListener('change', async function(e) {
    const file = e.target.files[0];
    if (!file) return;
    
    const formData = new FormData();
    formData.append('action', 'upload_avatar');
    formData.append('avatar', file);
    formData.append('csrf_token', await getCSRFToken());
    
    try {
        const response = await fetch(API_URL, {
            method: 'POST',
            body: formData
        });
        
        const data = await response.json();
        
        if (data.success) {
            alert(data.message);
            // Update avatar display
            location.reload();
        } else {
            alert('Error: ' + data.message);
        }
    } catch (error) {
        alert('Network error. Please try again.');
        console.error(error);
    }
});

// Update form submissions
document.getElementById('registerForm').addEventListener('submit', handleRegister);
document.getElementById('loginForm').addEventListener('submit', handleLogin);
