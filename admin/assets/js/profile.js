// State management
let currentSection = "profile";
let selectedTime = null;
let selectedPaymentOption = "deposit";
let tipAmount = 0;

// Set minimum date to today
document.addEventListener("DOMContentLoaded", function () {
  const today = new Date().toISOString().split("T")[0];
  const dateInput = document.getElementById("serviceDate");
  if (dateInput) {
    dateInput.min = today;
  }
});

// Navigation functions
function showLogin() {
  document.getElementById("registerPage").style.display = "none";
  document.getElementById("loginPage").style.display = "flex";
}

function showRegister() {
  document.getElementById("loginPage").style.display = "none";
  document.getElementById("registerPage").style.display = "flex";
}

function showDashboard() {
  document.getElementById("registerPage").style.display = "none";
  document.getElementById("loginPage").style.display = "none";
  document.getElementById("dashboard").style.display = "flex";
}

function showSection(section) {
  // Hide all sections
  document.querySelectorAll(".content-section").forEach((s) => {
    s.style.display = "none";
  });

  // Show selected section
  document.getElementById(section + "Section").style.display = "block";

  // Update nav active state
  document.querySelectorAll(".nav-item").forEach((item) => {
    item.classList.remove("active");
  });
  event.target.closest(".nav-item").classList.add("active");

  // Close mobile menu
  document.getElementById("sidebar").classList.remove("active");

  currentSection = section;
}

// Mobile menu toggle
function toggleMobileMenu() {
  document.getElementById("sidebar").classList.toggle("active");
}

// Modal functions
function showServiceModal() {
  document.getElementById("serviceModal").classList.add("active");
}

function showAddPaymentModal() {
  document.getElementById("addPaymentModal").classList.add("active");
}

function closeModal(modalId) {
  document.getElementById(modalId).classList.remove("active");
}

function proceedToPayment() {
  // Validate form
  const service = document.getElementById("serviceType").value;
  const date = document.getElementById("serviceDate").value;

  if (!service || !date || !selectedTime) {
    alert("Please fill in all required fields");
    return;
  }

  // Update summary
  document.getElementById(
    "summaryService"
  ).textContent = document.getElementById("serviceType").options[
    document.getElementById("serviceType").selectedIndex
  ].text;
  document.getElementById("summaryDate").textContent = new Date(
    date
  ).toLocaleDateString("en-US", {
    month: "short",
    day: "numeric",
    year: "numeric"
  });
  document.getElementById("summaryTime").textContent = selectedTime;

  closeModal("serviceModal");
  document.getElementById("paymentOptionsModal").classList.add("active");
}

function confirmBooking() {
  alert("Booking confirmed! You will receive a confirmation email shortly.");
  closeModal("paymentOptionsModal");

  // Refresh schedule section
  if (currentSection === "schedule") {
    // Add new job to list
    location.reload(); // In real app, update via API
  }
}

// Time selection
function selectTime(element) {
  document.querySelectorAll(".time-slot").forEach((slot) => {
    slot.classList.remove("selected");
  });
  element.classList.add("selected");
  selectedTime = element.textContent;
}

// Payment option selection
function selectPaymentOption(element, option) {
  document.querySelectorAll(".payment-option").forEach((opt) => {
    opt.classList.remove("selected");
  });
  element.classList.add("selected");
  selectedPaymentOption = option;
}

// Tip functions
function setTip(amount) {
  tipAmount = amount;
  updateTotal();
}

function setCustomTip() {
  tipAmount = parseFloat(document.getElementById("customTip").value) || 0;
  updateTotal();
}

function updateTotal() {
  // Update total in payment modal based on tip
  // In real app, calculate based on service price
}

// Location toggle
function toggleLocationFields() {
  const checkbox = document.getElementById("differentLocation");
  const fields = document.getElementById("locationFields");
  fields.style.display = checkbox.checked ? "block" : "none";
}

// Profile edit functions
function editField(field) {
  const modal = document.getElementById("editModal");
  const title = document.getElementById("editModalTitle");
  const label = document.getElementById("editFieldLabel");
  const input = document.getElementById("editFieldInput");

  switch (field) {
    case "email":
      title.textContent = "Edit Email";
      label.textContent = "Email Address";
      input.type = "email";
      input.value = document.getElementById("emailValue").textContent;
      break;
    case "phone":
      title.textContent = "Edit Phone";
      label.textContent = "Phone Number";
      input.type = "tel";
      input.value = document.getElementById("phoneValue").textContent;
      break;
    case "address":
      title.textContent = "Edit Address";
      label.textContent = "Full Address";
      input.type = "text";
      input.value = document.getElementById("addressValue").textContent;
      break;
  }

  modal.classList.add("active");
}

function saveFieldEdit() {
  // In real app, save to backend
  alert("Changes saved successfully!");
  closeModal("editModal");
}

function uploadAvatar() {
  document.getElementById("avatarInput").click();
}

// Form submissions
document
  .getElementById("registerForm")
  .addEventListener("submit", function (e) {
    e.preventDefault();
    // Validate passwords match
    const password = document.getElementById("password").value;
    const confirmPassword = document.getElementById("confirmPassword").value;

    if (password !== confirmPassword) {
      alert("Passwords do not match!");
      return;
    }

    // In real app, submit to backend
    alert("Account created successfully!");
    showDashboard();
  });

document.getElementById("loginForm").addEventListener("submit", function (e) {
  e.preventDefault();
  // In real app, authenticate with backend
  showDashboard();
});

function logout() {
  if (confirm("Are you sure you want to logout?")) {
    showLogin();
  }
}

// File upload handler
document.getElementById("avatarInput").addEventListener("change", function (e) {
  const file = e.target.files[0];
  if (file) {
    // In real app, upload to server
    alert("Profile photo updated!");
  }
});
