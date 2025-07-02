// Hamburger Menu
const hamburger = document.getElementById("hamburger");
const navLinks = document.getElementById("navLinks");

hamburger.addEventListener("click", () => {
  hamburger.classList.toggle("active");
  navLinks.classList.toggle("active");
});

// Smooth Scrolling
document.querySelectorAll('a[href^="#"]').forEach((anchor) => {
  anchor.addEventListener("click", function (e) {
    e.preventDefault();
    const target = document.querySelector(this.getAttribute("href"));
    if (target) {
      target.scrollIntoView({
        behavior: "smooth",
        block: "start"
      });
    }
    // Close mobile menu if open
    navLinks.classList.remove("active");
    hamburger.classList.remove("active");
  });
});

// Calendar Functionality
const months = [
  "January",
  "February",
  "March",
  "April",
  "May",
  "June",
  "July",
  "August",
  "September",
  "October",
  "November",
  "December"
];
const daysOfWeek = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];

let currentDate = new Date();
let selectedDate = null;

function generateCalendar(year, month) {
  const firstDay = new Date(year, month, 1).getDay();
  const daysInMonth = new Date(year, month + 1, 0).getDate();
  const calendarGrid = document.getElementById("calendarGrid");

  calendarGrid.innerHTML = "";

  // Add day headers
  daysOfWeek.forEach((day) => {
    const dayHeader = document.createElement("div");
    dayHeader.textContent = day;
    dayHeader.style.fontWeight = "bold";
    dayHeader.style.color = "var(--gray)";
    calendarGrid.appendChild(dayHeader);
  });

  // Add empty cells before first day
  for (let i = 0; i < firstDay; i++) {
    const emptyDay = document.createElement("div");
    calendarGrid.appendChild(emptyDay);
  }

  // Add days of month
  for (let day = 1; day <= daysInMonth; day++) {
    const dayElement = document.createElement("div");
    dayElement.textContent = day;
    dayElement.className = "calendar-day";

    // Disable past dates
    const dateToCheck = new Date(year, month, day);
    const today = new Date();
    today.setHours(0, 0, 0, 0);

    if (dateToCheck < today) {
      dayElement.style.opacity = "0.3";
      dayElement.style.cursor = "not-allowed";
    } else {
      dayElement.addEventListener("click", () => selectDate(year, month, day));
    }

    calendarGrid.appendChild(dayElement);
  }

  // Update month display
  document.getElementById(
    "currentMonth"
  ).textContent = `${months[month]} ${year}`;
}

function selectDate(year, month, day) {
  // Remove previous selection
  document.querySelectorAll(".calendar-day").forEach((el) => {
    el.classList.remove("selected");
  });

  // Add selection to clicked date
  event.target.classList.add("selected");
  selectedDate = new Date(year, month, day);
  console.log("Selected date:", selectedDate);
}

// Calendar navigation
document.getElementById("prevMonth").addEventListener("click", () => {
  currentDate.setMonth(currentDate.getMonth() - 1);
  generateCalendar(currentDate.getFullYear(), currentDate.getMonth());
});

document.getElementById("nextMonth").addEventListener("click", () => {
  currentDate.setMonth(currentDate.getMonth() + 1);
  generateCalendar(currentDate.getFullYear(), currentDate.getMonth());
});

// Initialize calendar
generateCalendar(currentDate.getFullYear(), currentDate.getMonth());

// Exit Intent Modal
let modalShown = false;
const modal = document.getElementById("emailModal");
const closeModal = document.getElementById("closeModal");

function showModal() {
  modal.style.display = "flex";
  modalShown = true;
}

function hideModal() {
  modal.style.display = "none";
}

// Mouse leave detection
document.addEventListener("mouseleave", (e) => {
  if (e.clientY <= 0 && !modalShown) {
    showModal();
  }
});

// Close modal
closeModal.addEventListener("click", hideModal);
modal.addEventListener("click", (e) => {
  if (e.target === modal) hideModal();
});

// Form submissions
document.getElementById("bookingForm").addEventListener("submit", (e) => {
  e.preventDefault();
  alert(
    "Thank you for booking! We will contact you within 24 hours to confirm your appointment."
  );
});

document.getElementById("emailForm").addEventListener("submit", (e) => {
  e.preventDefault();
  alert("Thank you for subscribing! Check your email for a welcome message.");
  hideModal();
});

// Header scroll effect
let lastScroll = 0;
window.addEventListener("scroll", () => {
  const header = document.querySelector("header");
  const currentScroll = window.pageYOffset;

  if (currentScroll > 100) {
    header.style.background = "rgba(255, 255, 255, 0.98)";
    header.style.boxShadow = "0 2px 20px rgba(0, 0, 0, 0.1)";
  } else {
    header.style.background = "rgba(255, 255, 255, 0.95)";
    header.style.boxShadow = "0 2px 10px rgba(0, 0, 0, 0.1)";
  }

  lastScroll = currentScroll;
});

// Intersection Observer for animations
const observerOptions = {
  threshold: 0.1,
  rootMargin: "0px 0px -50px 0px"
};

const observer = new IntersectionObserver((entries) => {
  entries.forEach((entry) => {
    if (entry.isIntersecting) {
      entry.target.style.opacity = "1";
      entry.target.style.transform = "translateY(0)";
    }
  });
}, observerOptions);

// Observe all service cards and steps
document
  .querySelectorAll(".service-card, .step, .pricing-card")
  .forEach((el) => {
    el.style.opacity = "0";
    el.style.transform = "translateY(20px)";
    el.style.transition = "all 0.6s ease";
    observer.observe(el);
  });

// Add some interactive hover effects
document.querySelectorAll(".service-icon").forEach((icon) => {
  icon.addEventListener("mouseenter", function () {
    this.style.transform = "scale(1.1) rotate(5deg)";
  });
  icon.addEventListener("mouseleave", function () {
    this.style.transform = "scale(1) rotate(0)";
  });
});

// Parallax effect for hero section
window.addEventListener("scroll", () => {
  const scrolled = window.pageYOffset;
  const hero = document.querySelector(".hero");
  hero.style.transform = `translateY(${scrolled * 0.5}px)`;
});

// Dynamic year for copyright
const currentYear = new Date().getFullYear();
document.querySelector(
  "footer p"
).innerHTML = `&copy; ${currentYear} RJ First Class Delivery. All rights reserved.`;
