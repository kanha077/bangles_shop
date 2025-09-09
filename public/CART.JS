// --- cart.js ---

// This function runs when the page loads to set everything up
document.addEventListener('DOMContentLoaded', () => {
    updateCartCount();
    setupHeader();
});


// UPDATED FUNCTION: Now adds a Dashboard button for the owner
function setupHeader() {
    const isLoggedIn = localStorage.getItem('isLoggedIn') === 'true';
    const username = localStorage.getItem('username');
    const userStatusElement = document.getElementById('user-status');

    if (!userStatusElement) return; // Exit if the element doesn't exist

    if (isLoggedIn && username) {
        // Check if the logged-in user is the owner
        if (username === 'owner') {
            // If it's the owner, show Welcome, Dashboard, and Logout
            userStatusElement.innerHTML = `
                <span>Welcome, ${username}!</span> | 
                <a href="admin.html" style="font-weight: bold;">Dashboard</a> | 
                <a href="#" id="logout-btn">Logout</a>
            `;
        } else {
            // For regular users, just show Welcome and Logout
            userStatusElement.innerHTML = `
                <span>Welcome, ${username}!</span> | <a href="#" id="logout-btn">Logout</a>
            `;
        }
        
        // Add functionality to the logout button
        document.getElementById('logout-btn').addEventListener('click', (e) => {
            e.preventDefault();
            localStorage.clear(); // Clear all user data
            window.location.href = 'index.html'; // Redirect to home
        });

    } else {
        // If not logged in, show the login link
        userStatusElement.innerHTML = `<a href="login.html">Login / Sign Up</a>`;
    }
}


// This function updates the cart count display in the header
function updateCartCount() {
    const cart = JSON.parse(localStorage.getItem('cart')) || [];
    const cartCountElement = document.getElementById('cart-count');
    if (cartCountElement) {
        cartCountElement.textContent = cart.length;
    }
}


// This function runs when the "Add to Cart" button is clicked
function addToCart(productName, price) {
    const isLoggedIn = localStorage.getItem('isLoggedIn') === 'true';

    if (!isLoggedIn) {
        // If not logged in, redirect to the login page
        window.location.href = `login.html?redirect=${window.location.pathname}`;
        return;
    }

    const cart = JSON.parse(localStorage.getItem('cart')) || [];
    cart.push({ name: productName, price: price });
    localStorage.setItem('cart', JSON.stringify(cart));

    updateCartCount();
    alert(`"${productName}" has been added to your cart!`);
}