// auth.js - Handles authentication and JWT token management

// Add JWT token to all HTMX requests
document.addEventListener('DOMContentLoaded', function() {
    // Add the Authorization header to all HTMX requests
    document.body.addEventListener('htmx:configRequest', function(evt) {
        // Get the JWT token from localStorage
        const token = localStorage.getItem('token');
        
        // If token exists, add it to the request headers
        if (token) {
            evt.detail.headers['Authorization'] = 'Bearer ' + token;
            console.log('Added token to request headers');
        } else {
            console.log('No token found in localStorage');
        }
    });

    // Handle unauthorized responses (401)
    document.body.addEventListener('htmx:responseError', function(evt) {
        if (evt.detail.xhr.status === 401) {
            // If unauthorized, redirect to login page
            localStorage.removeItem('token');
            window.location.href = '/';
        }
    });

    // Check if user is authenticated on page load
    const token = localStorage.getItem('token');
    if (token) {
        // Update auth section to show logout button
        const authSection = document.getElementById('auth-section');
        if (authSection) {
            authSection.innerHTML = `
                <button class="bg-accent hover:bg-blue-700 text-white font-bold py-2 px-4 rounded transition"
                        onclick="logout()">
                    Logout
                </button>
            `;
        }
    }
});

// Logout function
function logout() {
    localStorage.removeItem('token');
    window.location.href = '/';
}