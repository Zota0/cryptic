
document.addEventListener('DOMContentLoaded', function() {
    
    document.body.addEventListener('htmx:configRequest', function(evt) {
        
        const token = localStorage.getItem('token');
        
        
        if (token) {
            evt.detail.headers['Authorization'] = 'Bearer ' + token;
            console.log('Added token to request headers');
        } else {
            console.log('No token found in localStorage');
        }
    });
    document.body.addEventListener('htmx:responseError', function(evt) {
        if (evt.detail.xhr.status === 401) {
            
            localStorage.removeItem('token');
            window.location.href = '/';
        }
    });

    const token = localStorage.getItem('token');
    if (token) {
        
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

function logout() {
    localStorage.removeItem('token');
    window.location.href = '/';
}