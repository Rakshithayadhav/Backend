document.getElementById('logout-form').addEventListener('submit', async (e) => {
    e.preventDefault();

    const response = await fetch('/logout', {
        method: 'POST',
    });

    const data = await response.json();
    document.getElementById('logout-message').textContent = data.message;
});
