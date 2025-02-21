// assets/js/hide-footer.js
document.addEventListener('DOMContentLoaded', function() {
    // Selecciona el elemento footer
    const footer = document.querySelector('.site-footer');
    // Oculta el footer cambiando su estilo
    if (footer) {
        footer.style.display = 'none';
    }
});