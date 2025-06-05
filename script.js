// Обработчики для модальных окон
document.addEventListener('DOMContentLoaded', function() {
    // Открытие/закрытие модальных окон
    const modal = document.getElementById('settings-modal');
    const openBtn = document.querySelector('[data-modal-open]');
    const closeBtn = document.querySelector('[data-modal-close]');

    if (openBtn) {
        openBtn.addEventListener('click', () => {
            modal.style.display = 'flex';
        });
    }

    if (closeBtn) {
        closeBtn.addEventListener('click', () => {
            modal.style.display = 'none';
        });
    }

    // Закрытие по клику вне модалки
    window.addEventListener('click', (e) => {
        if (e.target === modal) {
            modal.style.display = 'none';
        }
    });

    // Анимация карточек
    document.querySelectorAll('.card-clickable').forEach(card => {
        card.addEventListener('mousedown', () => {
            card.style.transform = 'scale(0.98)';
        });
        card.addEventListener('mouseup', () => {
            card.style.transform = '';
        });
    });

    // Автопрокрутка чата вниз
    const messagesContainer = document.querySelector('.messages');
    if (messagesContainer) {
        messagesContainer.scrollTop = messagesContainer.scrollHeight;
    }
});