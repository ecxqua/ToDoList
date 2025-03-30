// Скрипт для автоматического определения часового пояса
document.addEventListener('DOMContentLoaded', function() {
    // Получаем часовой пояс пользователя через JavaScript API Intl
    const userTimezone = Intl.DateTimeFormat().resolvedOptions().timeZone;
    console.log('Определен часовой пояс пользователя:', userTimezone);
    
    // Отправляем на сервер через Ajax запрос
    if(userTimezone) {
        fetch('/set_timezone', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-Requested-With': 'XMLHttpRequest'
            },
            body: JSON.stringify({
                timezone: userTimezone,
                auto_detected: true
            })
        })
        .then(response => response.json())
        .then(data => {
            console.log('Ответ сервера:', data);
            if(data.success) {
                // Если в интерфейсе есть индикатор часового пояса, обновляем его
                const timezoneIndicator = document.getElementById('current-timezone');
                if(timezoneIndicator) {
                    timezoneIndicator.textContent = userTimezone;
                }
            }
        })
        .catch(error => console.error('Ошибка при установке часового пояса:', error));
    }
});