// Скрипт для автоматического определения часового пояса
document.addEventListener('DOMContentLoaded', function() {
    // Получаем часовой пояс пользователя через JavaScript API Intl
    const userTimezone = Intl.DateTimeFormat().resolvedOptions().timeZone;
    console.log('Определен часовой пояс пользователя:', userTimezone);
    
    // Отправляем на сервер через Ajax запрос
    if(userTimezone) {
        // Создаем форму для отправки данных
        const formData = new FormData();
        formData.append('timezone', userTimezone);
        formData.append('auto_detected', 'true');
        
        fetch('/set_timezone', {
            method: 'POST',
            body: formData
        })
        .then(response => {
            if (!response.ok) {
                throw new Error('Сетевая ошибка: ' + response.status);
            }
            return response.json();
        })
        .then(data => {
            console.log('Ответ сервера:', data);
            if(data.success) {
                // Если в интерфейсе есть индикатор часового пояса, обновляем его
                const timezoneIndicator = document.getElementById('current-timezone');
                if(timezoneIndicator) {
                    timezoneIndicator.textContent = userTimezone;
                }
                
                // Если страница была только что загружена, обновляем ее для применения часового пояса
                if (!window.timezoneUpdated) {
                    window.timezoneUpdated = true;
                    // Ждем секунду и перезагружаем страницу
                    setTimeout(() => {
                        location.reload();
                    }, 1000);
                }
            }
        })
        .catch(error => {
            console.error('Ошибка при установке часового пояса:', error);
        });
    }
});