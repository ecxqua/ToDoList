// Скрипт для автоматического определения часового пояса
document.addEventListener('DOMContentLoaded', function() {
    // Проверяем, включено ли автоопределение часового пояса
    const autoTimezoneCheckbox = document.getElementById('auto_timezone');
    
    // Если включено автоопределение (при загрузке страницы), то выполняем определение часового пояса
    if (!autoTimezoneCheckbox || (autoTimezoneCheckbox && autoTimezoneCheckbox.checked)) {
        detectAndSetTimezone();
    }
    
    // Если есть чекбокс автоопределения на странице, добавляем обработчик изменения
    if (autoTimezoneCheckbox) {
        autoTimezoneCheckbox.addEventListener('change', function() {
            if (this.checked) {
                detectAndSetTimezone(false); // Не обновляем страницу, только устанавливаем timezone
            }
        });
    }
});

// Функция определения и установки часового пояса
function detectAndSetTimezone(shouldReload = true) {
    // Получаем часовой пояс пользователя через JavaScript API Intl
    const userTimezone = Intl.DateTimeFormat().resolvedOptions().timeZone;
    console.log('Определен часовой пояс пользователя:', userTimezone);
    
    // Отправляем на сервер только если часовой пояс определен
    if (userTimezone) {
        // Создаем форму для отправки данных
        const formData = new FormData();
        formData.append('timezone', userTimezone);
        formData.append('auto_detected', 'true');
        
        fetch('/set_timezone', {
            method: 'POST',
            body: formData,
            headers: {
                'X-Requested-With': 'XMLHttpRequest'
            }
        })
        .then(response => {
            if (!response.ok) {
                throw new Error('Сетевая ошибка: ' + response.status);
            }
            return response.json();
        })
        .then(data => {
            console.log('Ответ сервера:', data);
            if (data.success) {
                // Если в интерфейсе есть индикатор часового пояса, обновляем его
                const timezoneIndicator = document.getElementById('current-timezone');
                if (timezoneIndicator) {
                    timezoneIndicator.textContent = userTimezone;
                }
                
                // Если есть выпадающий список часовых поясов, выбираем нужный
                const timezoneSelect = document.getElementById('timezone_select');
                if (timezoneSelect) {
                    for (let i = 0; i < timezoneSelect.options.length; i++) {
                        if (timezoneSelect.options[i].value === userTimezone) {
                            timezoneSelect.selectedIndex = i;
                            break;
                        }
                    }
                }
                
                // Если нужно обновить страницу для применения часового пояса
                if (shouldReload && !window.timezoneUpdated) {
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
}