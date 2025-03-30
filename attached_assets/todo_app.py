from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_mail import Mail, Message
import sqlite3
from datetime import datetime, timedelta
from pytz import timezone
import secrets


def format_datetime(dt):
    if not dt:
        return None
    local_tz = timezone('Europe/Moscow')
    if isinstance(dt, str):
        try:
            dt = datetime.strptime(dt, '%Y-%m-%d %H:%M:%S')
        except ValueError:
            try:
                dt = datetime.strptime(dt, '%Y-%m-%d')
                return dt.strftime('%d.%m.%Y')
            except ValueError:
                return dt
    return dt.astimezone(local_tz).strftime('%d.%m.%Y %H:%M')


import os
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'ваш_секретный_ключ'  # Замените на случайную строку

# Конфигурация Flask-Mail
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'dontreplythispls@gmail.com'
app.config['MAIL_PASSWORD'] = 'gtni hkpx obub mlig'  # Обновленный пароль приложения
app.config['MAIL_DEFAULT_SENDER'] = 'dontreplythispls@gmail.com'
app.config['MAIL_ASCII_ATTACHMENTS'] = False
mail = Mail(app)


# Создаем базу данных, если она не существует
def init_db():
    conn = sqlite3.connect('tasks.db')
    c = conn.cursor()

    # Создаем таблицу пользователей и добавляем столбец timezone если его нет
    c.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT NOT NULL,
        password TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        pending_email TEXT,
        email_confirm_token TEXT,
        email_confirm_expiry TIMESTAMP,
        reset_token TEXT,
        reset_token_expiry TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    
    # Проверяем наличие столбца timezone
    c.execute("PRAGMA table_info(users)")
    columns = [column[1] for column in c.fetchall()]
    if 'timezone' not in columns:
        c.execute('ALTER TABLE users ADD COLUMN timezone TEXT DEFAULT "Europe/Moscow"')
        conn.commit()

    # Создаем таблицу задач
    c.execute('''
    CREATE TABLE IF NOT EXISTS tasks (
        id INTEGER PRIMARY KEY,
        user_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        description TEXT,
        category TEXT,
        priority TEXT,
        due_date DATE,
        status TEXT DEFAULT "Новая",
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        send_reminder BOOLEAN DEFAULT 0,
        reminder_time INTEGER DEFAULT 24,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
    ''')

    conn.commit()
    conn.close()


init_db()


# Маршруты для авторизации
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']

        conn = sqlite3.connect('tasks.db')
        c = conn.cursor()

        # Проверяем, существует ли пользователь
        c.execute("SELECT id FROM users WHERE username = ? OR email = ?",
                  (username, email))
        if c.fetchone():
            conn.close()
            flash('Пользователь с таким именем или email уже существует!')
            return redirect(url_for('register'))

        # Хешируем пароль и сохраняем пользователя
        password_hash = generate_password_hash(password)
        c.execute(
            "INSERT INTO users (username, password, email) VALUES (?, ?, ?)",
            (username, password_hash, email))
        conn.commit()
        conn.close()

        flash('Регистрация успешна! Теперь вы можете войти.')
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        conn = sqlite3.connect('tasks.db')
        c = conn.cursor()

        try:
            c.execute("SELECT id, password, username FROM users WHERE email = ?",
                      (email, ))
            user = c.fetchone()

            if user and check_password_hash(user[1], password):
                session['user_id'] = user[0]
                session['username'] = user[2]
                conn.close()
                return redirect(url_for('dashboard'))

            conn.close()
            flash('Неверное имя пользователя или пароль!')
        except Exception as e:
            conn.close()
            flash('Ошибка при входе в систему')

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    return redirect(url_for('login'))


# Маршруты для работы с задачами
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = sqlite3.connect('tasks.db')
    c = conn.cursor()

    c.execute(
        """
    SELECT id, title, category, priority, due_date, status, created_at 
    FROM tasks 
    WHERE user_id = ? 
    ORDER BY 
        CASE status 
            WHEN 'Завершена' THEN 2
            ELSE 1
        END,
        CASE priority
            WHEN 'Высокий' THEN 1
            WHEN 'Средний' THEN 2
            WHEN 'Низкий' THEN 3
            ELSE 4
        END,
        due_date
    """, (session['user_id'], ))

    tasks = c.fetchall()
    conn.close()

    return render_template('dashboard.html', tasks=tasks, format_datetime=format_datetime)


@app.route('/task/new', methods=['GET', 'POST'])
def new_task():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        category = request.form['category']
        priority = request.form['priority']
        due_date = request.form['due_date'] if request.form[
            'due_date'] else None

        conn = sqlite3.connect('tasks.db')
        c = conn.cursor()

        c.execute(
            """
        INSERT INTO tasks (user_id, title, description, category, priority, due_date)
        VALUES (?, ?, ?, ?, ?, ?)
        """, (session['user_id'], title, description, category, priority,
              due_date))

        conn.commit()
        conn.close()

        flash('Задача успешно создана!')
        return redirect(url_for('dashboard'))

    return render_template('new_task.html')


@app.route('/task/<int:task_id>')
def view_task(task_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = sqlite3.connect('tasks.db')
    c = conn.cursor()

    c.execute(
        """
    SELECT id, title, description, category, priority, due_date, status, created_at
    FROM tasks 
    WHERE id = ? AND user_id = ?
    """, (task_id, session['user_id']))

    task = c.fetchone()
    conn.close()

    if not task:
        flash('Задача не найдена!')
        return redirect(url_for('dashboard'))

    return render_template('view_task.html', task=task, format_datetime=format_datetime)


@app.route('/task/<int:task_id>/edit', methods=['GET', 'POST'])
def edit_task(task_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = sqlite3.connect('tasks.db')
    c = conn.cursor()

    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        category = request.form['category']
        priority = request.form['priority']
        due_date = request.form['due_date'] if request.form[
            'due_date'] else None
        status = request.form['status']
        send_reminder = 'send_reminder' in request.form
        reminder_time = request.form.get('reminder_time', 24)

        c.execute(
            """
        UPDATE tasks 
        SET title = ?, description = ?, category = ?, priority = ?, due_date = ?, status = ?,
            send_reminder = ?, reminder_time = ?
        WHERE id = ? AND user_id = ?
        """, (title, description, category, priority, due_date, status,
              send_reminder, reminder_time, task_id, session['user_id']))

        conn.commit()
        flash('Задача обновлена!')
        return redirect(url_for('view_task', task_id=task_id))

    c.execute(
        """
    SELECT id, title, description, category, priority, due_date, status, send_reminder, reminder_time
    FROM tasks 
    WHERE id = ? AND user_id = ?
    """, (task_id, session['user_id']))

    task = c.fetchone()
    conn.close()

    if not task:
        flash('Задача не найдена!')
        return redirect(url_for('dashboard'))

    return render_template('edit_task.html', task=task)


@app.route('/task/<int:task_id>/delete', methods=['POST'])
def delete_task(task_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = sqlite3.connect('tasks.db')
    c = conn.cursor()

    c.execute("DELETE FROM tasks WHERE id = ? AND user_id = ?",
              (task_id, session['user_id']))
    conn.commit()
    conn.close()

    flash('Задача удалена!')
    return redirect(url_for('dashboard'))


@app.route('/tasks/analytics')
def analytics():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = sqlite3.connect('tasks.db')
    c = conn.cursor()

    # Статистика по категориям
    c.execute(
        """
    SELECT category, COUNT(*) as count
    FROM tasks
    WHERE user_id = ?
    GROUP BY category
    """, (session['user_id'], ))
    categories = c.fetchall()

    # Статистика по приоритетам
    c.execute(
        """
    SELECT priority, COUNT(*) as count
    FROM tasks
    WHERE user_id = ?
    GROUP BY priority
    """, (session['user_id'], ))
    priorities = c.fetchall()

    # Статистика по статусам
    c.execute(
        """
    SELECT status, COUNT(*) as count
    FROM tasks
    WHERE user_id = ?
    GROUP BY status
    """, (session['user_id'], ))
    statuses = c.fetchall()

    conn.close()

    return render_template('analytics.html',
                           categories=categories,
                           priorities=priorities,
                           statuses=statuses)


@app.route('/reset_password_request', methods=['GET', 'POST'])
def reset_password_request():
    if request.method == 'POST':
        email = request.form['email']

        conn = sqlite3.connect('tasks.db')
        c = conn.cursor()
        c.execute("SELECT id, username FROM users WHERE email = ?", (email, ))
        user = c.fetchone()

        if user:
            token = secrets.token_urlsafe(32)
            expiry = datetime.now() + timedelta(hours=24)

            c.execute(
                "UPDATE users SET reset_token = ?, reset_token_expiry = ? WHERE id = ?",
                (token, expiry, user[0]))
            conn.commit()

            reset_url = url_for('reset_password', token=token, _external=True)
            msg = Message('Сброс пароля',
                          sender=app.config['MAIL_USERNAME'],
                          recipients=[email])
            msg.body = f'''Для сброса пароля перейдите по ссылке:
{reset_url}

Если вы не запрашивали сброс пароля, проигнорируйте это сообщение.'''

            mail.send(msg)
            flash('Инструкции по сбросу пароля отправлены на вашу почту.')
            return redirect(url_for('login'))

        flash('Email не найден.')
        conn.close()

    return render_template('reset_password_request.html')


@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = sqlite3.connect('tasks.db')
    c = conn.cursor()

    # Получаем информацию о пользователе
    c.execute("SELECT username, email, pending_email, timezone FROM users WHERE id = ?", (session['user_id'],))
    user = c.fetchone()

    # Получаем статистику задач
    c.execute("SELECT COUNT(*) FROM tasks WHERE user_id = ?", (session['user_id'],))
    total_tasks = c.fetchone()[0]

    c.execute("SELECT COUNT(*) FROM tasks WHERE user_id = ? AND status = 'Завершена'", (session['user_id'],))
    completed_tasks = c.fetchone()[0]

    c.execute("SELECT COUNT(*) FROM tasks WHERE user_id = ? AND status != 'Завершена'", (session['user_id'],))
    active_tasks = c.fetchone()[0]

    conn.close()

    return render_template('profile.html',
                         username=user[0],
                         email=user[1],
                         pending_email=user[2],
                         timezone=user[3],
                         total_tasks=total_tasks,
                         completed_tasks=completed_tasks,
                         active_tasks=active_tasks)

@app.route('/update_profile', methods=['POST'])
def update_profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    new_username = request.form['username']
    new_email = request.form['email']
    new_timezone = request.form['timezone']

    conn = sqlite3.connect('tasks.db')
    c = conn.cursor()

    # Проверяем, не занята ли почта другим пользователем
    c.execute("SELECT id FROM users WHERE email = ? AND id != ?", (new_email, session['user_id']))
    if c.fetchone():
        flash('Этот email уже используется')
        return redirect(url_for('profile'))

    # Получаем текущий email пользователя
    c.execute("SELECT email FROM users WHERE id = ?", (session['user_id'],))
    current_email = c.fetchone()[0]

    # Обновляем имя пользователя и часовой пояс
    c.execute("UPDATE users SET username = ?, timezone = ? WHERE id = ?", (new_username, new_timezone, session['user_id']))
    session['username'] = new_username

    # Если email изменился, отправляем подтверждение
    if current_email != new_email:
        token = secrets.token_urlsafe(32)
        expiry = datetime.now() + timedelta(hours=24)

        c.execute("""UPDATE users 
                    SET pending_email = ?,
                        email_confirm_token = ?,
                        email_confirm_expiry = ?
                    WHERE id = ?""",
                 (new_email, token, expiry, session['user_id']))

        # Отправляем письмо подтверждения
        confirm_url = url_for('confirm_email', token=token, _external=True)
        msg = Message('Подтверждение email',
                      recipients=[new_email])
        msg.body = f'''Для подтверждения нового email перейдите по ссылке:
{confirm_url}

Если вы не запрашивали изменение email, проигнорируйте это сообщение.'''
        mail.send(msg)
        flash('На новый email отправлено письмо для подтверждения')
    else:
        flash('Профиль успешно обновлен')

    conn.commit()
    conn.close()
    return redirect(url_for('profile'))

@app.route('/confirm_email/<token>')
def confirm_email(token):
    conn = sqlite3.connect('tasks.db')
    c = conn.cursor()

    try:
        c.execute("""SELECT id, pending_email 
                     FROM users 
                     WHERE email_confirm_token = ? 
                     AND email_confirm_expiry > datetime('now')""",
                  (token,))
        result = c.fetchone()

        if result:
            user_id, new_email = result
            c.execute("""UPDATE users 
                        SET email = ?,
                            pending_email = NULL,
                            email_confirm_token = NULL,
                            email_confirm_expiry = NULL
                        WHERE id = ?""",
                     (new_email, user_id))
            conn.commit()
            flash('Email успешно подтвержден')
        else:
            flash('Недействительная или истекшая ссылка подтверждения')

    except Exception as e:
        flash('Произошла ошибка при подтверждении email')
        print(f"Error confirming email: {str(e)}")
    finally:
        conn.close()
        return redirect(url_for('profile'))

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    conn = sqlite3.connect('tasks.db')
    c = conn.cursor()

    c.execute(
        """
    SELECT id FROM users 
    WHERE reset_token = ? AND reset_token_expiry > datetime('now')
    """, (token, ))
    user = c.fetchone()

    if not user:
        conn.close()
        flash('Недействительная или истекшая ссылка для сброса пароля.')
        return redirect(url_for('login'))

    if request.method == 'POST':
        password = request.form['password']
        password_hash = generate_password_hash(password)

        c.execute(
            """
        UPDATE users 
        SET password = ?, reset_token = NULL, reset_token_expiry = NULL 
        WHERE id = ?
        """, (password_hash, user[0]))
        conn.commit()
        conn.close()

        flash('Ваш пароль был успешно изменен.')
        return redirect(url_for('login'))

    conn.close()
    return render_template('reset_password.html')


def send_reminders():
    print("Checking reminders...")
    conn = sqlite3.connect('tasks.db')
    c = conn.cursor()

    # Получаем задачи с включенными напоминаниями
    print("Fetching tasks with enabled reminders...")
    c.execute("""
        SELECT t.id, t.title, t.due_date, t.reminder_time, u.email, u.username, u.timezone
        FROM tasks t
        JOIN users u ON t.user_id = u.id
        WHERE t.send_reminder = 1 
        AND t.status != 'Завершена'
        AND t.due_date IS NOT NULL
        AND date(t.due_date) >= date('now')
    """)

    tasks = c.fetchall()
    
    print(f"Found {len(tasks)} tasks with reminders")
    for task in tasks:
        task_id, title, due_date, reminder_hours, email, username, user_timezone = task
        print(f"Processing task: {title} (ID: {task_id})")
        print(f"Due date: {due_date}, Reminder hours: {reminder_hours}")

        try:
            due_date = datetime.strptime(due_date, '%Y-%m-%d')
            due_date = due_date.replace(hour=23, minute=59, second=59)
            user_tz = timezone(user_timezone)
            due_date = user_tz.localize(due_date)

            # Проверяем, нужно ли отправить напоминание
            now = datetime.now(user_tz)
            time_until_due = due_date - now
            hours_until_due = time_until_due.total_seconds() / 3600
            print(f"Hours until due: {hours_until_due}, Reminder threshold: {reminder_hours}")

            if 0 <= hours_until_due <= float(reminder_hours):
                try:
                    msg = Message(
                        'Напоминание о задаче',
                        sender=app.config['MAIL_USERNAME'],
                        recipients=[email]
                    )
                    msg.body = f"""
Здравствуйте, {username}!

Напоминаем о предстоящей задаче:
Название: {title}
Срок выполнения: {due_date.strftime('%d.%m.%Y')}

С уважением,
Система управления задачами
                    """
                    print(f"Attempting to send email to {email} for task: {title}")
                    mail.send(msg)
                    print(f"Email sent successfully to {email}")

                    # Отключаем напоминание после отправки
                    c.execute("UPDATE tasks SET send_reminder = 0 WHERE id = ?", (task_id,))
                    conn.commit()
                except Exception as e:
                    print(f"Error sending reminder for task {task_id}: {str(e)}")

        except ValueError as e:
            print(f"Error parsing due date for task {task_id}: {str(e)}")


    conn.close()

def start_reminder_scheduler():
    from apscheduler.schedulers.background import BackgroundScheduler
    scheduler = BackgroundScheduler()
    scheduler.add_job(send_reminders, 'interval', minutes=5)
    scheduler.start()

if __name__ == '__main__':
    start_reminder_scheduler()
    app.run(host='0.0.0.0', port=5000, debug=True)