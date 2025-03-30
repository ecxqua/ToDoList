from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_mail import Mail, Message
import sqlite3
from datetime import datetime, timedelta
from pytz import timezone, all_timezones
import secrets
import os
import logging
from werkzeug.security import generate_password_hash, check_password_hash

# Set up logging for debugging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "development_secret_key")

# Configuration for Flask-Mail
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME', 'dontreplythispls@gmail.com')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD', 'gtni hkpx obub mlig')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER', 'dontreplythispls@gmail.com')
app.config['MAIL_ASCII_ATTACHMENTS'] = False
mail = Mail(app)

# Helper function to format datetime with user's timezone
def format_datetime(dt, user_timezone=None):
    if not dt:
        return None
        
    # Use session timezone or default to Moscow if not provided
    if not user_timezone:
        user_timezone = session.get('timezone', 'Europe/Moscow')
    
    # Convert string datetime to datetime object
    if isinstance(dt, str):
        try:
            # Try with time
            dt = datetime.strptime(dt, '%Y-%m-%d %H:%M:%S')
        except ValueError:
            try:
                # Try with date only
                dt = datetime.strptime(dt, '%Y-%m-%d')
                # Format as date only
                return dt.strftime('%d.%m.%Y')
            except ValueError:
                # If all parsing fails, return original
                return dt
                
    try:
        # Convert to UTC first if it's not already a timezone-aware datetime
        if dt.tzinfo is None:
            utc_tz = timezone('UTC')
            dt = utc_tz.localize(dt)
            
        # Convert to user's timezone
        local_tz = timezone(user_timezone)
        dt = dt.astimezone(local_tz)
        return dt.strftime('%d.%m.%Y %H:%M')
    except Exception as e:
        logger.error(f"Error formatting datetime: {e}")
        return str(dt)

# Initialize database
def init_db():
    conn = sqlite3.connect('tasks.db')
    c = conn.cursor()

    # Create users table with timezone field
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
        timezone TEXT DEFAULT "Europe/Moscow",
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    
    # Check if timezone column exists
    c.execute("PRAGMA table_info(users)")
    columns = [column[1] for column in c.fetchall()]
    if 'timezone' not in columns:
        c.execute('ALTER TABLE users ADD COLUMN timezone TEXT DEFAULT "Europe/Moscow"')
        conn.commit()

    # Create tasks table
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

# Initialize database
init_db()

# Authentication routes
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        timezone_name = request.form.get('timezone', 'Europe/Moscow')

        conn = sqlite3.connect('tasks.db')
        c = conn.cursor()

        # Check if user already exists
        c.execute("SELECT id FROM users WHERE username = ? OR email = ?",
                  (username, email))
        if c.fetchone():
            conn.close()
            flash('Пользователь с таким именем или email уже существует!')
            return redirect(url_for('register'))

        # Hash password and save user
        password_hash = generate_password_hash(password)
        c.execute(
            "INSERT INTO users (username, password, email, timezone) VALUES (?, ?, ?, ?)",
            (username, password_hash, email, timezone_name))
        conn.commit()
        conn.close()

        flash('Регистрация успешна! Теперь вы можете войти.')
        return redirect(url_for('login'))

    timezones = sorted([(tz, tz) for tz in all_timezones if 'Europe/' in tz or 'Asia/' in tz])
    return render_template('register.html', timezones=timezones)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        conn = sqlite3.connect('tasks.db')
        c = conn.cursor()

        try:
            c.execute("SELECT id, password, username, timezone FROM users WHERE email = ?",
                      (email, ))
            user = c.fetchone()

            if user and check_password_hash(user[1], password):
                session['user_id'] = user[0]
                session['username'] = user[2]
                session['timezone'] = user[3] or 'Europe/Moscow'
                conn.close()
                return redirect(url_for('dashboard'))

            conn.close()
            flash('Неверное имя пользователя или пароль!')
        except Exception as e:
            conn.close()
            logger.error(f"Login error: {e}")
            flash('Ошибка при входе в систему')

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    session.pop('timezone', None)
    return redirect(url_for('login'))

# Task management routes
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
        due_date = request.form['due_date'] if request.form['due_date'] else None

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
        due_date = request.form['due_date'] if request.form['due_date'] else None
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

    # Statistics by category
    c.execute(
        """
    SELECT category, COUNT(*) as count
    FROM tasks
    WHERE user_id = ?
    GROUP BY category
    """, (session['user_id'], ))
    categories = c.fetchall()

    # Statistics by priority
    c.execute(
        """
    SELECT priority, COUNT(*) as count
    FROM tasks
    WHERE user_id = ?
    GROUP BY priority
    """, (session['user_id'], ))
    priorities = c.fetchall()

    # Statistics by status
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

@app.route('/profile', methods=['GET'])
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = sqlite3.connect('tasks.db')
    c = conn.cursor()
    
    # Get user information
    c.execute("SELECT username, email, timezone FROM users WHERE id = ?", (session['user_id'],))
    user = c.fetchone()
    
    # Get task statistics
    c.execute("SELECT COUNT(*) FROM tasks WHERE user_id = ?", (session['user_id'],))
    total_tasks = c.fetchone()[0]
    
    c.execute("SELECT COUNT(*) FROM tasks WHERE user_id = ? AND status = 'Завершена'", (session['user_id'],))
    completed_tasks = c.fetchone()[0]
    
    active_tasks = total_tasks - completed_tasks
    
    conn.close()
    
    # Get all available timezones for Russia
    timezones = sorted([(tz, tz) for tz in all_timezones if 'Europe/' in tz or 'Asia/' in tz])
    
    return render_template('profile.html', 
                          username=user[0], 
                          email=user[1], 
                          timezone=user[2] or 'Europe/Moscow',
                          total_tasks=total_tasks,
                          completed_tasks=completed_tasks,
                          active_tasks=active_tasks,
                          timezones=timezones)

@app.route('/update_profile', methods=['POST'])
def update_profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    username = request.form['username']
    email = request.form['email']
    timezone_name = request.form['timezone']
    
    conn = sqlite3.connect('tasks.db')
    c = conn.cursor()
    
    # Get current user info to check if email changed
    c.execute("SELECT email FROM users WHERE id = ?", (session['user_id'],))
    current_email = c.fetchone()[0]
    
    # Update username and timezone
    c.execute("UPDATE users SET username = ?, timezone = ? WHERE id = ?", 
              (username, timezone_name, session['user_id']))
    
    # Handle email change if needed
    if email != current_email:
        # In a real app, we would send verification to the new email
        # For now, we'll just update it
        c.execute("UPDATE users SET email = ? WHERE id = ?", (email, session['user_id']))
    
    conn.commit()
    conn.close()
    
    # Update session data
    session['username'] = username
    session['timezone'] = timezone_name
    
    flash('Профиль успешно обновлен!')
    return redirect(url_for('profile'))

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

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    conn = sqlite3.connect('tasks.db')
    c = conn.cursor()
    c.execute("SELECT id FROM users WHERE reset_token = ? AND reset_token_expiry > ?", 
              (token, datetime.now()))
    user = c.fetchone()
    
    if not user:
        conn.close()
        flash('Ссылка для сброса пароля недействительна или срок ее действия истек.')
        return redirect(url_for('reset_password_request'))
    
    if request.method == 'POST':
        password = request.form['password']
        password_hash = generate_password_hash(password)
        
        c.execute("UPDATE users SET password = ?, reset_token = NULL, reset_token_expiry = NULL WHERE id = ?",
                 (password_hash, user[0]))
        conn.commit()
        conn.close()
        
        flash('Ваш пароль успешно изменен. Теперь вы можете войти с новым паролем.')
        return redirect(url_for('login'))
    
    conn.close()
    return render_template('reset_password.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
