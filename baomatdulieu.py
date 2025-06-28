
import sqlite3
import os
import re
from datetime import datetime, timedelta
from flask import Flask, request, render_template, redirect, url_for, flash, session
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, Regexp, EqualTo
from Crypto.Cipher import DES3, AES
from Crypto.Util.Padding import pad, unpad
import base64
import bcrypt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address


# Thêm lớp ViewForm
class ViewForm(FlaskForm):
    submit = SubmitField('Submit')  # Trường submit để tương thích với template

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Secure session and CSRF key
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)  # Session timeout

# Encryption keys (consider storing in environment variables for production)
TRIPLE_DES_KEY = b'Sixteen byte key12345678'  # 24 bytes for 3DES
AES_KEY = b'ThirtyTwoByteKeyForAES256!!!!!!!'  # 32 bytes for AES-256

# Initialize Flask-Limiter for login attempt limits
limiter = Limiter(app=app, key_func=get_remote_address, default_limits=["5 per 15 minutes"])

# Database initialization
def init_db():
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            name TEXT,
            cmnd TEXT,  -- Encrypted with 3DES
            diachi TEXT,  -- Encrypted with AES
            stk_nganhang TEXT,  -- Encrypted with AES
            so_bhxh TEXT,  -- Encrypted with AES
            login_attempts INTEGER DEFAULT 0,
            locked_until TIMESTAMP,
            role TEXT DEFAULT 'user'
        )
    """)
    # Create default admin if not exists
    admin_password = bcrypt.hashpw(b'admin123', bcrypt.gensalt()).decode()
    cursor.execute("""
        INSERT OR IGNORE INTO users (username, password, role)
        VALUES (?, ?, ?)
    """, ('admin', admin_password, 'admin'))
    conn.commit()
    conn.close()

# Encryption functions
def encrypt_3des(data, key):
    cipher = DES3.new(key, DES3.MODE_CBC)
    iv = cipher.iv
    padded_data = pad(data.encode(), DES3.block_size)
    encrypted = cipher.encrypt(padded_data)
    return base64.b64encode(iv + encrypted).decode()

def decrypt_3des(encrypted_data, key):
    encrypted_data = base64.b64decode(encrypted_data)
    iv = encrypted_data[:DES3.block_size]
    cipher = DES3.new(key, DES3.MODE_CBC, iv=iv)
    decrypted = unpad(cipher.decrypt(encrypted_data[DES3.block_size:]), DES3.block_size)
    return decrypted.decode()

def encrypt_aes(data, key):
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv
    padded_data = pad(data.encode(), AES.block_size)
    encrypted = cipher.encrypt(padded_data)
    return base64.b64encode(iv + encrypted).decode()

def decrypt_aes(encrypted_data, key):
    encrypted_data = base64.b64decode(encrypted_data)
    iv = encrypted_data[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    decrypted = unpad(cipher.decrypt(encrypted_data[AES.block_size:]), AES.block_size)
    return decrypted.decode()

# Logging function
def log_action(action, user_id, details):
    with open("access_log.txt", "a") as f:
        timestamp = datetime.now().strftime("%Y-%m-%d %I:%M %p +07")
        f.write(f"[{timestamp}] UserID: {user_id}, Action: {action}, Details: {details}\n")

# Flask-WTF Forms
class RegisterForm(FlaskForm):
    username = StringField('Tên đăng nhập', validators=[
        DataRequired(), Length(min=4, max=20),
        Regexp(r'^[a-zA-Z0-9_]+$', message="Chỉ chứa chữ cái, số, dấu gạch dưới!")
    ])
    password = PasswordField('Mật khẩu', validators=[DataRequired(), Length(min=8)])
    name = StringField('Họ tên', validators=[DataRequired(), Length(max=100)])
    cmnd = StringField('Số CMND', validators=[
        DataRequired(), Regexp(r'^\d{12}$', message="CMND phải là 12 chữ số!")
    ])
    diachi = StringField('Địa chỉ', validators=[DataRequired(), Length(max=200)])
    stk_nganhang = StringField('Số tài khoản', validators=[
        DataRequired(), Regexp(r'^\d{10,16}$', message="Số tài khoản phải từ 10-16 chữ số!")
    ])
    so_bhxh = StringField('Số BHXH', validators=[
        DataRequired(), Regexp(r'^\d{10}$', message="Số BHXH phải là 10 chữ số!")
    ])
    submit = SubmitField('Đăng ký')

class LoginForm(FlaskForm):
    username = StringField('Tên đăng nhập', validators=[DataRequired()])
    password = PasswordField('Mật khẩu', validators=[DataRequired()])
    submit = SubmitField('Đăng nhập')

class UpdateForm(FlaskForm):
    name = StringField('Họ tên', validators=[Length(max=100)])
    cmnd = StringField('Số CMND', validators=[Regexp(r'^\d{12}$', message="CMND phải là 12 chữ số!")])
    diachi = StringField('Địa chỉ', validators=[Length(max=200)])
    stk_nganhang = StringField('Số tài khoản', validators=[Regexp(r'^\d{10,16}$', message="Số tài khoản phải từ 10-16 chữ số!")])
    so_bhxh = StringField('Số BHXH', validators=[Regexp(r'^\d{10}$', message="Số BHXH phải là 10 chữ số!")])
    submit = SubmitField('Cập nhật')

class ChangePasswordForm(FlaskForm):
    old_password = PasswordField('Mật khẩu cũ', validators=[DataRequired()])
    new_password = PasswordField('Mật khẩu mới', validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField('Xác nhận mật khẩu mới', validators=[
        DataRequired(), EqualTo('new_password', message='Mật khẩu không khớp!')
    ])
    submit = SubmitField('Đổi mật khẩu')

class AdminForm(FlaskForm):
    username = StringField('Tên đăng nhập', validators=[DataRequired()])
    password = PasswordField('Mật khẩu', validators=[DataRequired()])
    submit = SubmitField('Xác nhận')

# Routes
@app.route('/')
def index():
    user_id = session.get('user_id', 'Guest')
    log_action("Access", user_id, "Accessed homepage")
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        data = form.data
        # Encrypt sensitive data
        cmnd_encrypted = encrypt_3des(data["cmnd"], TRIPLE_DES_KEY)
        diachi_encrypted = encrypt_aes(data["diachi"], AES_KEY)
        stk_encrypted = encrypt_aes(data["stk_nganhang"], AES_KEY)
        so_bhxh_encrypted = encrypt_aes(data["so_bhxh"], AES_KEY)
        password = bcrypt.hashpw(data["password"].encode(), bcrypt.gensalt()).decode()

        conn = sqlite3.connect("users.db")
        cursor = conn.cursor()
        try:
            cursor.execute("""
                INSERT INTO users (username, password, name, cmnd, diachi, stk_nganhang, so_bhxh)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (data["username"], password, data["name"], cmnd_encrypted, diachi_encrypted, stk_encrypted, so_bhxh_encrypted))
            conn.commit()
            user_id = cursor.lastrowid
            log_action("Register", user_id, f"User {data['username']} registered with encrypted data")
            flash("Đăng ký thành công!", 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash("Tên đăng nhập đã tồn tại!", 'error')
        finally:
            conn.close()
    return render_template('signup.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
# @limiter.limit("5 per 15 minutes")
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data.encode()

        conn = sqlite3.connect("users.db")
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()

        if user:
            locked_until = user[9] if user[9] else None
            if locked_until and datetime.now() < datetime.fromisoformat(locked_until):
                flash(f"Tài khoản bị khóa đến {locked_until}. Vui lòng thử lại sau!", 'error')
                conn.close()
                return render_template('signin.html', form=form)

            if bcrypt.checkpw(password, user[2].encode()):
                cursor.execute("UPDATE users SET login_attempts = 0, locked_until = NULL WHERE id = ?", (user[0],))
                conn.commit()
                session['user_id'] = user[0]
                session['username'] = user[1]
                session['role'] = user[10] if user[10] else 'user'
                log_action("Login", user[0], f"User {username} logged in")
                conn.close()
                return redirect(url_for('user_info'))
            else:
                current_attempts = user[8]
                new_attempts = current_attempts + 1
                cursor.execute("UPDATE users SET login_attempts = ? WHERE id = ?", (new_attempts, user[0]))
                if new_attempts >= 5:
                    lock_time = (datetime.now() + timedelta(minutes=15)).isoformat()
                    cursor.execute("UPDATE users SET locked_until = ? WHERE id = ?", (lock_time, user[0]))
                    flash("Tài khoản đã bị khóa 15 phút do đăng nhập sai quá nhiều!", 'error')
                else:
                    flash(f"Sai mật khẩu! Còn {5 - new_attempts} lần thử.", 'error')
                conn.commit()
        else:
            flash("Tên đăng nhập không tồn tại!", 'error')
        log_action("Failed Login", "Unknown", f"Failed login attempt with username: {username}")
        conn.close()
    return render_template('signin.html', form=form)


@app.route('/user_info')
def user_info():
    if 'user_id' not in session:
        log_action("Access Denied", "Guest", "Attempted to access user_info without login")
        flash("Vui lòng đăng nhập!", 'error')
        return redirect(url_for('login'))

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (session['user_id'],))
    user = cursor.fetchone()
    conn.close()

    decrypted_data = {
        'name': user[3],
        'cmnd': decrypt_3des(user[4], TRIPLE_DES_KEY) if user[4] else '',
        'diachi': decrypt_aes(user[5], AES_KEY) if user[5] else '',
        'stk_nganhang': decrypt_aes(user[6], AES_KEY) if user[6] else '',
        'so_bhxh': decrypt_aes(user[7], AES_KEY) if user[7] else ''
    }
    log_action("View", user[0], f"User {user[1]} viewed their info")
    return render_template('profile.html', user=decrypted_data)

@app.route('/update', methods=['GET', 'POST'])
def update():
    if 'user_id' not in session:
        log_action("Access Denied", "Guest", "Attempted to access update page without login")
        flash("Vui lòng đăng nhập!", 'error')
        return redirect(url_for('login'))

    form = UpdateForm()
    if form.validate_on_submit():
        data = {k: v for k, v in form.data.items() if k != 'submit' and v}
        conn = sqlite3.connect("users.db")
        cursor = conn.cursor()
        updates = []
        values = []
        encrypted_updates = {}

        if data.get("name"):
            updates.append("name = ?")
            values.append(data["name"])
            encrypted_updates["name"] = data["name"]
        if data.get("cmnd"):
            encrypted_cmnd = encrypt_3des(data["cmnd"], TRIPLE_DES_KEY)
            updates.append("cmnd = ?")
            values.append(encrypted_cmnd)
            encrypted_updates["cmnd"] = encrypted_cmnd
        if data.get("diachi"):
            encrypted_diachi = encrypt_aes(data["diachi"], AES_KEY)
            updates.append("diachi = ?")
            values.append(encrypted_diachi)
            encrypted_updates["diachi"] = encrypted_diachi
        if data.get("stk_nganhang"):
            encrypted_stk = encrypt_aes(data["stk_nganhang"], AES_KEY)
            updates.append("stk_nganhang = ?")
            values.append(encrypted_stk)
            encrypted_updates["stk_nganhang"] = encrypted_stk
        if data.get("so_bhxh"):
            encrypted_so_bhxh = encrypt_aes(data["so_bhxh"], AES_KEY)
            updates.append("so_bhxh = ?")
            values.append(encrypted_so_bhxh)
            encrypted_updates["so_bhxh"] = encrypted_so_bhxh

        if updates:
            values.append(session['user_id'])
            query = f"UPDATE users SET {', '.join(updates)} WHERE id = ?"
            cursor.execute(query, values)
            conn.commit()
            log_action("Update", session['user_id'], f"User {session['username']} updated fields: {encrypted_updates}")
            flash("Cập nhật thành công!", 'success')
        conn.close()
        return redirect(url_for('user_info'))
    return render_template('edit.html', form=form)

@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if 'user_id' not in session:
        log_action("Access Denied", "Guest", "Attempted to access change password without login")
        flash("Vui lòng đăng nhập!", 'error')
        return redirect(url_for('login'))

    form = ChangePasswordForm()
    if form.validate_on_submit():
        conn = sqlite3.connect("users.db")
        cursor = conn.cursor()
        cursor.execute("SELECT password FROM users WHERE id = ?", (session['user_id'],))
        user = cursor.fetchone()

        if bcrypt.checkpw(form.old_password.data.encode(), user[0].encode()):
            new_password = bcrypt.hashpw(form.new_password.data.encode(), bcrypt.gensalt()).decode()
            cursor.execute("UPDATE users SET password = ? WHERE id = ?", (new_password, session['user_id']))
            conn.commit()
            log_action("Change Password", session['user_id'], f"User {session['username']} changed password")
            flash("Đổi mật khẩu thành công!", 'success')
            conn.close()
            return redirect(url_for('user_info'))
        else:
            flash("Mật khẩu cũ không đúng!", 'error')
        conn.close()
    return render_template('change_password.html', form=form)

@app.route('/delete')
def delete():
    if 'user_id' not in session:
        log_action("Access Denied", "Guest", "Attempted to delete account without login")
        flash("Vui lòng đăng nhập!", 'error')
        return redirect(url_for('login'))

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("DELETE FROM users WHERE id = ?", (session['user_id'],))
    conn.commit()
    log_action("Delete", session['user_id'], f"User {session['username']} deleted their account")
    conn.close()
    session.clear()
    flash("Xóa tài khoản thành công!", 'success')
    return redirect(url_for('index'))

@app.route('/admin', methods=['GET', 'POST'])
def admin():
    form = AdminForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data.encode()

        conn = sqlite3.connect("users.db")
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ? AND role = 'admin'", (username,))
        admin = cursor.fetchone()
        conn.close()

        if admin and bcrypt.checkpw(password, admin[2].encode()):
            session['admin'] = True
            session['user_id'] = admin[0]
            session['username'] = admin[1]
            session['role'] = admin[10]
            log_action("Admin Login", admin[0], "Admin logged in")
            return redirect(url_for('admin_panel'))
        else:
            log_action("Failed Admin Login", "Unknown", "Failed admin login attempt")
            flash("Sai thông tin admin!", 'error')
    return render_template('admin_login.html', form=form)

@app.route('/admin_panel')
def admin_panel():
    if 'admin' not in session or session.get('role') != 'admin':
        log_action("Access Denied", "Guest", "Attempted to access admin panel without verification")
        flash("Vui lòng xác minh admin!", 'error')
        return redirect(url_for('admin'))
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, name, login_attempts, locked_until FROM users WHERE role = 'user'")
    users = cursor.fetchall()
    print("Users in admin_panel:", users)  # Debug
    conn.close()
    log_action("Admin View", "Admin", "Admin viewed user list")
    return render_template('admin_dashboard.html', users=users)

# Route admin_view
@app.route('/admin_view/<int:user_id>', methods=['GET', 'POST'])
def admin_view(user_id):
    if 'admin' not in session or session.get('role') != 'admin':
        log_action("Access Denied", "Guest", f"Attempted to view user {user_id} without admin verification")
        flash("Vui lòng xác minh admin!", 'error')
        return redirect(url_for('admin'))
    
    form = ViewForm()  # Khởi tạo form
    
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    conn.close()
    
    if not user:
        log_action("Admin View", "Admin", f"User {user_id} not found")
        flash("Người dùng không tồn tại!", 'error')
        return redirect(url_for('admin_panel'))
    
    decrypted_data = {
        'username': user[1],
        'name': user[3],
        'cmnd': decrypt_3des(user[4], TRIPLE_DES_KEY) if user[4] else '',
        'diachi': decrypt_aes(user[5], AES_KEY) if user[5] else '',
        'stk_nganhang': decrypt_aes(user[6], AES_KEY) if user[6] else '',
        'so_bhxh': decrypt_aes(user[7], AES_KEY) if user[7] else ''
    }
    log_action("Admin View", "Admin", f"Admin viewed sensitive data of user {user[1]}")
    return render_template('admin_view.html', user=decrypted_data, user_id=user_id, form=form)

@app.route('/admin_edit/<int:user_id>', methods=['GET', 'POST'])
def admin_edit(user_id):
    if 'admin' not in session or session.get('role') != 'admin':
        log_action("Access Denied", "Guest", f"Attempted to edit user {user_id} without admin verification")
        flash("Vui lòng xác minh admin!", 'error')
        return redirect(url_for('admin'))

    form = UpdateForm()
    if form.validate_on_submit():
        data = {k: v for k, v in form.data.items() if k != 'submit' and v}
        conn = sqlite3.connect("users.db")
        cursor = conn.cursor()
        updates = []
        values = []
        encrypted_updates = {}

        if data.get("name"):
            updates.append("name = ?")
            values.append(data["name"])
            encrypted_updates["name"] = data["name"]
        if data.get("cmnd"):
            encrypted_cmnd = encrypt_3des(data["cmnd"], TRIPLE_DES_KEY)
            updates.append("cmnd = ?")
            values.append(encrypted_cmnd)
            encrypted_updates["cmnd"] = encrypted_cmnd
        if data.get("diachi"):
            encrypted_diachi = encrypt_aes(data["diachi"], AES_KEY)
            updates.append("diachi = ?")
            values.append(encrypted_diachi)
            encrypted_updates["diachi"] = encrypted_diachi
        if data.get("stk_nganhang"):
            encrypted_stk = encrypt_aes(data["stk_nganhang"], AES_KEY)
            updates.append("stk_nganhang = ?")
            values.append(encrypted_stk)
            encrypted_updates["stk_nganhang"] = encrypted_stk
        if data.get("so_bhxh"):
            encrypted_so_bhxh = encrypt_aes(data["so_bhxh"], AES_KEY)
            updates.append("so_bhxh = ?")
            values.append(encrypted_so_bhxh)
            encrypted_updates["so_bhxh"] = encrypted_so_bhxh

        if updates:
            values.append(user_id)
            query = f"UPDATE users SET {', '.join(updates)} WHERE id = ?"
            cursor.execute(query, values)
            conn.commit()
            log_action("Admin Edit", "Admin", f"Admin edited user {user_id}: {encrypted_updates}")
            flash("Cập nhật người dùng thành công!", 'success')
        conn.close()
        return redirect(url_for('admin_panel'))
    return render_template('admin_edit.html', form=form, user_id=user_id)

@app.route('/admin_delete/<int:user_id>')
def admin_delete(user_id):
    if 'admin' not in session or session.get('role') != 'admin':
        log_action("Access Denied", "Guest", f"Attempted to delete user {user_id} without admin verification")
        flash("Vui lòng xác minh admin!", 'error')
        return redirect(url_for('admin'))

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("SELECT username FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    if user:
        cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()
        log_action("Admin Delete", "Admin", f"Admin deleted user {user[0]}")
        flash("Xóa người dùng thành công!", 'success')
    conn.close()
    return redirect(url_for('admin_panel'))

@app.route('/logout')
def logout():
    user_id = session.get('user_id', 'Unknown')
    log_action("Logout", user_id, f"User {session.get('username', 'Unknown')} logged out")
    session.clear()
    flash("Đã đăng xuất!", 'success')
    return redirect(url_for('index'))

if __name__ == "__main__":
    init_db()
    app.run(debug=True)