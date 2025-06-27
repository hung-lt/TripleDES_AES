import sqlite3
import os
import re
from datetime import datetime
from flask import Flask, request, render_template, redirect, url_for, flash, session
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, Regexp
from Crypto.Cipher import DES3, AES
from Crypto.Util.Padding import pad, unpad
import base64
import hashlib

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Khóa bí mật cho session và CSRF

# Khóa mã hóa (tĩnh, có thể mở rộng để sinh động)
TRIPLE_DES_KEY = b'Sixteen byte key12345678'  # 24 bytes cho 3DES
AES_KEY = b'ThirtyTwoByteKeyForAES256!!!!!!!'  # 32 bytes cho AES-256
ADMIN_PASSWORD_HASH = hashlib.sha256(b'admin123').hexdigest()  # Mật khẩu admin mẫu

# Hàm mã hóa và giải mã bằng Triple DES
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

# Hàm mã hóa và giải mã bằng AES
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

# Hàm ghi log
def log_action(action, user_id, details):
    with open("access_log.txt", "a") as f:
        timestamp = datetime.now().strftime("%Y-%m-%d %I:%M %p +07")
        f.write(f"[{timestamp}] UserID: {user_id}, Action: {action}, Details: {details}\n")

# Khởi tạo cơ sở dữ liệu
def init_db():
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            name TEXT,
            cmnd TEXT,  -- Mã hóa bằng 3DES
            diachi TEXT,  -- Mã hóa bằng AES
            stk_nganhang TEXT  -- Mã hóa bằng AES
        )
    """)
    conn.commit()
    conn.close()

# Form Flask-WTF
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
    submit = SubmitField('Cập nhật')

class AdminForm(FlaskForm):
    password = PasswordField('Mật khẩu admin', validators=[DataRequired()])
    submit = SubmitField('Xác nhận')

# Route trang chủ
@app.route('/')
def index():
    user_id = session.get('user_id', 'Guest')
    log_action("Access", user_id, "Accessed homepage")
    return render_template('home.html')

# Route đăng ký
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        data = form.data
        # Mã hóa dữ liệu nhạy cảm
        cmnd_encrypted = encrypt_3des(data["cmnd"], TRIPLE_DES_KEY)
        diachi_encrypted = encrypt_aes(data["diachi"], AES_KEY)
        stk_encrypted = encrypt_aes(data["stk_nganhang"], AES_KEY)
        password = hashlib.sha256(data["password"].encode()).hexdigest()

        conn = sqlite3.connect("users.db")
        cursor = conn.cursor()
        try:
            cursor.execute("""
                INSERT INTO users (username, password, name, cmnd, diachi, stk_nganhang)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (data["username"], password, data["name"], cmnd_encrypted, diachi_encrypted, stk_encrypted))
            conn.commit()
            user_id = cursor.lastrowid
            log_action("Register", user_id, f"User {data['username']} registered with encrypted data - CMND: {cmnd_encrypted}, Address: {diachi_encrypted}, Bank Account: {stk_encrypted}")
            flash("Đăng ký thành công!", 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash("Tên đăng nhập đã tồn tại!", 'error')
        finally:
            conn.close()
    return render_template('signup.html', form=form)

# Route đăng nhập
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = hashlib.sha256(form.password.data.encode()).hexdigest()

        conn = sqlite3.connect("users.db")
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
        user = cursor.fetchone()
        conn.close()

        if user:
            session['user_id'] = user[0]
            session['username'] = user[1]
            log_action("Login", user[0], f"User {username} logged in")
            return redirect(url_for('user_info'))
        else:
            log_action("Failed Login", "Unknown", f"Failed login attempt with username: {username}")
            flash("Sai tên đăng nhập hoặc mật khẩu!", 'error')
    return render_template('signin.html', form=form)

# Route thông tin người dùng
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
        'cmnd': decrypt_3des(user[4], TRIPLE_DES_KEY),
        'diachi': decrypt_aes(user[5], AES_KEY),
        'stk_nganhang': decrypt_aes(user[6], AES_KEY)
    }
    log_action("View", user[0], f"User {user[1]} viewed their info - Decrypted: CMND={decrypted_data['cmnd']}, Address={decrypted_data['diachi']}, Bank Account={decrypted_data['stk_nganhang']}")
    return render_template('profile.html', user=decrypted_data)

# Route sửa thông tin
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

        if updates:
            values.append(session['user_id'])
            query = f"UPDATE users SET {', '.join(updates)} WHERE id = ?"
            cursor.execute(query, values)
            conn.commit()
            log_action("Update", session['user_id'], f"User {session['username']} updated encrypted fields: {encrypted_updates}")
            flash("Cập nhật thành công!", 'success')
        conn.close()
        return redirect(url_for('user_info'))
    return render_template('edit.html', form=form)

# Route xóa tài khoản
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

# Route quản trị viên
@app.route('/admin', methods=['GET', 'POST'])
def admin():
    form = AdminForm()
    if form.validate_on_submit():
        password = hashlib.sha256(form.password.data.encode()).hexdigest()
        if password != ADMIN_PASSWORD_HASH:
            log_action("Failed Admin Login", "Unknown", "Failed admin login attempt")
            flash("Sai mật khẩu admin!", 'error')
            return redirect(url_for('admin'))
        session['admin'] = True
        log_action("Admin Login", "Admin", "Admin logged in")
        return redirect(url_for('admin_panel'))
    return render_template('admin_login.html', form=form)

# Route bảng quản trị
@app.route('/admin_panel')
def admin_panel():
    if 'admin' not in session:
        log_action("Access Denied", "Guest", "Attempted to access admin panel without verification")
        flash("Vui lòng xác minh admin!", 'error')
        return redirect(url_for('admin'))

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, name FROM users")
    users = cursor.fetchall()
    conn.close()
    log_action("Admin View", "Admin", "Admin viewed user list")
    return render_template('admin_dashboard.html', users=users)

@app.route('/admin_view/<int:user_id>', methods=['GET', 'POST'])
def admin_view(user_id):
    if 'admin' not in session:
        log_action("Access Denied", "Guest", f"Attempted to view user {user_id} without admin verification")
        flash("Vui lòng xác minh admin!", 'error')
        return redirect(url_for('admin'))

    form = AdminForm()
    user_data = None

    # Lấy thông tin người dùng
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    conn.close()

    if not user:
        log_action("Admin View", "Admin", f"User {user_id} not found")
        flash("Người dùng không tồn tại!", 'error')
        return redirect(url_for('admin_panel'))

    if form.validate_on_submit():
        password = hashlib.sha256(form.password.data.encode()).hexdigest()
        if password != ADMIN_PASSWORD_HASH:
            log_action("Failed Admin Verification", "Admin", f"Failed verification to view user {user_id}")
            flash("Sai mật khẩu admin!", 'error')
        else:
            # Giải mã thông tin người dùng
            user_data = {
                'username': user[1],
                'name': user[3],
                'cmnd': decrypt_3des(user[4], TRIPLE_DES_KEY),
                'diachi': decrypt_aes(user[5], AES_KEY),
                'stk_nganhang': decrypt_aes(user[6], AES_KEY)
            }
            log_action("Admin View", "Admin", f"Admin viewed sensitive data of user {user[1]} - Decrypted: CMND={user_data['cmnd']}, Address={user_data['diachi']}, Bank Account={user_data['stk_nganhang']}")

    return render_template('admin_view.html', form=form, user_id=user_id, user=user_data)

# Route đăng xuất
@app.route('/logout')
def logout():
    user_id = session.get('user_id', 'Unknown')
    log_action("Logout", user_id, f"User {session.get('username', 'Unknown')} logged out")
    session.clear()
    flash("Đã đăng xuất!", 'success')
    return redirect(url_for('index'))

# Chạy ứng dụng
if __name__ == "__main__":
    init_db()
    app.run(debug=True)