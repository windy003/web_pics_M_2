import os
import uuid
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_from_directory, session
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import sqlite3
import shutil

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here-change-in-production'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# 允许的文件扩展名
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'bmp', 'webp'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def login_required(f):
    """登录验证装饰器"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('请先登录', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def table_exists(cursor, table_name):
    """检查表是否存在"""
    cursor.execute("""
        SELECT name FROM sqlite_master 
        WHERE type='table' AND name=?
    """, (table_name,))
    return cursor.fetchone() is not None

def column_exists(cursor, table_name, column_name):
    """检查列是否存在"""
    cursor.execute(f"PRAGMA table_info({table_name})")
    columns = [column[1] for column in cursor.fetchall()]
    return column_name in columns

def init_db():
    """初始化数据库和处理迁移"""
    conn = sqlite3.connect('gallery.db')
    cursor = conn.cursor()
    
    # 检查是否是全新数据库
    is_new_db = not table_exists(cursor, 'folders')
    
    # 创建用户表
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    if is_new_db:
        # 全新数据库，直接创建新结构
        cursor.execute('''
            CREATE TABLE folders (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                description TEXT DEFAULT '',
                user_id INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id),
                UNIQUE(name, user_id)
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE images (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT NOT NULL,
                original_filename TEXT NOT NULL,
                folder_id INTEGER,
                user_id INTEGER NOT NULL,
                uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (folder_id) REFERENCES folders (id),
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
    else:
        # 现有数据库，需要迁移
        migrate_database(cursor)
    
    conn.commit()
    conn.close()

def migrate_database(cursor):
    """迁移现有数据库到新结构"""
    print("检测到现有数据库，开始迁移...")
    
    # 检查folders表是否需要添加user_id列
    if table_exists(cursor, 'folders') and not column_exists(cursor, 'folders', 'user_id'):
        print("迁移folders表...")
        
        # 创建临时管理员用户
        cursor.execute('''
            INSERT OR IGNORE INTO users (username, email, password_hash) 
            VALUES ('admin', 'admin@example.com', ?)
        ''', (generate_password_hash('admin123'),))
        
        # 获取管理员用户ID
        admin_user = cursor.execute('SELECT id FROM users WHERE username = "admin"').fetchone()
        admin_id = admin_user[0]
        
        # 备份现有folders表
        cursor.execute('ALTER TABLE folders RENAME TO folders_old')
        
        # 创建新的folders表
        cursor.execute('''
            CREATE TABLE folders (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                description TEXT DEFAULT '',
                user_id INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id),
                UNIQUE(name, user_id)
            )
        ''')
        
        # 迁移数据
        cursor.execute('''
            INSERT INTO folders (id, name, description, user_id, created_at)
            SELECT id, name, COALESCE(description, ''), ?, created_at
            FROM folders_old
        ''', (admin_id,))
        
        # 删除旧表
        cursor.execute('DROP TABLE folders_old')
        print("folders表迁移完成")
    
    # 检查images表是否需要添加user_id列
    if table_exists(cursor, 'images') and not column_exists(cursor, 'images', 'user_id'):
        print("迁移images表...")
        
        # 获取管理员用户ID
        admin_user = cursor.execute('SELECT id FROM users WHERE username = "admin"').fetchone()
        admin_id = admin_user[0]
        
        # 备份现有images表
        cursor.execute('ALTER TABLE images RENAME TO images_old')
        
        # 创建新的images表
        cursor.execute('''
            CREATE TABLE images (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT NOT NULL,
                original_filename TEXT NOT NULL,
                folder_id INTEGER,
                user_id INTEGER NOT NULL,
                uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (folder_id) REFERENCES folders (id),
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        # 迁移数据
        cursor.execute('''
            INSERT INTO images (id, filename, original_filename, folder_id, user_id, uploaded_at)
            SELECT id, filename, original_filename, folder_id, ?, uploaded_at
            FROM images_old
        ''', (admin_id,))
        
        # 删除旧表
        cursor.execute('DROP TABLE images_old')
        
        # 移动现有图片文件到用户目录
        migrate_image_files(admin_id)
        print("images表迁移完成")
    
    print("数据库迁移完成！")
    print("如果你有现有数据，默认管理员账户为：")
    print("用户名: admin")
    print("密码: admin123")
    print("请登录后修改密码！")

def migrate_image_files(user_id):
    """迁移图片文件到用户目录"""
    upload_folder = app.config['UPLOAD_FOLDER']
    user_folder = os.path.join(upload_folder, str(user_id))
    
    if not os.path.exists(upload_folder):
        return
    
    # 创建用户目录
    os.makedirs(user_folder, exist_ok=True)
    
    # 移动所有图片文件到用户目录
    for filename in os.listdir(upload_folder):
        if filename.lower().endswith(('.png', '.jpg', '.jpeg', '.gif', '.bmp', '.webp')):
            old_path = os.path.join(upload_folder, filename)
            new_path = os.path.join(user_folder, filename)
            if os.path.isfile(old_path) and not os.path.exists(new_path):
                shutil.move(old_path, new_path)

def get_db_connection():
    """获取数据库连接"""
    conn = sqlite3.connect('gallery.db')
    conn.row_factory = sqlite3.Row
    return conn

def create_default_folder(user_id):
    """为新用户创建默认文件夹"""
    conn = get_db_connection()
    try:
        conn.execute('INSERT INTO folders (name, description, user_id) VALUES (?, ?, ?)', 
                     ('默认', '默认图片文件夹', user_id))
        conn.commit()
    except sqlite3.IntegrityError:
        pass  # 文件夹已存在
    finally:
        conn.close()

@app.route('/register', methods=['GET', 'POST'])
def register():
    """用户注册"""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()
        confirm_password = request.form.get('confirm_password', '').strip()
        
        # 验证输入
        if not username or not email or not password:
            flash('所有字段都是必填的', 'error')
            return render_template('register.html')
        
        if password != confirm_password:
            flash('两次输入的密码不一致', 'error')
            return render_template('register.html')
        
        if len(password) < 6:
            flash('密码长度至少6位', 'error')
            return render_template('register.html')
        
        # 检查用户名和邮箱是否已存在
        conn = get_db_connection()
        existing_user = conn.execute(
            'SELECT id FROM users WHERE username = ? OR email = ?', 
            (username, email)
        ).fetchone()
        
        if existing_user:
            flash('用户名或邮箱已存在', 'error')
            conn.close()
            return render_template('register.html')
        
        # 创建新用户
        password_hash = generate_password_hash(password)
        cursor = conn.execute(
            'INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)',
            (username, email, password_hash)
        )
        user_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        # 为新用户创建默认文件夹
        create_default_folder(user_id)
        
        flash('注册成功，请登录', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """用户登录"""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        
        if not username or not password:
            flash('请输入用户名和密码', 'error')
            return render_template('login.html')
        
        conn = get_db_connection()
        user = conn.execute(
            'SELECT * FROM users WHERE username = ? OR email = ?', 
            (username, username)
        ).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            flash(f'欢迎回来，{user["username"]}！', 'success')
            return redirect(url_for('index'))
        else:
            flash('用户名或密码错误', 'error')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    """用户登出"""
    session.clear()
    flash('已成功登出', 'success')
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    """主页 - 显示当前用户的所有文件夹和图片"""
    user_id = session['user_id']
    conn = get_db_connection()
    
    # 获取当前用户的所有文件夹
    folders = conn.execute(
        'SELECT * FROM folders WHERE user_id = ? ORDER BY name', 
        (user_id,)
    ).fetchall()
    
    # 获取每个文件夹的图片数量
    folder_counts = {}
    for folder in folders:
        count = conn.execute(
            'SELECT COUNT(*) FROM images WHERE folder_id = ? AND user_id = ?', 
            (folder['id'], user_id)
        ).fetchone()[0]
        folder_counts[folder['id']] = count
    
    conn.close()
    return render_template('index.html', folders=folders, folder_counts=folder_counts)

@app.route('/folder/<int:folder_id>')
@login_required
def view_folder(folder_id):
    """查看特定文件夹的图片"""
    user_id = session['user_id']
    conn = get_db_connection()
    
    # 获取文件夹信息（确保属于当前用户）
    folder = conn.execute(
        'SELECT * FROM folders WHERE id = ? AND user_id = ?', 
        (folder_id, user_id)
    ).fetchone()
    
    if not folder:
        flash('文件夹不存在或无权访问', 'error')
        return redirect(url_for('index'))
    
    # 获取文件夹中的图片
    images = conn.execute('''
        SELECT * FROM images WHERE folder_id = ? AND user_id = ? ORDER BY uploaded_at DESC
    ''', (folder_id, user_id)).fetchall()
    
    # 获取当前用户的所有文件夹（用于移动图片）
    all_folders = conn.execute(
        'SELECT * FROM folders WHERE user_id = ? ORDER BY name', 
        (user_id,)
    ).fetchall()
    
    conn.close()
    return render_template('folder.html', folder=folder, images=images, all_folders=all_folders)

@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    """上传图片"""
    if 'file' not in request.files:
        flash('没有选择文件', 'error')
        return redirect(request.referrer)
    
    file = request.files['file']
    folder_id = request.form.get('folder_id')
    user_id = session['user_id']
    
    if file.filename == '':
        flash('没有选择文件', 'error')
        return redirect(request.referrer)
    
    # 验证文件夹属于当前用户
    conn = get_db_connection()
    folder = conn.execute(
        'SELECT id FROM folders WHERE id = ? AND user_id = ?', 
        (folder_id, user_id)
    ).fetchone()
    
    if not folder:
        flash('无效的文件夹', 'error')
        conn.close()
        return redirect(request.referrer)
    
    if file and allowed_file(file.filename):
        # 生成唯一文件名
        file_extension = file.filename.rsplit('.', 1)[1].lower()
        unique_filename = f"{uuid.uuid4().hex}.{file_extension}"
        
        # 确保上传目录存在
        user_upload_dir = os.path.join(app.config['UPLOAD_FOLDER'], str(user_id))
        os.makedirs(user_upload_dir, exist_ok=True)
        
        # 保存文件
        file_path = os.path.join(user_upload_dir, unique_filename)
        file.save(file_path)
        
        # 保存到数据库
        conn.execute('''
            INSERT INTO images (filename, original_filename, folder_id, user_id)
            VALUES (?, ?, ?, ?)
        ''', (unique_filename, file.filename, folder_id, user_id))
        conn.commit()
        flash('图片上传成功', 'success')
    else:
        flash('不支持的文件格式', 'error')
    
    conn.close()
    return redirect(request.referrer)

@app.route('/create_folder', methods=['POST'])
@login_required
def create_folder():
    """创建新文件夹"""
    folder_name = request.form.get('folder_name', '').strip()
    description = request.form.get('description', '').strip()
    user_id = session['user_id']
    
    if not folder_name:
        flash('文件夹名称不能为空', 'error')
        return redirect(url_for('index'))
    
    conn = get_db_connection()
    try:
        conn.execute('INSERT INTO folders (name, description, user_id) VALUES (?, ?, ?)', 
                    (folder_name, description, user_id))
        conn.commit()
        flash('文件夹创建成功', 'success')
    except sqlite3.IntegrityError:
        flash('文件夹名称已存在', 'error')
    finally:
        conn.close()
    
    return redirect(url_for('index'))

@app.route('/update_folder/<int:folder_id>', methods=['POST'])
@login_required
def update_folder(folder_id):
    """更新文件夹信息"""
    folder_name = request.form.get('folder_name', '').strip()
    description = request.form.get('description', '').strip()
    user_id = session['user_id']
    
    if not folder_name:
        flash('文件夹名称不能为空', 'error')
        return redirect(request.referrer)
    
    conn = get_db_connection()
    try:
        result = conn.execute(
            'UPDATE folders SET name = ?, description = ? WHERE id = ? AND user_id = ?', 
            (folder_name, description, folder_id, user_id)
        )
        if result.rowcount == 0:
            flash('文件夹不存在或无权访问', 'error')
        else:
            conn.commit()
            flash('文件夹更新成功', 'success')
    except sqlite3.IntegrityError:
        flash('文件夹名称已存在', 'error')
    finally:
        conn.close()
    
    return redirect(request.referrer)

@app.route('/delete_folder/<int:folder_id>', methods=['POST'])
@login_required
def delete_folder(folder_id):
    """删除文件夹"""
    user_id = session['user_id']
    conn = get_db_connection()
    
    # 检查文件夹是否属于当前用户
    folder = conn.execute(
        'SELECT * FROM folders WHERE id = ? AND user_id = ?', 
        (folder_id, user_id)
    ).fetchone()
    
    if not folder:
        flash('文件夹不存在或无权访问', 'error')
        conn.close()
        return redirect(url_for('index'))
    
    # 获取文件夹中的所有图片
    images = conn.execute(
        'SELECT filename FROM images WHERE folder_id = ? AND user_id = ?', 
        (folder_id, user_id)
    ).fetchall()
    
    # 删除物理文件
    user_upload_dir = os.path.join(app.config['UPLOAD_FOLDER'], str(user_id))
    for image in images:
        file_path = os.path.join(user_upload_dir, image['filename'])
        if os.path.exists(file_path):
            os.remove(file_path)
    
    # 删除数据库记录
    conn.execute('DELETE FROM images WHERE folder_id = ? AND user_id = ?', (folder_id, user_id))
    conn.execute('DELETE FROM folders WHERE id = ? AND user_id = ?', (folder_id, user_id))
    conn.commit()
    conn.close()
    
    flash('文件夹删除成功', 'success')
    return redirect(url_for('index'))

@app.route('/rename_image/<int:image_id>', methods=['POST'])
@login_required
def rename_image(image_id):
    """重命名图片"""
    new_name = request.form.get('new_name', '').strip()
    user_id = session['user_id']
    
    if not new_name:
        flash('图片名称不能为空', 'error')
        return redirect(request.referrer)
    
    conn = get_db_connection()
    result = conn.execute(
        'UPDATE images SET original_filename = ? WHERE id = ? AND user_id = ?', 
        (new_name, image_id, user_id)
    )
    
    if result.rowcount == 0:
        flash('图片不存在或无权访问', 'error')
    else:
        conn.commit()
        flash('图片重命名成功', 'success')
    
    conn.close()
    return redirect(request.referrer)

@app.route('/move_image/<int:image_id>', methods=['POST'])
@login_required
def move_image(image_id):
    """移动图片到其他文件夹"""
    new_folder_id = request.form.get('new_folder_id')
    user_id = session['user_id']
    
    if not new_folder_id:
        flash('请选择目标文件夹', 'error')
        return redirect(request.referrer)
    
    conn = get_db_connection()
    
    # 验证目标文件夹属于当前用户
    folder = conn.execute(
        'SELECT id FROM folders WHERE id = ? AND user_id = ?', 
        (new_folder_id, user_id)
    ).fetchone()
    
    if not folder:
        flash('目标文件夹无效', 'error')
        conn.close()
        return redirect(request.referrer)
    
    result = conn.execute(
        'UPDATE images SET folder_id = ? WHERE id = ? AND user_id = ?', 
        (new_folder_id, image_id, user_id)
    )
    
    if result.rowcount == 0:
        flash('图片不存在或无权访问', 'error')
    else:
        conn.commit()
        flash('图片移动成功', 'success')
    
    conn.close()
    return redirect(request.referrer)

@app.route('/delete_image/<int:image_id>', methods=['POST'])
@login_required
def delete_image(image_id):
    """删除图片"""
    user_id = session['user_id']
    conn = get_db_connection()
    
    # 获取图片信息
    image = conn.execute(
        'SELECT filename FROM images WHERE id = ? AND user_id = ?', 
        (image_id, user_id)
    ).fetchone()
    
    if image:
        # 删除物理文件
        user_upload_dir = os.path.join(app.config['UPLOAD_FOLDER'], str(user_id))
        file_path = os.path.join(user_upload_dir, image['filename'])
        if os.path.exists(file_path):
            os.remove(file_path)
        
        # 删除数据库记录
        conn.execute('DELETE FROM images WHERE id = ? AND user_id = ?', (image_id, user_id))
        conn.commit()
        flash('图片删除成功', 'success')
    else:
        flash('图片不存在或无权访问', 'error')
    
    conn.close()
    return redirect(request.referrer)

@app.route('/search')
@login_required
def search():
    """搜索功能"""
    query = request.args.get('q', '').strip()
    folder_id = request.args.get('folder_id', '')
    user_id = session['user_id']
    
    if not query:
        conn = get_db_connection()
        all_folders = conn.execute(
            'SELECT * FROM folders WHERE user_id = ? ORDER BY name', 
            (user_id,)
        ).fetchall()
        conn.close()
        return render_template('search.html', images=[], folders=all_folders, query='')
    
    conn = get_db_connection()
    
    # 获取当前用户的所有文件夹（用于搜索过滤）
    all_folders = conn.execute(
        'SELECT * FROM folders WHERE user_id = ? ORDER BY name', 
        (user_id,)
    ).fetchall()
    
    if folder_id:
        # 在特定文件夹中搜索
        images = conn.execute('''
            SELECT i.*, f.name as folder_name 
            FROM images i 
            JOIN folders f ON i.folder_id = f.id 
            WHERE i.folder_id = ? AND i.user_id = ? AND (
                i.original_filename LIKE ? OR 
                f.description LIKE ?
            )
            ORDER BY i.uploaded_at DESC
        ''', (folder_id, user_id, f'%{query}%', f'%{query}%')).fetchall()
    else:
        # 全局搜索（仅当前用户的数据）
        images = conn.execute('''
            SELECT i.*, f.name as folder_name 
            FROM images i 
            JOIN folders f ON i.folder_id = f.id 
            WHERE i.user_id = ? AND (
                i.original_filename LIKE ? OR f.description LIKE ?
            )
            ORDER BY i.uploaded_at DESC
        ''', (user_id, f'%{query}%', f'%{query}%')).fetchall()
    
    conn.close()
    return render_template('search.html', images=images, folders=all_folders, 
                         query=query, selected_folder=folder_id)

@app.route('/uploads/<int:user_id>/<filename>')
@login_required
def uploaded_file(user_id, filename):
    """提供上传的图片文件（需要验证用户权限）"""
    if session['user_id'] != user_id:
        flash('无权访问此文件', 'error')
        return redirect(url_for('index'))
    
    user_upload_dir = os.path.join(app.config['UPLOAD_FOLDER'], str(user_id))
    return send_from_directory(user_upload_dir, filename)

if __name__ == '__main__':
    # 确保上传目录存在
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    
    # 初始化数据库
    init_db()
    
    app.run(debug=True) 