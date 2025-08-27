from pki_infrastructure import VA
import os
import json
import hashlib
import psutil  # Установите: pip install psutil
from datetime import datetime, timedelta
from flask import Flask, render_template, redirect, url_for, flash, request, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from flask_socketio import SocketIO, emit, join_room, leave_room
from config import Config
from werkzeug.security import generate_password_hash, check_password_hash

# Импорты для криптографии
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography import x509
from cryptography.x509.oid import NameOID

app = Flask(__name__)
app.config.from_object(Config)

db = SQLAlchemy(app)
socketio = SocketIO(app)
login_manager = LoginManager(app)
# Указываем конечную точку для входа, чтобы шаблоны могли обращаться через url_for("login")
login_manager.login_view = 'login'

# ===========================
# 1. МОДЕЛИ
# ===========================

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), nullable=False)
    price = db.Column(db.Float, nullable=False)
    description = db.Column(db.Text, nullable=True)
    image_filename = db.Column(db.String(128), nullable=True)

class Review(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    rating = db.Column(db.Integer, nullable=False)
    comment = db.Column(db.Text, nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    product = db.relationship('Product', backref=db.backref('reviews', lazy=True))
    user = db.relationship('User', backref=db.backref('reviews', lazy=True))

class Order(db.Model):
    __tablename__ = 'order'  # Если нужно явно
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    total = db.Column(db.Float, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    signature = db.Column(db.String(512), nullable=True)
    
    user = db.relationship('User', backref=db.backref('orders', lazy=True))
    
    # Ключевая часть — каскад в ORM
    items = db.relationship(
        'OrderItem',
        backref='order',
        cascade='all, delete-orphan',  # Позволяет удалять связанные OrderItem
        passive_deletes=True          # Учитывает ondelete='CASCADE' на уровне БД
    )


class OrderItem(db.Model):
    __tablename__ = 'order_item'
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(
        db.Integer,
        db.ForeignKey('order.id', ondelete='CASCADE'),
        nullable=False
    )
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    price = db.Column(db.Float, nullable=False)
    
    # Добавляем отношение к модели Product
    product = db.relationship('Product', backref=db.backref('order_items', lazy=True))



class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(256), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    image_filename = db.Column(db.String(128), nullable=True)

class PostLike(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    post = db.relationship('Post', backref=db.backref('likes', lazy=True))
    user = db.relationship('User', backref=db.backref('post_likes', lazy=True))

class PostComment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    post = db.relationship('Post', backref=db.backref('comments', lazy=True))
    user = db.relationship('User', backref=db.backref('post_comments', lazy=True))

class IssuedCertificate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    common_name = db.Column(db.String(256), nullable=False)
    certificate = db.Column(db.Text, nullable=False)
    issued_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    revoked = db.Column(db.Boolean, default=False)
    user = db.relationship('User', backref=db.backref('certificates', lazy=True))

class AuditLog(db.Model):
    __tablename__ = 'audit_log'
    __table_args__ = {'extend_existing': True}
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    operation = db.Column(db.String(64), nullable=False)
    table_name = db.Column(db.String(64), nullable=False)
    record_id = db.Column(db.Integer, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    data_before = db.Column(db.Text, nullable=True)
    data_after = db.Column(db.Text, nullable=True)
    signature = db.Column(db.String(512), nullable=False)
    user = db.relationship('User')

# ===========================
# 2. Загрузка пользователя
# ===========================
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ===========================
# 3. Вспомогательные функции
# ===========================
def init_cart():
    if "cart" not in session:
        session["cart"] = {}

def file_sha256(filepath):
    """Вычисляет SHA-256 хэш указанного файла."""
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

# ===========================
# 4. PKI: Функции цифровой подписи
# ===========================
DIGITAL_PRIVATE_KEY_FILE = "digital_private.pem"
DIGITAL_PUBLIC_KEY_FILE = "digital_public.pem"

def load_or_generate_digital_keys(private_file, public_file):
    if not os.path.exists(private_file) or not os.path.exists(public_file):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        with open(private_file, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
        public_key = private_key.public_key()
        with open(public_file, "wb") as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
    else:
        with open(private_file, "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
        with open(public_file, "rb") as f:
            public_key = serialization.load_pem_public_key(f.read())
    return private_key, public_key

digital_private_key, digital_public_key = load_or_generate_digital_keys(DIGITAL_PRIVATE_KEY_FILE, DIGITAL_PUBLIC_KEY_FILE)

def sign_data(data: bytes) -> bytes:
    """Подписывает данные с использованием RSA-PSS и SHA-256."""
    signature = digital_private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def verify_signature(data: bytes, signature: bytes) -> bool:
    try:
        digital_public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

# ===========================
# 5. PKI: Собственный ЦС (эмуляция выдачи сертификатов)
# ===========================
CA_PRIVATE_KEY_FILE = "ca_private.pem"
CA_CERT_FILE = "ca_cert.pem"

def load_or_generate_ca():
    if not os.path.exists(CA_PRIVATE_KEY_FILE) or not os.path.exists(CA_CERT_FILE):
        ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"RU"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My CA"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"My CA"),
        ])
        ca_cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(
            ca_key.public_key()
        ).serial_number(x509.random_serial_number()).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=3650)
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True,
        ).sign(ca_key, hashes.SHA256())
        with open(CA_PRIVATE_KEY_FILE, "wb") as f:
            f.write(ca_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
        with open(CA_CERT_FILE, "wb") as f:
            f.write(ca_cert.public_bytes(serialization.Encoding.PEM))
    else:
        with open(CA_PRIVATE_KEY_FILE, "rb") as f:
            ca_key = serialization.load_pem_private_key(f.read(), password=None)
        with open(CA_CERT_FILE, "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read())
    return ca_key, ca_cert

ca_private_key, ca_cert = load_or_generate_ca()

@app.route("/issue_certificate", methods=["POST"])
@login_required
def issue_certificate():
    if not current_user.is_admin:
        return {"error": "Доступ запрещён"}, 403
    common_name = request.json.get("common_name")
    if not common_name:
        return {"error": "common_name обязателен"}, 400
    user_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"RU"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    cert = x509.CertificateBuilder().subject_name(subject).issuer_name(ca_cert.subject).public_key(
        user_key.public_key()
    ).serial_number(x509.random_serial_number()).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=365)
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True,
    ).sign(ca_private_key, hashes.SHA256())
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
    key_pem = user_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode("utf-8")
    issued_cert = IssuedCertificate(
        user_id=current_user.id,
        common_name=common_name,
        certificate=cert_pem,
        issued_at=datetime.utcnow(),
        expires_at=datetime.utcnow() + timedelta(days=365),
        revoked=False
    )
    db.session.add(issued_cert)
    db.session.commit()
    return {"certificate": cert_pem, "private_key": key_pem}, 200


# ===========================
# 7. Контроль целостности данных (аудит)
# ===========================
def log_audit(operation, table_name, record_id, data_before, data_after):
    timestamp = datetime.utcnow()
    audit_str = f"{operation}:{table_name}:{record_id}:{timestamp.isoformat()}:{data_before}:{data_after}"
    signature = sign_data(audit_str.encode("utf-8")).hex()
    audit = AuditLog(
        user_id=current_user.id,
        operation=operation,
        table_name=table_name,
        record_id=record_id,
        timestamp=timestamp,
        data_before=data_before,
        data_after=data_after,
        signature=signature
    )
    db.session.add(audit)
    db.session.commit()

def generate_order_signature(order):
    data_str = f"{order.id}:{order.user_id}:{order.total}:{order.timestamp.isoformat()}"
    return sign_data(data_str.encode("utf-8")).hex()

def verify_order_signature(order):
    data_str = f"{order.id}:{order.user_id}:{order.total}:{order.timestamp.isoformat()}"
    try:
        signature_bytes = bytes.fromhex(order.signature)
    except Exception:
        return False
    return verify_signature(data_str.encode("utf-8"), signature_bytes)

@app.route("/verify_order/<int:order_id>")
@login_required
def verify_order(order_id):
    order = Order.query.get_or_404(order_id)
    status = "Подпись заказа корректна. Данные не изменены." if order.signature and verify_order_signature(order) else "Подпись заказа некорректна или отсутствует!"
    return jsonify({"order_id": order.id, "status": status})

@app.route("/checkout", methods=["POST"])
@login_required
def checkout():
    init_cart()
    cart_data = session.get("cart", {})
    if not cart_data:
        flash("Ваша корзина пуста.", "warning")
        return redirect(url_for("menu"))

    total = 0.0
    order = Order(user_id=current_user.id, total=0)
    db.session.add(order)
    db.session.flush()  # Получаем order.id

    for prod_id, quantity in cart_data.items():
        product = Product.query.get(int(prod_id))
        if product:
            subtotal = product.price * quantity
            total += subtotal
            order_item = OrderItem(
                order_id=order.id,  # ✅ Теперь точно не None
                product_id=product.id,
                quantity=quantity,
                price=product.price
            )
            db.session.add(order_item)

    order.total = total
    order.signature = generate_order_signature(order)
    db.session.commit()

    log_audit("create_order", "order", order.id, "", json.dumps({
        "total": order.total,
        "timestamp": order.timestamp.isoformat()
    }))

    session["cart"] = {}
    flash("Заказ оформлен успешно!", "success")
    return redirect(url_for("account"))


# ===========================
# 8. Маршруты магазина и блога
# ===========================
@app.route("/")
def home():
    posts = Post.query.order_by(Post.timestamp.desc()).limit(3).all()
    return render_template("index.html", posts=posts)

@app.route("/menu")
def menu():
    search_query = request.args.get('q', '')
    if search_query:
        products = Product.query.filter(Product.name.ilike(f"%{search_query}%")).all()
    else:
        products = Product.query.all()
    return render_template("menu.html", products=products, search_query=search_query)

@app.route("/product/<int:product_id>")
def product_detail(product_id):
    product = Product.query.get_or_404(product_id)
    reviews = Review.query.filter_by(product_id=product.id).order_by(Review.timestamp.desc()).all()
    return render_template("product_detail.html", product=product, reviews=reviews)

@app.route("/product/<int:product_id>/review", methods=["POST"])
@login_required
def add_review(product_id):
    try:
        rating = int(request.form.get("rating"))
    except (ValueError, TypeError):
        flash("Некорректная оценка.", "danger")
        return redirect(url_for("product_detail", product_id=product_id))
    comment = request.form.get("comment")
    review = Review(product_id=product_id, user_id=current_user.id, rating=rating, comment=comment)
    db.session.add(review)
    db.session.commit()
    log_audit("add_review", "review", review.id, "", json.dumps({"rating": rating, "comment": comment}))
    flash("Спасибо за отзыв!", "success")
    return redirect(url_for("product_detail", product_id=product_id))

@app.route("/add_to_cart/<int:product_id>")
def add_to_cart(product_id):
    init_cart()
    cart = session["cart"]
    cart[str(product_id)] = cart.get(str(product_id), 0) + 1
    session["cart"] = cart
    flash("Товар добавлен в корзину.", "success")
    return redirect(url_for("menu"))

@app.route("/cart")
def cart():
    init_cart()
    cart_data = session.get("cart", {})
    products = []
    total = 0.0
    for prod_id, quantity in cart_data.items():
        product = Product.query.get(int(prod_id))
        if product:
            products.append({
                "id": product.id,
                "name": product.name,
                "price": product.price,
                "quantity": quantity,
                "subtotal": product.price * quantity,
                "image_filename": product.image_filename
            })
            total += product.price * quantity
    return render_template("cart.html", products=products, total=total)

@app.route("/remove_from_cart/<int:product_id>")
def remove_from_cart(product_id):
    init_cart()
    cart = session["cart"]
    prod_id = str(product_id)
    if prod_id in cart:
        del cart[prod_id]
    session["cart"] = cart
    flash("Товар удалён из корзины.", "info")
    return redirect(url_for("cart"))

@app.route("/account")
@login_required
def account():
    orders = Order.query.filter_by(user_id=current_user.id).order_by(Order.timestamp.desc()).all()
    return render_template("account.html", orders=orders)

@app.route("/blog")
def blog():
    posts = Post.query.order_by(Post.timestamp.desc()).all()
    return render_template("blog.html", posts=posts)

@app.route("/blog/<int:post_id>")
def blog_post(post_id):
    post = Post.query.get_or_404(post_id)
    like_count = len(post.likes)
    user_liked = False
    if current_user.is_authenticated:
        user_liked = any(like.user_id == current_user.id for like in post.likes)
    return render_template("blog_post.html", post=post, like_count=like_count, user_liked=user_liked)

@app.route("/blog/<int:post_id>/like", methods=["POST"])
@login_required
def like_post(post_id):
    post = Post.query.get_or_404(post_id)
    existing_like = PostLike.query.filter_by(post_id=post.id, user_id=current_user.id).first()
    if existing_like:
        db.session.delete(existing_like)
        db.session.commit()
        log_audit("remove_like", "post_like", existing_like.id, json.dumps({"user_id": current_user.id}), "")
        flash("Лайк убран.", "info")
    else:
        new_like = PostLike(post_id=post.id, user_id=current_user.id)
        db.session.add(new_like)
        db.session.commit()
        log_audit("add_like", "post_like", new_like.id, "", json.dumps({"user_id": current_user.id}))
        flash("Пост понравился!", "success")
    return redirect(url_for("blog_post", post_id=post.id))

@app.route("/blog/<int:post_id>/comment", methods=["POST"])
@login_required
def add_blog_comment(post_id):
    post = Post.query.get_or_404(post_id)
    content = request.form.get("content")
    if not content:
        flash("Комментарий не может быть пустым!", "danger")
        return redirect(url_for("blog_post", post_id=post.id))
    new_comment = PostComment(post_id=post.id, user_id=current_user.id, content=content)
    db.session.add(new_comment)
    db.session.commit()
    log_audit("add_comment", "post_comment", new_comment.id, "", json.dumps({"content": content}))
    flash("Комментарий добавлен!", "success")
    return redirect(url_for("blog_post", post_id=post.id))

# ===========================
# АУТЕНТИФИКАЦИЯ
# ===========================
# Чтобы в шаблонах можно было вызывать url_for("login"),
# указываем endpoint="login" в декораторе.
#@app.route("/login", methods=["GET", "POST"], endpoint="login")
#def login_view():
#    if request.method == "POST":
#        username = request.form.get("username")
#        password = request.form.get("password")
#        user = User.query.filter_by(username=username).first()
#        if user and check_password_hash(user.password, password):
#            login_user(user)
#            flash("Вы успешно вошли в систему.", "success")
#            if user.is_admin:
#                return redirect(url_for("admin_dashboard"))
#            return redirect(url_for("home"))
#        else:
#            flash("Неверное имя пользователя или пароль.", "danger")
#    return render_template("login.html")

@app.route("/login", methods=["GET", "POST"], endpoint="login")
def login_view():
    if request.method == "POST":
        username = request.form.get("username").strip()
        password = request.form.get("password").strip()
        
        # Находим пользователя в базе данных
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            # Формируем путь к файлу сертификата (например, certificates/{username}_cert.pem)
            cert_path = os.path.join("certificates", f"{username}_cert.pem")
            if not os.path.exists(cert_path):
                flash("Сертификат для пользователя не найден. Обратитесь к администратору.", "danger")
                return redirect(url_for("login"))
            with open(cert_path, "r", encoding="utf-8") as f:
                cert_pem = f.read()
            
            # Создаем объект VA (или получаем его, если он уже создан)
            va = VA()
            if va.is_revoked(cert_pem):
                flash("Ваш сертификат отозван. Вход отклонен.", "danger")
                return redirect(url_for("login"))
            
            # Если все проверки пройдены, производим вход
            login_user(user)
            flash("Вы успешно вошли в систему.", "success")
            return redirect(url_for("home"))
        else:
            flash("Неверное имя пользователя или пароль.", "danger")
    return render_template("login.html")



@app.route("/register", methods=["GET", "POST"], endpoint="register")
def register_view():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        if User.query.filter_by(username=username).first():
            flash("Пользователь с таким именем уже существует.", "warning")
        else:
            new_user = User(username=username, password=generate_password_hash(password))
            db.session.add(new_user)
            db.session.commit()
            flash("Регистрация прошла успешно. Теперь вы можете войти.", "success")
            return redirect(url_for("login"))
    return render_template("register.html")

@app.route("/logout", methods=["GET"], endpoint="logout")
@login_required
def logout_view():
    logout_user()
    flash("Вы вышли из системы.", "info")
    return redirect(url_for("home"))

# ===========================
# АДМИН-МАРШРУТЫ
# ===========================
from functools import wraps
def admin_required(func):
    @wraps(func)
    def decorated_view(*args, **kwargs):
        if not current_user.is_admin:
            flash("Доступ запрещён.", "danger")
            return redirect(url_for("home"))
        return func(*args, **kwargs)
    return decorated_view

REFERENCE_INTEGRITY_FILE = "integrity_reference.json"

def load_reference_hashes():
    """
    Загружает эталонные хэши из файла integrity_reference.json.
    Если файл не найден, возвращает пустой словарь.
    """
    if os.path.exists(REFERENCE_INTEGRITY_FILE):
        with open(REFERENCE_INTEGRITY_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}


@app.route("/admin/integrity")
@login_required
@admin_required
def admin_integrity():
    results = {}
    ref_hashes = load_reference_hashes()  # Функция, которая загружает эталонные хэши из файла
    base_dir = os.path.dirname(__file__)
    files_to_check = []

    # Собираем файлы .py в корневой директории
    for file in os.listdir(base_dir):
        if file.endswith(".py"):
            files_to_check.append(file)
            
    # Собираем файлы .html из директории шаблонов
    templates_dir = os.path.join(base_dir, "templates")
    if os.path.isdir(templates_dir):
        for file in os.listdir(templates_dir):
            if file.endswith(".html"):
                files_to_check.append(os.path.join("templates", file))

    # Для каждого файла вычисляем текущий хэш и сравниваем с эталоном
    for filename in files_to_check:
        filepath = os.path.join(base_dir, filename)
        if os.path.exists(filepath):
            current_hash = file_sha256(filepath)
            ref_hash = ref_hashes.get(filename, None)
            status = "OK" if ref_hash and current_hash == ref_hash else "Изменён"
            results[filename] = {
                "current_hash": current_hash,
                "reference_hash": ref_hash,
                "status": status
            }
        else:
            results[filename] = {"status": "Файл не найден"}

    return render_template("admin_integrity.html", results=results)


@app.route("/admin/orders")
@login_required
@admin_required
def admin_orders():
    orders = Order.query.order_by(Order.timestamp.desc()).all()
    results = []
    for order in orders:
        # Если подпись существует и проходит верификацию, заказ считается корректным
        is_valid = order.signature and verify_order_signature(order)
        results.append({
            "order": order,
            "valid": is_valid
        })
    return render_template("admin_orders.html", orders=results)

@app.route("/admin/orders/delete/<int:order_id>", methods=["POST"])
@login_required
@admin_required
def delete_order(order_id):
    order = Order.query.get_or_404(order_id)
    db.session.delete(order)
    db.session.commit()
    flash("Заказ удалён.", "info")
    return redirect(url_for("admin_orders"))


@app.route("/admin")
@login_required
@admin_required
def admin_dashboard():
    products = Product.query.all()
    users = User.query.all()
    posts = Post.query.order_by(Post.timestamp.desc()).all()
    return render_template("admin_dashboard.html", products=products, users=users, posts=posts)

@app.route("/admin/product/add", methods=["GET", "POST"])
@login_required
@admin_required
def add_product_admin():
    if request.method == "POST":
        name = request.form.get("name")
        price = float(request.form.get("price"))
        description = request.form.get("description")
        file = request.files.get("image")
        filename = None
        if file:
            filename = file.filename
            file.save(os.path.join("static", "images", filename))
        product = Product(name=name, price=price, description=description, image_filename=filename)
        db.session.add(product)
        db.session.commit()
        flash("Продукт успешно добавлен.", "success")
        return redirect(url_for("admin_dashboard"))
    return render_template("add_product_admin.html")

@app.route("/admin/product/edit/<int:product_id>", methods=["GET", "POST"])
@login_required
@admin_required
def edit_product(product_id):
    product = Product.query.get_or_404(product_id)
    if request.method == "POST":
        product.name = request.form.get("name")
        product.price = float(request.form.get("price"))
        product.description = request.form.get("description")
        file = request.files.get("image")
        if file:
            filename = file.filename
            file.save(os.path.join("static", "images", filename))
            product.image_filename = filename
        db.session.commit()
        flash("Продукт обновлён.", "success")
        return redirect(url_for("admin_dashboard"))
    return render_template("edit_product.html", product=product)

@app.route("/admin/product/delete/<int:product_id>", methods=["POST"])
@login_required
@admin_required
def delete_product(product_id):
    product = Product.query.get_or_404(product_id)
    db.session.delete(product)
    db.session.commit()
    flash("Продукт удалён.", "success")
    return redirect(url_for("admin_dashboard"))

@app.route("/admin/user/delete/<int:user_id>", methods=["POST"])
@login_required
@admin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash("Нельзя удалить самого себя.", "danger")
        return redirect(url_for("admin_dashboard"))
    db.session.delete(user)
    db.session.commit()
    flash("Пользователь удалён.", "success")
    return redirect(url_for("admin_dashboard"))

@app.route("/admin/blog/add", methods=["GET", "POST"])
@login_required
@admin_required
def add_blog_post_admin():
    if request.method == "POST":
        title = request.form.get("title")
        content = request.form.get("content")
        file = request.files.get("image")
        filename = None
        if file:
            filename = file.filename
            file.save(os.path.join("static", "images", filename))
        new_post = Post(title=title, content=content, image_filename=filename)
        db.session.add(new_post)
        db.session.commit()
        flash("Новая статья блога успешно добавлена!", "success")
        return redirect(url_for("blog"))
    return render_template("add_blog_post_admin.html")

@app.route("/admin/blog/edit/<int:post_id>", methods=["GET", "POST"])
@login_required
@admin_required
def edit_blog_post_admin(post_id):
    post = Post.query.get_or_404(post_id)
    if request.method == "POST":
        post.title = request.form.get("title")
        post.content = request.form.get("content")
        file = request.files.get("image")
        if file:
            filename = file.filename
            file.save(os.path.join("static", "images", filename))
            post.image_filename = filename
        db.session.commit()
        flash("Статья обновлена!", "success")
        return redirect(url_for("blog_post", post_id=post.id))
    return render_template("edit_blog_post_admin.html", post=post)

@app.route("/admin/blog/delete/<int:post_id>", methods=["POST"])
@login_required
@admin_required
def delete_blog_post_admin(post_id):
    post = Post.query.get_or_404(post_id)
    db.session.delete(post)
    db.session.commit()
    flash("Статья удалена.", "info")
    return redirect(url_for("blog"))

# ===========================
# Запуск приложения через SocketIO
# ===========================
if __name__ == '__main__':
    # Для создания таблиц выполните:
    # >>> from app import app, db
    # >>> with app.app_context():
    # ...     db.create_all()
    socketio.run(app, debug=True)
