import os
import tkinter as tk
from tkinter import ttk, messagebox
import hashlib
from datetime import datetime, timedelta

# SQLAlchemy
from sqlalchemy import create_engine, Column, Integer, String, Boolean, Text, DateTime, Float, ForeignKey
from sqlalchemy.orm import sessionmaker, declarative_base, relationship

from werkzeug.security import generate_password_hash
from cryptography import x509
from cryptography.x509 import load_pem_x509_certificate
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import cryptography.exceptions

# -------------------- БАЗА ДАННЫХ --------------------
DATABASE_URL = "postgresql://postgres:3752@localhost/coffee_shop"
Base = declarative_base()
engine = create_engine(DATABASE_URL)
Session = sessionmaker(bind=engine)
session = Session()

# Модель User
class User(Base):
    __tablename__ = "user"
    id = Column(Integer, primary_key=True)
    username = Column(String(64), unique=True, nullable=False)
    password = Column(String(256), nullable=False)
    is_admin = Column(Boolean, default=False)

# Модель отозванных сертификатов
class RevokedCertificate(Base):
    __tablename__ = "revoked_certificate"
    id = Column(Integer, primary_key=True)
    serial_number = Column(String(128), nullable=False, unique=True)
    revoked_at = Column(DateTime, default=datetime.utcnow)
    reason = Column(String(256), nullable=True)

# Прочие модели (Product, Order, OrderItem) при необходимости
class Product(Base):
    __tablename__ = "product"
    id = Column(Integer, primary_key=True)
    name = Column(String(128), nullable=False)
    price = Column(Float, nullable=False)
    description = Column(Text, nullable=True)
    image_filename = Column(String(128), nullable=True)

class Order(Base):
    __tablename__ = 'order'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('user.id'), nullable=False)
    total = Column(Float, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)
    signature = Column(String(512), nullable=True)

    user = relationship('User', backref='orders')
    items = relationship('OrderItem', backref='order', cascade='all, delete-orphan', passive_deletes=True)

class OrderItem(Base):
    __tablename__ = 'order_item'
    id = Column(Integer, primary_key=True)
    order_id = Column(Integer, ForeignKey('order.id', ondelete='CASCADE'), nullable=False)
    product_id = Column(Integer, ForeignKey('product.id'), nullable=False)
    quantity = Column(Integer, nullable=False)
    price = Column(Float, nullable=False)

    product = relationship('Product', backref='order_items')

Base.metadata.create_all(engine)


# -------------------- Верификационные функции --------------------
def verify_subca_vs_root(root_cert_pem: str, subca_cert_pem: str) -> bool:
    """
    Проверяет, что subca_cert действительно подписан root_cert.
    Если подпись неверна — бросаем исключение (InvalidSignature).
    """
    root_cert = load_pem_x509_certificate(root_cert_pem.encode("utf-8"))
    subca_cert = load_pem_x509_certificate(subca_cert_pem.encode("utf-8"))

    subca_tbs = subca_cert.tbs_certificate_bytes
    subca_sig = subca_cert.signature
    subca_sig_alg = subca_cert.signature_hash_algorithm

    root_pubkey = root_cert.public_key()
    root_pubkey.verify(
        subca_sig,
        subca_tbs,
        padding.PKCS1v15(),
        subca_sig_alg
    )
    return True

def verify_user_vs_subca(subca_cert_pem: str, user_cert_pem: str) -> bool:
    """
    Проверяет, что user_cert действительно подписан subca_cert.
    Если подпись неверна — бросаем исключение InvalidSignature.
    """
    subca_cert = load_pem_x509_certificate(subca_cert_pem.encode("utf-8"))
    user_cert = load_pem_x509_certificate(user_cert_pem.encode("utf-8"))

    user_tbs = user_cert.tbs_certificate_bytes
    user_sig = user_cert.signature
    user_sig_alg = user_cert.signature_hash_algorithm

    subca_pubkey = subca_cert.public_key()
    subca_pubkey.verify(
        user_sig,
        user_tbs,
        padding.PKCS1v15(),
        user_sig_alg
    )
    return True


# -------------------- CA (Корневой УЦ) --------------------
class CA:
    def __init__(self, ca_key_file="rootCA_key.pem", ca_cert_file="rootCA_cert.pem"):
        self.ca_key_file = ca_key_file
        self.ca_cert_file = ca_cert_file
        self._load_or_create_ca()

    def _load_or_create_ca(self):
        if not os.path.exists(self.ca_key_file) or not os.path.exists(self.ca_cert_file):
            ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            subject = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, u"RU"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Root CA"),
                x509.NameAttribute(NameOID.COMMON_NAME, u"My Root CA"),
            ])
            ca_cert = x509.CertificateBuilder()\
                .subject_name(subject)\
                .issuer_name(subject)\
                .public_key(ca_key.public_key())\
                .serial_number(x509.random_serial_number())\
                .not_valid_before(datetime.utcnow())\
                .not_valid_after(datetime.utcnow() + timedelta(days=3650))\
                .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)\
                .sign(ca_key, hashes.SHA256())

            with open(self.ca_key_file, "wb") as f:
                f.write(ca_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            with open(self.ca_cert_file, "wb") as f:
                f.write(ca_cert.public_bytes(serialization.Encoding.PEM))

        with open(self.ca_key_file, "rb") as f:
            self.ca_key = serialization.load_pem_private_key(f.read(), password=None)
        with open(self.ca_cert_file, "rb") as f:
            self.ca_cert = x509.load_pem_x509_certificate(f.read())

    def sign_certificate(self, subject_name: x509.Name, public_key, days=365):
        cert = x509.CertificateBuilder()\
            .subject_name(subject_name)\
            .issuer_name(self.ca_cert.subject)\
            .public_key(public_key)\
            .serial_number(x509.random_serial_number())\
            .not_valid_before(datetime.utcnow())\
            .not_valid_after(datetime.utcnow() + timedelta(days=days))\
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)\
            .sign(self.ca_key, hashes.SHA256())
        return cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")

    def create_subordinate_ca(self, sub_ca_cn, key_size=2048, validity_days=365):
        sub_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"RU"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Subordinate CA"),
            x509.NameAttribute(NameOID.COMMON_NAME, sub_ca_cn),
        ])
        sub_cert = x509.CertificateBuilder()\
            .subject_name(subject)\
            .issuer_name(self.ca_cert.subject)\
            .public_key(sub_key.public_key())\
            .serial_number(x509.random_serial_number())\
            .not_valid_before(datetime.utcnow())\
            .not_valid_after(datetime.utcnow() + timedelta(days=validity_days))\
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)\
            .sign(self.ca_key, hashes.SHA256())

        sub_cert_pem = sub_cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
        sub_key_pem = sub_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ).decode("utf-8")

        return sub_cert_pem, sub_key_pem


# -------------------- VA (Центр Валидации/CRL) --------------------
class VA:
    def __init__(self):
        pass

    def is_revoked(self, cert_pem: str) -> bool:
        cert = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))
        serial_hex = hex(cert.serial_number)[2:].upper()
        rec = session.query(RevokedCertificate).filter_by(serial_number=serial_hex).first()
        return rec is not None

    def revoke_certificate(self, cert_pem: str, reason: str = ""):
        cert = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))
        serial_hex = hex(cert.serial_number)[2:].upper()
        existing = session.query(RevokedCertificate).filter_by(serial_number=serial_hex).first()
        if not existing:
            rec = RevokedCertificate(
                serial_number=serial_hex,
                revoked_at=datetime.utcnow(),
                reason=reason
            )
            session.add(rec)
            session.commit()

    def get_crl(self):
        revoked = session.query(RevokedCertificate).all()
        if not revoked:
            return "CRL пустой."
        lines = []
        for r in revoked:
            lines.append(f"Serial: {r.serial_number}, Revoked at: {r.revoked_at}, Reason: {r.reason}")
        return "\n".join(lines)


# -------------------- Генерация user-сертификата --------------------
def generate_user_certificate(common_name, key_size=2048, validity_days=365, ca_obj=None):
    """
    ca_obj: либо объект CA, либо CA_Sub (оба имеют .sign_certificate()).
    Возвращает (cert_pem, private_key_pem, user_key).
    """
    user_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)

    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"RU"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My CoffeeShop"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    # Если не передали явно, используем корневой CA по умолчанию
    if ca_obj is None:
        ca_obj = CA()

    # Подписываем сертификат (user -> ca_obj)
    cert_pem = ca_obj.sign_certificate(subject, user_key.public_key(), days=validity_days)

    private_key_pem = user_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode("utf-8")

    return cert_pem, private_key_pem, user_key


# -------------------- CA_Sub (дочерний УЦ) --------------------
class CA_Sub:
    def __init__(self, cert_pem, key_pem):
        self.cert_pem = cert_pem
        self.key = serialization.load_pem_private_key(key_pem.encode("utf-8"), password=None)

    def sign_data(self, data: bytes) -> bytes:
        """
        Пример дополнительной функции для подписи произвольных данных.
        """
        signature = self.key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature

    def sign_certificate(self, subject_name: x509.Name, public_key, days=365):
        """
        Аналогия CA.sign_certificate, но используем свой cert_pem (SubCA) и свой ключ.
        """
        subca_cert = load_pem_x509_certificate(self.cert_pem.encode("utf-8"))

        builder = x509.CertificateBuilder()\
            .subject_name(subject_name)\
            .issuer_name(subca_cert.subject)\
            .public_key(public_key)\
            .serial_number(x509.random_serial_number())\
            .not_valid_before(datetime.utcnow())\
            .not_valid_after(datetime.utcnow() + timedelta(days=days))\
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)

        new_cert = builder.sign(
            private_key=self.key,
            algorithm=hashes.SHA256()
        )
        return new_cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")


# -------------------- Главное Приложение PKIApp --------------------
class PKIApp(tk.Tk):
    def __init__(self, ca: CA, va: VA):
        super().__init__()
        self.title("PKI Инфраструктура")
        self.geometry("850x650")

        self.ca = ca
        self.va = va

        # Словарь для SubCA: { "Подпись пользователей": (cert, key, name, CA_Sub) , ... }
        self.subcas = {}

        self.certs_folder = os.path.join(os.getcwd(), "certificates")
        if not os.path.exists(self.certs_folder):
            os.makedirs(self.certs_folder)

        self.subcas_folder = os.path.join(os.getcwd(), "subCAs")
        if not os.path.exists(self.subcas_folder):
            os.makedirs(self.subcas_folder)

        self.load_subcas_from_folder()
        self.create_notebook()

    def load_subcas_from_folder(self):
        """
        Ищем пары subCA_{}_cert.pem / subCA_{}_key.pem, формируем CA_Sub и кладём в self.subcas.
        """
        pem_files = [f for f in os.listdir(self.subcas_folder) if f.endswith(".pem")]
        temp_map = {}
        valid_types = {
            "Подпись_пользователей": "Подпись пользователей",
            "Целостность_ПО": "Целостность ПО",
            "Целостность_заказа": "Целостность заказа"
        }

        for filename in pem_files:
            if not filename.startswith("subCA_"):
                continue
            is_cert = filename.endswith("_cert.pem")
            is_key = filename.endswith("_key.pem")
            if not (is_cert or is_key):
                continue

            base_name = filename[len("subCA_"):]
            if is_cert:
                core_name = base_name[:-len("_cert.pem")]
            else:
                core_name = base_name[:-len("_key.pem")]

            parts = core_name.split("_")
            subca_type_key = None
            subca_cn_final = None

            for i in range(1, len(parts) + 1):
                candidate_type = "_".join(parts[:i])  # e.g. "Подпись_пользователей"
                if candidate_type in valid_types:
                    remainder = parts[i:]
                    subca_cn_final = "_".join(remainder)
                    subca_type_key = valid_types[candidate_type]
                    break

            if not subca_type_key:
                continue

            full_path = os.path.join(self.subcas_folder, filename)
            with open(full_path, "r", encoding="utf-8") as f:
                content = f.read()

            key_tuple = (subca_type_key, subca_cn_final)
            if key_tuple not in temp_map:
                temp_map[key_tuple] = {"cert": None, "key": None}

            if is_cert:
                temp_map[key_tuple]["cert"] = content
            else:
                temp_map[key_tuple]["key"] = content

        # Теперь создаём CA_Sub
        for (type_str, cn_str), pair in temp_map.items():
            cert_pem = pair["cert"]
            key_pem = pair["key"]
            if cert_pem and key_pem:
                full_subca_cn = f"{type_str} - {cn_str}"
                subca_obj = CA_Sub(cert_pem, key_pem)
                self.subcas[type_str] = (cert_pem, key_pem, full_subca_cn, subca_obj)

    def create_notebook(self):
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(expand=True, fill="both")

        # CA
        self.tab_ca = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_ca, text="CA")
        self.create_ca_tab()

        # RA
        self.tab_ra = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_ra, text="RA")
        self.create_ra_tab()

        # VA
        self.tab_va = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_va, text="VA")
        self.create_va_tab()

        # SubCA
        self.tab_subca = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_subca, text="SubCA")
        self.create_subca_tab()

    # -------------- CA TAB --------------
    def create_ca_tab(self):
        frame = self.tab_ca
        ttk.Label(frame, text="Корневой сертификат (CA):", font=("Arial", 12, "bold")).pack(pady=5)

        ca_cert_text = self.ca.ca_cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
        self.text_ca = tk.Text(frame, wrap="word", height=15)
        self.text_ca.insert(tk.END, ca_cert_text)
        self.text_ca.config(state="disabled")
        self.text_ca.pack(expand=True, fill="both", padx=10, pady=5)

        ttk.Button(frame, text="Перегенерировать CA", command=self.regenerate_ca).pack(pady=5)

    def regenerate_ca(self):
        if os.path.exists(self.ca.ca_key_file):
            os.remove(self.ca.ca_key_file)
        if os.path.exists(self.ca.ca_cert_file):
            os.remove(self.ca.ca_cert_file)
        self.ca._load_or_create_ca()

        ca_cert_text = self.ca.ca_cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
        self.text_ca.config(state="normal")
        self.text_ca.delete("1.0", tk.END)
        self.text_ca.insert(tk.END, ca_cert_text)
        self.text_ca.config(state="disabled")

        messagebox.showinfo("CA", "Корневой CA перегенерирован.")

    # -------------- RA (регистрация пользователей) --------------
    def create_ra_tab(self):
        frame = self.tab_ra
        ttk.Label(frame, text="Регистрация пользователя", font=("Arial", 12, "bold")).grid(row=0, column=0, columnspan=2, pady=5)

        ttk.Label(frame, text="Имя пользователя:").grid(row=1, column=0, sticky="w", pady=5, padx=5)
        self.entry_username = ttk.Entry(frame)
        self.entry_username.grid(row=1, column=1, pady=5, padx=5)

        ttk.Label(frame, text="Пароль:").grid(row=2, column=0, sticky="w", pady=5, padx=5)
        self.entry_password = ttk.Entry(frame, show="*")
        self.entry_password.grid(row=2, column=1, pady=5, padx=5)

        ttk.Label(frame, text="Common Name (CN):").grid(row=3, column=0, sticky="w", pady=5, padx=5)
        self.entry_cn = ttk.Entry(frame)
        self.entry_cn.grid(row=3, column=1, pady=5, padx=5)

        ttk.Label(frame, text="Размер ключа:").grid(row=4, column=0, sticky="w", pady=5, padx=5)
        self.combo_key_size = ttk.Combobox(frame, values=[2048, 3072, 4096], state="readonly")
        self.combo_key_size.current(0)
        self.combo_key_size.grid(row=4, column=1, pady=5, padx=5)

        self.var_is_admin = tk.BooleanVar()
        ttk.Checkbutton(frame, text="Администратор", variable=self.var_is_admin).grid(row=5, column=1, sticky="w", pady=5, padx=5)

        ttk.Label(frame, text="Выберите CA для регистрации:").grid(row=6, column=0, sticky="w", pady=5, padx=5)

        # Root CA либо SubCA (если есть)
        options = ["Root CA"]
        if "Подпись пользователей" in self.subcas:
            options.append(f"SubCA: {self.subcas['Подпись пользователей'][2]}")
        self.combo_reg_ca = ttk.Combobox(frame, values=options, state="readonly")
        self.combo_reg_ca.current(0)
        self.combo_reg_ca.grid(row=6, column=1, pady=5, padx=5)

        ttk.Button(frame, text="Зарегистрировать", command=self.register_user).grid(row=7, column=0, columnspan=2, pady=10)

        # Кнопка проверки сертификата отдельного пользователя
        ttk.Label(frame, text="Проверить сертификат пользователя:").grid(row=8, column=0, sticky="w", pady=5, padx=5)
        self.entry_verify_user = ttk.Entry(frame)
        self.entry_verify_user.grid(row=8, column=1, pady=5, padx=5)

        ttk.Button(frame, text="Проверить цепочку", command=self.do_verify_user_certificate).grid(row=9, column=0, columnspan=2, pady=5)

        # Кнопка "Проверить все сертификаты"
        ttk.Button(frame, text="Проверить все сертификаты", command=self.check_all_certificates).grid(row=10, column=0, columnspan=2, pady=10)

    def register_user(self):
        username = self.entry_username.get().strip()
        password = self.entry_password.get().strip()
        common_name = self.entry_cn.get().strip()

        try:
            key_size = int(self.combo_key_size.get())
        except ValueError:
            key_size = 2048

        is_admin = self.var_is_admin.get()

        if not username or not password or not common_name:
            messagebox.showerror("Ошибка", "Все поля должны быть заполнены!")
            return

        existing_user = session.query(User).filter_by(username=username).first()
        cert_filename = os.path.join(os.getcwd(), "certificates", f"{username}_cert.pem")
        key_filename = os.path.join(os.getcwd(), "certificates", f"{username}_key.pem")

        if existing_user:
            if os.path.exists(cert_filename):
                messagebox.showerror("Ошибка", f"Пользователь '{username}' уже существует, и сертификат уже создан.")
                return
            else:
                messagebox.showerror("Ошибка", f"Пользователь '{username}' уже есть в БД, но файл '{cert_filename}' не найден.")
                return

        if os.path.exists(cert_filename):
            messagebox.showerror("Ошибка", f"Файл {cert_filename} уже существует, но в БД пользователя '{username}' нет.")
            return

        hashed_pass = generate_password_hash(password)
        new_user = User(username=username, password=hashed_pass, is_admin=is_admin)
        session.add(new_user)
        session.commit()

        # Выбираем CA
        selected_ca = self.ca
        if self.combo_reg_ca.get() != "Root CA":
            # Тут subCA (напр. 'Подпись пользователей')
            selected_ca = self.subcas["Подпись пользователей"][3]  # Это CA_Sub

        cert_pem, key_pem, _ = generate_user_certificate(
            common_name,
            key_size=key_size,
            ca_obj=selected_ca
        )

        # Сохраняем cert & key
        with open(cert_filename, "w", encoding="utf-8") as f_cert:
            f_cert.write(cert_pem)
        with open(key_filename, "w", encoding="utf-8") as f_key:
            f_key.write(key_pem)

        messagebox.showinfo("Успех", f"Пользователь {username} создан!\nСертификат: {cert_filename}\nКлюч: {key_filename}")

    def do_verify_user_certificate(self):
        username = self.entry_verify_user.get().strip()
        if not username:
            messagebox.showerror("Ошибка", "Введите имя пользователя для проверки цепочки сертификата.")
            return
        self.verify_user_certificate(username)

    def verify_user_certificate(self, username: str):
        cert_filename = os.path.join(os.getcwd(), "certificates", f"{username}_cert.pem")
        if not os.path.exists(cert_filename):
            messagebox.showerror("Ошибка", f"Сертификат для пользователя '{username}' не найден: {cert_filename}")
            return

        with open(cert_filename, "r", encoding="utf-8") as f:
            user_cert_pem = f.read()

        user_db = session.query(User).filter_by(username=username).first()
        if not user_db:
            messagebox.showerror("Ошибка", f"Пользователь '{username}' не найден в БД.")
            return

        # Читаем Root
        with open(self.ca.ca_cert_file, "r", encoding="utf-8") as f:
            root_cert_pem = f.read()

        if user_db.is_admin:
            # Проверка (User -> Root)
            try:
                root_cert = load_pem_x509_certificate(root_cert_pem.encode("utf-8"))
                user_cert = load_pem_x509_certificate(user_cert_pem.encode("utf-8"))

                user_tbs = user_cert.tbs_certificate_bytes
                user_sig = user_cert.signature
                user_sig_alg = user_cert.signature_hash_algorithm
                root_pubkey = root_cert.public_key()
                root_pubkey.verify(user_sig, user_tbs, padding.PKCS1v15(), user_sig_alg)

                messagebox.showinfo("Проверка", f"Сертификат '{username}' подписан Root CA. Нет подмены.")
            except cryptography.exceptions.InvalidSignature:
                messagebox.showerror("Подмена!", f"Сертификат '{username}' не совпадает с Root CA.")
            except Exception as ex:
                messagebox.showerror("Ошибка", f"Ошибка проверки: {ex}")
        else:
            # Проверяем SubCA 'Подпись пользователей' => Root
            if "Подпись пользователей" not in self.subcas:
                messagebox.showerror("Ошибка", "SubCA 'Подпись пользователей' не найден!")
                return
            subca_cert_pem = self.subcas["Подпись пользователей"][0]

            # Сначала subCA -> Root
            try:
                verify_subca_vs_root(root_cert_pem, subca_cert_pem)
            except cryptography.exceptions.InvalidSignature:
                messagebox.showerror("Подмена!", "SubCA 'Подпись пользователей' не совпадает с Root CA!")
                return
            except Exception as ex:
                messagebox.showerror("Ошибка", f"Ошибка проверки SubCA vs Root: {ex}")
                return

            # Потом user -> subCA
            try:
                verify_user_vs_subca(subca_cert_pem, user_cert_pem)
                messagebox.showinfo("Проверка", f"Сертификат '{username}' корректен, SubCA тоже корректен.")
            except cryptography.exceptions.InvalidSignature:
                messagebox.showerror("Подмена!", f"Сертификат '{username}' не совпадает с SubCA 'Подпись пользователей'!")
            except Exception as ex:
                messagebox.showerror("Ошибка", f"Ошибка проверки User vs SubCA: {ex}")

    # -------------- Проверить все сертификаты --------------
    def check_all_certificates(self):
        bad_certs = []

        with open(self.ca.ca_cert_file, "r", encoding="utf-8") as f:
            root_cert_pem = f.read()

        # Проверяем subCA
        for subca_type, (cert_pem, key_pem, full_subca_cn, subca_obj) in self.subcas.items():
            try:
                verify_subca_vs_root(root_cert_pem, cert_pem)
            except cryptography.exceptions.InvalidSignature:
                bad_certs.append(f"SubCA '{full_subca_cn}' - подмена (не совпадает с Root CA).")
            except Exception as ex:
                bad_certs.append(f"SubCA '{full_subca_cn}' - ошибка: {ex}")

        # Проверяем user
        all_users = session.query(User).all()
        for user in all_users:
            username = user.username
            cfile = os.path.join(os.getcwd(), "certificates", f"{username}_cert.pem")
            if not os.path.exists(cfile):
                bad_certs.append(f"User '{username}': Файл {cfile} не найден.")
                continue

            with open(cfile, "r", encoding="utf-8") as f:
                user_cert_pem = f.read()

            if user.is_admin:
                try:
                    root_cert = load_pem_x509_certificate(root_cert_pem.encode("utf-8"))
                    user_cert = load_pem_x509_certificate(user_cert_pem.encode("utf-8"))
                    user_tbs = user_cert.tbs_certificate_bytes
                    user_sig = user_cert.signature
                    user_sig_alg = user_cert.signature_hash_algorithm
                    root_pub = root_cert.public_key()
                    root_pub.verify(user_sig, user_tbs, padding.PKCS1v15(), user_sig_alg)
                except cryptography.exceptions.InvalidSignature:
                    bad_certs.append(f"User '{username}': подмена (не совпадает с Root CA).")
                except Exception as ex:
                    bad_certs.append(f"User '{username}': ошибка верификации - {ex}")
            else:
                if "Подпись пользователей" not in self.subcas:
                    bad_certs.append(f"User '{username}': нет SubCA 'Подпись пользователей'!")
                    continue

                subca_cert_pem = self.subcas["Подпись пользователей"][0]
                try:
                    verify_subca_vs_root(root_cert_pem, subca_cert_pem)
                except cryptography.exceptions.InvalidSignature:
                    bad_certs.append(f"SubCA 'Подпись пользователей' подмена (не совпадает с Root CA).")
                    continue
                except Exception as ex:
                    bad_certs.append(f"SubCA 'Подпись пользователей': ошибка - {ex}")
                    continue

                try:
                    verify_user_vs_subca(subca_cert_pem, user_cert_pem)
                except cryptography.exceptions.InvalidSignature:
                    bad_certs.append(f"User '{username}': подмена (не совпадает с SubCA 'Подпись пользователей').")
                except Exception as ex:
                    bad_certs.append(f"User '{username}': ошибка - {ex}")

        if bad_certs:
            msg = "Обнаружены проблемы:\n" + "\n".join(bad_certs)
            messagebox.showerror("Подмена!", msg)
        else:
            messagebox.showinfo("Проверка", "Все сертификаты корректны. Нет подмены.")

    # -------------- VA TAB --------------
    def create_va_tab(self):
        frame = self.tab_va
        ttk.Label(frame, text="Центр валидации (VA)", font=("Arial", 12, "bold")).pack(pady=5)

        subframe = ttk.Frame(frame)
        subframe.pack(pady=5)

        ttk.Label(subframe, text="Имя пользователя для отзыва:").grid(row=0, column=0, sticky="w", padx=5)
        self.entry_va_username = ttk.Entry(subframe)
        self.entry_va_username.grid(row=0, column=1, padx=5)

        ttk.Button(subframe, text="Отозвать сертификат", command=self.revoke_certificate).grid(row=0, column=2, padx=5)
        ttk.Button(frame, text="Обновить CRL", command=self.update_crl).pack(pady=5)

        self.text_crl = tk.Text(frame, wrap="word", height=10)
        self.text_crl.pack(expand=True, fill="both", padx=10, pady=5)
        self.update_crl()

    def revoke_certificate(self):
        username = self.entry_va_username.get().strip()
        if not username:
            messagebox.showerror("Ошибка", "Введите имя пользователя для отзыва сертификата.")
            return

        cfile = os.path.join(self.certs_folder, f"{username}_cert.pem")
        if not os.path.exists(cfile):
            messagebox.showerror("Ошибка", f"Сертификат для пользователя '{username}' не найден.")
            return

        with open(cfile, "r", encoding="utf-8") as f:
            cert_pem = f.read()

        self.va.revoke_certificate(cert_pem, reason="Отзыв по запросу")
        messagebox.showinfo("Успех", "Сертификат отозван.")
        self.update_crl()

    def update_crl(self):
        crl_text = self.va.get_crl()
        self.text_crl.config(state="normal")
        self.text_crl.delete("1.0", tk.END)
        self.text_crl.insert(tk.END, crl_text)
        self.text_crl.config(state="disabled")

    # -------------- SubCA TAB --------------
    def create_subca_tab(self):
        frame = self.tab_subca
        ttk.Label(frame, text="Создание дочернего удостоверяющего центра", font=("Arial", 12, "bold")).grid(row=0, column=0, columnspan=2, pady=5)

        ttk.Label(frame, text="Тип SubCA:").grid(row=1, column=0, sticky="w", pady=5, padx=5)
        self.combo_subca_type = ttk.Combobox(frame, values=["Подпись пользователей", "Целостность ПО", "Целостность заказа"], state="readonly")
        self.combo_subca_type.current(0)
        self.combo_subca_type.grid(row=1, column=1, pady=5, padx=5)

        ttk.Label(frame, text="Common Name:").grid(row=2, column=0, sticky="w", pady=5, padx=5)
        self.entry_subca_cn = ttk.Entry(frame)
        self.entry_subca_cn.grid(row=2, column=1, pady=5, padx=5)

        ttk.Label(frame, text="Размер ключа:").grid(row=3, column=0, sticky="w", pady=5, padx=5)
        self.combo_subca_key_size = ttk.Combobox(frame, values=[2048, 3072, 4096], state="readonly")
        self.combo_subca_key_size.current(0)
        self.combo_subca_key_size.grid(row=3, column=1, pady=5, padx=5)

        ttk.Button(frame, text="Создать дочерний УЦ", command=self.create_subca).grid(row=4, column=0, columnspan=2, pady=10)

        # Кнопки для проверки целостности
        self.btn_check_software = ttk.Button(frame, text="Проверить целостность ПО", command=self.check_software_integrity)
        self.btn_check_order = ttk.Button(frame, text="Проверить целостность заказов", command=self.check_order_integrity)
        self.btn_check_software.grid(row=5, column=0, columnspan=2, pady=5)
        self.btn_check_order.grid(row=6, column=0, columnspan=2, pady=5)

        # Кнопка "Проверить SubCA"
        ttk.Button(frame, text="Проверить SubCA", command=self.do_verify_subca).grid(row=7, column=0, columnspan=2, pady=5)

    def create_subca(self):
        subca_type = self.combo_subca_type.get()
        subca_cn = self.entry_subca_cn.get().strip()

        try:
            subca_key_size = int(self.combo_subca_key_size.get())
        except ValueError:
            subca_key_size = 2048

        if not subca_cn:
            messagebox.showerror("Ошибка", "Введите Common Name для дочернего УЦ!")
            return

        full_subca_cn = f"{subca_type} - {subca_cn}"

        cert_filename = os.path.join(self.subcas_folder, f"subCA_{subca_type.replace(' ', '_')}_{subca_cn}_cert.pem")
        key_filename = os.path.join(self.subcas_folder, f"subCA_{subca_type.replace(' ', '_')}_{subca_cn}_key.pem")

        if os.path.exists(cert_filename) and os.path.exists(key_filename):
            messagebox.showerror("Ошибка", f"Дочерний УЦ '{full_subca_cn}' уже создан!\n{cert_filename}\n{key_filename}")
            return
        elif os.path.exists(cert_filename) or os.path.exists(key_filename):
            messagebox.showerror("Ошибка", f"Файлы для '{full_subca_cn}' частично существуют.\n{cert_filename}\n{key_filename}")
            return

        # Создаём SubCA через root CA
        sub_cert_pem, sub_key_pem = self.ca.create_subordinate_ca(
            full_subca_cn,
            key_size=subca_key_size,
            validity_days=365
        )

        with open(cert_filename, "w", encoding="utf-8") as f_cert:
            f_cert.write(sub_cert_pem)
        with open(key_filename, "w", encoding="utf-8") as f_key:
            f_key.write(sub_key_pem)

        # Запоминаем в self.subcas
        self.subcas[subca_type] = (sub_cert_pem, sub_key_pem, full_subca_cn, CA_Sub(sub_cert_pem, sub_key_pem))

        if subca_type == "Подпись пользователей":
            options = ["Root CA", f"SubCA: {full_subca_cn}"]
            self.combo_reg_ca.config(values=options)
            self.combo_reg_ca.current(1)

        self.entry_subca_cn.delete(0, tk.END)
        self.combo_subca_key_size.current(0)

        messagebox.showinfo("Успех",
            f"Дочерний УЦ '{full_subca_cn}' создан!\n"
            f"Сертификат: {cert_filename}\nКлюч: {key_filename}"
        )

    def do_verify_subca(self):
        subca_type = self.combo_subca_type.get()
        self.verify_subca_integrity(subca_type)

    def verify_subca_integrity(self, subca_type: str):
        if subca_type not in self.subcas:
            messagebox.showerror("Ошибка", f"SubCA '{subca_type}' не найден.")
            return

        subca_cert_pem = self.subcas[subca_type][0]
        with open(self.ca.ca_cert_file, "r", encoding="utf-8") as f:
            root_cert_pem = f.read()

        try:
            verify_subca_vs_root(root_cert_pem, subca_cert_pem)
            messagebox.showinfo("Проверка SubCA",
                f"SubCA '{subca_type}' корректно подписан Root CA.")
        except cryptography.exceptions.InvalidSignature:
            messagebox.showerror("Подмена!",
                f"Сертификат SubCA '{subca_type}' не совпадает с Root CA!")
        except Exception as ex:
            messagebox.showerror("Ошибка",
                f"Ошибка при проверке SubCA '{subca_type}': {ex}")

    # -------------- Проверка целостности ПО / заказов --------------
    def file_sha256(self, filepath) -> str:
        sha256_hash = hashlib.sha256()
        with open(filepath, "rb") as f:
            while True:
                chunk = f.read(4096)
                if not chunk:
                    break
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()

    def check_software_integrity(self):
        # ...
        pass

    def check_order_integrity(self):
        # ...
        pass

    def show_results(self, title, text):
        result_win = tk.Toplevel(self)
        result_win.title(title)
        txt = tk.Text(result_win, wrap="word")
        txt.insert(tk.END, text)
        txt.pack(expand=True, fill="both")


# -------------------- Запуск приложения --------------------
if __name__ == "__main__":
    ca = CA()
    va = VA()
    app = PKIApp(ca, va)
    app.mainloop()
