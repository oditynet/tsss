import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import socket
import threading
import json
import base64
import os
import hashlib
import pickle
import mimetypes
import time
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
import logging

# Детальное логирование для клиента
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(threadName)s - %(message)s',
    handlers=[
        logging.FileHandler('client_debug.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class SecureMessengerClient:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Secure Messenger")
        self.root.geometry("1000x800")
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        self.server_host = "localhost"
        self.server_port = 5555
        
        self.username = None
        self.private_key = None
        self.public_key = None
        self.public_key_pem = None
        self.symmetric_key = None
        
        self.client_socket = None
        self.connected = False
        self.receive_thread = None
        
        self.contacts = {}
        self.active_chat = None
        self.messages = self.load_messages()
        self.all_users = []
        
        self.typing_status = {}
        self.typing_timers = {}
        
        self.message_status = {}
        
        self.save_timer = None
        self.typing_timeout = None
        
        self.attached_file = None
        self.attached_filename = None
        
        self.message_counter = 0
        
        self.file_storage = {}
        
        self.search_dialog = None
        
        # Счетчики непрочитанных сообщений
        self.unread_counts = {}  # username -> количество непрочитанных сообщений
        
        logger.debug(f"__init__: Инициализация клиента")
        logger.debug(f"__init__: Сообщения загружены: {list(self.messages.keys())}")
        
        self.setup_ui()
        self.load_or_register()
    
    def setup_ui(self):
        logger.debug(f"setup_ui: Настройка пользовательского интерфейса")

        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Левая панель - профиль и контакты
        left_panel = ttk.Frame(main_frame, width=200)
        left_panel.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 10))
        left_panel.pack_propagate(False)

        # Профиль пользователя
        profile_frame = ttk.LabelFrame(left_panel, text="Мой профиль", padding=10)
        profile_frame.pack(fill=tk.X, pady=(0, 10))

        self.profile_label = ttk.Label(profile_frame, text="", font=('Arial', 12, 'bold'))
        self.profile_label.pack(anchor=tk.W)

        # Кнопка поиска пользователей
        search_frame = ttk.Frame(left_panel)
        search_frame.pack(fill=tk.X, pady=(0, 10))

        search_btn = ttk.Button(search_frame, text="Найти пользователей",
                               command=self.show_search_dialog, width=20)
        search_btn.pack(fill=tk.X)

        # Список контактов
        contacts_label = ttk.Label(left_panel, text="История переписки",
                                  font=('Arial', 11, 'bold'))
        contacts_label.pack(anchor=tk.W, pady=(10, 5))

        contacts_container = ttk.Frame(left_panel)
        contacts_container.pack(fill=tk.BOTH, expand=True)

        # Создаем Listbox с настроенными цветами
        self.contacts_listbox = tk.Listbox(
            contacts_container,
            height=25,
            font=('Arial', 10),
            selectbackground='#007ACC',
            selectforeground='white',
            bg='white',
            relief='flat',
            highlightthickness=0
        )
        self.contacts_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        scrollbar = ttk.Scrollbar(contacts_container)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.contacts_listbox.config(yscrollcommand=scrollbar.set)
        scrollbar.config(command=self.contacts_listbox.yview)

        self.contacts_listbox.bind('<<ListboxSelect>>', self.on_contact_select)

        # Индикатор подключения
        self.status_label = ttk.Label(left_panel, text="Отключен")
        self.status_label.pack(side=tk.BOTTOM, fill=tk.X, pady=(10, 0))

        # Правая панель - чат
        right_panel = ttk.Frame(main_frame)
        right_panel.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        # Заголовок чата
        header_frame = ttk.Frame(right_panel)
        header_frame.pack(fill=tk.X, pady=(0, 10))

        self.chat_header = ttk.Label(header_frame, text="Выберите контакт",
                                    font=('Arial', 12, 'bold'))
        self.chat_header.pack(side=tk.LEFT)

        self.verify_status = ttk.Label(header_frame, text="", font=('Arial', 9))
        self.verify_status.pack(side=tk.LEFT, padx=(10, 0))

        self.verify_btn = ttk.Button(header_frame, text="Проверить", width=12,
                                    command=self.show_verification_dialog, state='disabled')
        self.verify_btn.pack(side=tk.RIGHT)

        # Метка "печатает..."
        self.typing_label = ttk.Label(right_panel, text="", font=('Arial', 9, 'italic'),
                                     foreground="gray")
        self.typing_label.pack(anchor=tk.W, pady=(0, 5))

        # Область сообщений
        chat_frame = ttk.Frame(right_panel)
        chat_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

        self.chat_display = scrolledtext.ScrolledText(
            chat_frame,
            height=25,
            state='disabled',
            wrap=tk.WORD,
            font=('Arial', 10),
            spacing1=2,
            spacing3=2
        )
        self.chat_display.pack(fill=tk.BOTH, expand=True)

        # Панель для файла
        self.file_frame = ttk.Frame(right_panel)
        self.file_frame.pack(fill=tk.X, pady=(0, 5))
        self.file_label = ttk.Label(self.file_frame, text="", foreground="blue")
        self.file_label.pack(side=tk.LEFT)

        self.remove_file_btn = ttk.Button(self.file_frame, text="✕", width=3,
                                         command=self.clear_attachment, state='disabled')
        self.remove_file_btn.pack(side=tk.RIGHT)

        # Панель ввода
        input_frame = ttk.Frame(right_panel)
        input_frame.pack(fill=tk.X, side=tk.BOTTOM)

        attach_btn = ttk.Button(input_frame, text="Прикрепить", width=12,
                               command=self.attach_file)
        attach_btn.pack(side=tk.LEFT, padx=(0, 5))

        # Поле ввода сообщения
        self.message_entry = tk.Text(input_frame, height=3, wrap=tk.WORD, font=('Arial', 10))
        self.message_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)

        # Обработчики клавиш
        self.message_entry.bind('<KeyPress>', self.on_key_press)
        self.message_entry.bind('<KeyRelease>', self.on_typing)

        # Кнопка отправки
        send_btn = ttk.Button(input_frame, text="Отправить", command=self.send_message)
        send_btn.pack(side=tk.RIGHT)

        # Подсказка для пользователя о горячих клавишах
        hint_frame = ttk.Frame(right_panel)
        hint_frame.pack(fill=tk.X, pady=(5, 0))

        hint_label = ttk.Label(hint_frame,
                              text="Enter - отправить сообщение | Ctrl+Enter или Shift+Enter - новая строка",
                              font=('Arial', 8),
                              foreground="gray",
                              justify=tk.LEFT)
        hint_label.pack(anchor=tk.W)

        logger.debug(f"setup_ui: Интерфейс настроен")
    
    def on_key_press(self, event):
        """Обработка нажатия клавиш в поле ввода"""
        logger.debug(f"on_key_press: Клавиша: {event.keysym}, состояние: {event.state}")
        
        # Enter без модификаторов - отправка
        if (event.keysym == 'Return' or event.keysym == 'KP_Enter') and event.state == 16:
            logger.debug(f"on_key_press: Enter без модификаторов - отправка")
            self.send_message()
            return "break"  # Предотвращаем стандартную обработку
            
        # Enter с Ctrl или Shift - новая строка
        elif event.keysym == 'Return' and (event.state & 0x0004 or event.state & 0x0001):
            logger.debug(f"on_key_press: Enter с модификатором - новая строка")
            self.message_entry.insert(tk.INSERT, '\n')
            return "break"
            
        # Numpad Enter с Ctrl или Shift
        elif event.keysym == 'KP_Enter' and (event.state & 0x0004 or event.state & 0x0001):
            logger.debug(f"on_key_press: KP_Enter с модификатором - новая строка")
            self.message_entry.insert(tk.INSERT, '\n')
            return "break"
        
        return None
    
    def show_search_dialog(self):
        logger.debug(f"show_search_dialog: Открытие диалога поиска")
        
        if self.search_dialog and self.search_dialog.winfo_exists():
            self.search_dialog.lift()
            return
        
        self.search_dialog = tk.Toplevel(self.root)
        dialog = self.search_dialog
        dialog.title("Поиск пользователей")
        dialog.geometry("500x500")
        dialog.transient(self.root)
        dialog.grab_set()
        
        dialog.protocol("WM_DELETE_WINDOW", lambda: self.close_search_dialog())
        
        # Поле поиска
        search_frame = ttk.Frame(dialog)
        search_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(search_frame, text="Имя пользователя:").pack(side=tk.LEFT)
        
        self.search_var = tk.StringVar()
        search_entry = ttk.Entry(search_frame, textvariable=self.search_var, width=30)
        search_entry.pack(side=tk.LEFT, padx=(10, 5), fill=tk.X, expand=True)
        
        search_btn = ttk.Button(search_frame, text="Найти", 
                               command=self.do_search)
        search_btn.pack(side=tk.RIGHT)
        
        # Флажок "только онлайн"
        options_frame = ttk.Frame(dialog)
        options_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        
        self.online_only_var = tk.BooleanVar(value=False)
        online_only_check = ttk.Checkbutton(
            options_frame, 
            text="Только онлайн пользователи",
            variable=self.online_only_var
        )
        online_only_check.pack(anchor=tk.W)
        
        # Список результатов
        results_frame = ttk.Frame(dialog)
        results_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
        
        results_label = ttk.Label(results_frame, text="Результаты поиска:", 
                                 font=('Arial', 10, 'bold'))
        results_label.pack(anchor=tk.W, pady=(0, 5))
        
        self.results_listbox = tk.Listbox(results_frame, height=15, font=('Arial', 10))
        self.results_listbox.pack(fill=tk.BOTH, expand=True)
        
        scrollbar = ttk.Scrollbar(self.results_listbox)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.results_listbox.config(yscrollcommand=scrollbar.set)
        scrollbar.config(command=self.results_listbox.yview)
        
        # Кнопки
        btn_frame = ttk.Frame(dialog)
        btn_frame.pack(pady=(0, 10))
        
        select_btn = ttk.Button(btn_frame, text="Начать чат", 
                               command=lambda: self.select_search_result(dialog))
        select_btn.pack(side=tk.LEFT, padx=5)
        
        close_btn = ttk.Button(btn_frame, text="Закрыть", command=self.close_search_dialog)
        close_btn.pack(side=tk.LEFT, padx=5)
        
        search_entry.bind('<Return>', lambda e: self.do_search())
        search_entry.focus_set()
    
    def close_search_dialog(self):
        logger.debug(f"close_search_dialog: Закрытие диалога поиска")
        if self.search_dialog:
            self.search_dialog.destroy()
            self.search_dialog = None
    
    def do_search(self):
        logger.debug(f"do_search: Выполнение поиска")
        
        if not self.connected:
            logger.warning(f"do_search: Нет подключения к серверу")
            messagebox.showerror("Ошибка", "Нет подключения к серверу")
            return
        
        search_term = self.search_var.get().strip()
        if not search_term:
            logger.warning(f"do_search: Пустой поисковый запрос")
            messagebox.showwarning("Предупреждение", "Введите текст для поиска")
            return
        
        data = {
            'type': 'search',
            'username': search_term,
            'online_only': self.online_only_var.get()
        }
        
        logger.debug(f"do_search: Отправка запроса поиска: {data}")
        
        try:
            self.client_socket.send(json.dumps(data).encode('utf-8'))
            logger.debug(f"do_search: Запрос поиска отправлен: {search_term}, online_only={self.online_only_var.get()}")
        except Exception as e:
            logger.error(f"do_search: Ошибка отправки запроса поиска: {e}")
            messagebox.showerror("Ошибка", "Не удалось выполнить поиск")
    
    def select_search_result(self, dialog):
        logger.debug(f"select_search_result: Выбор результата поиска")
        
        selection = self.results_listbox.curselection()
        if not selection:
            logger.warning(f"select_search_result: Не выбран пользователь")
            messagebox.showwarning("Предупреждение", "Выберите пользователя из списка")
            return
        
        username = self.results_listbox.get(selection[0])
        logger.debug(f"select_search_result: Выбран пользователь: {username}")
        
        if " " in username:
            username = username.split(" ", 1)[0]
            logger.debug(f"select_search_result: Имя пользователя после обработки: {username}")
        
        self.close_search_dialog()
        self.start_chat_with_user(username)
    
    def start_chat_with_user(self, username):
        logger.debug(f"start_chat_with_user: Начало чата с пользователем: {username}")
        
        if username == self.username:
            logger.warning(f"start_chat_with_user: Попытка начать чат с самим собой")
            messagebox.showinfo("Информация", "Нельзя начать чат с самим собой")
            return
        
        logger.debug(f"start_chat_with_user: Текущие сообщения: {list(self.messages.keys())}")
        
        if username not in self.messages:
            self.messages[username] = []
            #logger.debug(f"start_chat_with_user: Создана новая история для {username}")
            #self.save_messages_delayed()
        
        contacts_list = self.contacts_listbox.get(0, tk.END)
        logger.debug(f"start_chat_with_user: Текущие контакты в списке: {contacts_list}")
        
        if username not in contacts_list:
            # Проверяем, есть ли непрочитанные сообщения для этого пользователя
            unread_count = self.unread_counts.get(username, 0)
            display_name = f"{username} ({unread_count})" if unread_count > 0 else username
            self.contacts_listbox.insert(tk.END, display_name)
            logger.debug(f"start_chat_with_user: Добавлен в список контактов: {display_name}")
        
        for i in range(self.contacts_listbox.size()):
            item = self.contacts_listbox.get(i)
            item_username = self.get_username_from_display(item)
            if item_username == username:
                self.contacts_listbox.selection_clear(0, tk.END)
                self.contacts_listbox.selection_set(i)
                self.contacts_listbox.activate(i)
                logger.debug(f"start_chat_with_user: Выбран контакт {username} на позиции {i}")
                break
        
        self.on_contact_select(None)
    
    def load_or_register(self):
        logger.debug(f"load_or_register: Проверка существования пользователя")
        
        if os.path.exists("user_data.bin"):
            logger.debug(f"load_or_register: Файл пользователя найден, показ логина")
            self.show_login_dialog()
        else:
            logger.debug(f"load_or_register: Файл пользователя не найден, показ регистрации")
            self.show_register_dialog()
    
    def show_register_dialog(self):
        logger.debug(f"show_register_dialog: Показ диалога регистрации")
        
        self.dialog = tk.Toplevel(self.root)
        self.dialog.title("Регистрация")
        self.dialog.geometry("350x280")
        self.dialog.transient(self.root)
        self.dialog.grab_set()
        
        ttk.Label(self.dialog, text="Логин:").pack(pady=(20, 5))
        self.reg_username = ttk.Entry(self.dialog, width=30)
        self.reg_username.pack()
        
        ttk.Label(self.dialog, text="Пароль:").pack(pady=(10, 5))
        self.reg_password = ttk.Entry(self.dialog, width=30, show="*")
        self.reg_password.pack()
        
        ttk.Label(self.dialog, text="Повторите пароль:").pack(pady=(10, 5))
        self.reg_password_confirm = ttk.Entry(self.dialog, width=30, show="*")
        self.reg_password_confirm.pack()
        
        reg_btn = ttk.Button(self.dialog, text="Зарегистрироваться", command=self.do_register)
        reg_btn.pack(pady=15)
        
        self.dialog.bind('<Return>', lambda e: self.do_register())
    
    def show_login_dialog(self):
        logger.debug(f"show_login_dialog: Показ диалога входа")
        
        self.dialog = tk.Toplevel(self.root)
        self.dialog.title("Вход")
        self.dialog.geometry("300x200")
        self.dialog.transient(self.root)
        self.dialog.grab_set()
        
        ttk.Label(self.dialog, text="Логин:").pack(pady=(20, 5))
        self.login_username = ttk.Entry(self.dialog, width=30)
        self.login_username.pack()
        
        ttk.Label(self.dialog, text="Пароль:").pack(pady=(10, 5))
        self.login_password = ttk.Entry(self.dialog, width=30, show="*")
        self.login_password.pack()
        
        login_btn = ttk.Button(self.dialog, text="Войти", command=self.do_login)
        login_btn.pack(pady=15)
        
        self.dialog.bind('<Return>', lambda e: self.do_login())
    
    def do_register(self):
        username = self.reg_username.get().strip()
        password = self.reg_password.get()
        password_confirm = self.reg_password_confirm.get()
        
        logger.debug(f"do_register: Регистрация пользователя {username}")
        
        if not username or not password:
            logger.warning(f"do_register: Не заполнены все поля")
            messagebox.showerror("Ошибка", "Заполните все поля")
            return
        
        if password != password_confirm:
            logger.warning(f"do_register: Пароли не совпадают")
            messagebox.showerror("Ошибка", "Пароли не совпадают")
            return
        
        self.generate_keys(username, password)
        
        if self.connect_to_server():
            self.send_public_key()
            self.dialog.destroy()
            self.root.deiconify()
            self.profile_label.config(text=f"{username}")
            self.load_history_contacts()
            logger.debug(f"do_register: Регистрация успешна для {username}")
        else:
            logger.error(f"do_register: Не удалось подключиться к серверу")
            messagebox.showerror("Ошибка", "Не удалось подключиться к серверу")
    
    def do_login(self):
        username = self.login_username.get().strip()
        password = self.login_password.get()
        
        logger.debug(f"do_login: Вход пользователя {username}")
        
        if self.load_keys(username, password):
            if self.connect_to_server():
                self.send_public_key()
                self.dialog.destroy()
                self.root.deiconify()
                self.profile_label.config(text=f"{username}")
                self.load_history_contacts()
                logger.debug(f"do_login: Вход успешен для {username}")
            else:
                logger.error(f"do_login: Не удалось подключиться к серверу")
                messagebox.showerror("Ошибка", "Не удалось подключиться к серверу")
        else:
            logger.warning(f"do_login: Неверный логин или пароль")
            messagebox.showerror("Ошибка", "Неверный логин или пароль")

    def get_username_from_display(self, display_text):
        """Извлекает имя пользователя из отображаемого текста (убирает счетчик)"""
        import re
        match = re.match(r'^(.+?)\s*\(\d+\)$', display_text)
        if match:
            return match.group(1).strip()
        return display_text.strip()

    def calculate_unread_counts(self):
        """Вычисление количества непрочитанных сообщений для каждого контакта"""
        logger.debug(f"calculate_unread_counts: Расчет непрочитанных сообщений")

        self.unread_counts = {}

        for username, messages in self.messages.items():
            if username == self.username:
                continue

            unread = 0
            for msg in messages:
                # Сообщение непрочитано, если:
                # 1. Оно не исходящее (не от нас)
                # 2. Не имеет статуса 'read'
                # 3. Не было помечено как прочитанное
                if (not msg.get('outgoing', False) and
                        msg.get('status') != 'read' and
                        not msg.get('read', False)):
                    unread += 1

            if unread > 0:
                self.unread_counts[username] = unread
                logger.debug(f"calculate_unread_counts: {username}: {unread} непрочитанных")

    def load_history_contacts(self):
        """Загрузка истории контактов с учетом непрочитанных сообщений"""
        logger.debug(f"load_history_contacts: Загрузка истории контактов")

        # Сначала вычисляем непрочитанные сообщения
        self.calculate_unread_counts()

        self.contacts_listbox.delete(0, tk.END)

        # Сортируем контакты по времени последнего сообщения (сначала новые)
        sorted_contacts = []
        for username in self.messages.keys():
            if username != self.username:# and self.messages[username]:
                last_message_time = max(
                    [datetime.fromisoformat(msg['timestamp'])
                     for msg in self.messages[username]
                     if 'timestamp' in msg],
                    default=datetime.min
                )
                sorted_contacts.append((last_message_time, username))

        # Сортируем по времени (сначала новые)
        sorted_contacts.sort(reverse=True)

        for _, username in sorted_contacts:
            # Добавляем индикатор непрочитанных сообщений
            unread_count = self.unread_counts.get(username, 0)
            display_name = f"{username} ({unread_count})" if unread_count > 0 else username

            self.contacts_listbox.insert(tk.END, display_name)
            logger.debug(f"load_history_contacts: Добавлен контакт: {display_name}")

        # Автоматически выделяем первый контакт, если нет активного
        if self.contacts_listbox.size() > 0 and not self.active_chat:
            self.contacts_listbox.selection_set(0)
            self.contacts_listbox.activate(0)
            selected_user = self.get_username_from_display(self.contacts_listbox.get(0))
            self.active_chat = selected_user
            logger.debug(f"load_history_contacts: Автоматически выбран первый контакт: {self.active_chat}")

            # Загружаем чат
            self.root.after(100, lambda: self.on_contact_select(None))
    
    def generate_keys(self, username, password):
        logger.debug(f"generate_keys: Генерация ключей для {username}")
        
        self.username = username
        
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        
        
        self.public_key_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=700000,
            backend=default_backend()
        )
        key = kdf.derive(password.encode())
        self.symmetric_key = base64.urlsafe_b64encode(key)
        
        private_key_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        cipher = Fernet(self.symmetric_key)
        encrypted_data = cipher.encrypt(private_key_pem)
        
        print(self.public_key_pem.decode('utf-8'))
        
        with open("user_data.bin", "wb") as f:
            f.write(salt)
            f.write(encrypted_data)
        
        logger.debug(f"generate_keys: Ключи сгенерированы и сохранены")
    
    def load_keys(self, username, password):
        logger.debug(f"load_keys: Загрузка ключей для {username}")
        
        try:
            with open("user_data.bin", "rb") as f:
                salt = f.read(16)
                encrypted_data = f.read()
            
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=700000,
                backend=default_backend()
            )
            key = kdf.derive(password.encode())
            symmetric_key = base64.urlsafe_b64encode(key)
            
            cipher = Fernet(symmetric_key)
            private_key_pem = cipher.decrypt(encrypted_data)
            
            self.private_key = serialization.load_pem_private_key(
                private_key_pem,
                password=None,
                backend=default_backend()
            )
            self.public_key = self.private_key.public_key()
            self.public_key_pem = self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            self.symmetric_key = symmetric_key
            self.username = username
            
            logger.debug(f"load_keys: Ключи успешно загружены")
            return True
        except Exception as e:
            logger.error(f"load_keys: Ошибка загрузки ключей: {e}")
            return False
    
    def connect_to_server(self):
        logger.debug(f"connect_to_server: Подключение к серверу {self.server_host}:{self.server_port}")
        
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.settimeout(1.0)
            logger.debug(f"connect_to_server: Создан сокет: {self.client_socket}")
            
            self.client_socket.connect((self.server_host, self.server_port))
            self.connected = True
            self.status_label.config(text="Подключен")
            
            logger.debug(f"connect_to_server: Подключение успешно")
            
            self.receive_thread = threading.Thread(target=self.receive_messages, daemon=True)
            self.receive_thread.start()
            logger.debug(f"connect_to_server: Запущен поток приема сообщений")
            
            self.start_ping_thread()
            
            return True
        except Exception as e:
            logger.error(f"connect_to_server: Ошибка подключения: {e}")
            return False
    
    def start_ping_thread(self):
        def ping_loop():
            logger.debug(f"ping_loop: Запуск цикла ping")
            while self.connected:
                time.sleep(30)
                if self.connected:
                    self.send_ping()
        
        thread = threading.Thread(target=ping_loop, daemon=True, name="PingThread")
        thread.start()
        logger.debug(f"start_ping_thread: Поток ping запущен")
    
    def send_ping(self):
        if not self.connected:
            logger.debug(f"send_ping: Нет подключения, ping не отправлен")
            return
        
        data = {
            'type': 'ping',
            'username': self.username
        }
        
        logger.debug(f"send_ping: Отправка ping: {data}")
        
        try:
            self.client_socket.send(json.dumps(data).encode('utf-8'))
            logger.debug(f"send_ping: Ping отправлен")
        except Exception as e:
            logger.error(f"send_ping: Ошибка отправки ping: {e}")
            self.connected = False
            self.status_label.config(text="Отключен")
    
    def send_public_key(self):
        if not self.connected:
            logger.warning(f"send_public_key: Нет подключения, ключ не отправлен")
            return
        
        data = {
            'type': 'register',
            'username': self.username,
            'public_key': self.public_key_pem.decode('utf-8')
        }
        
        logger.debug(f"send_public_key: Отправка публичного ключа")
        logger.debug(f"send_public_key: Длина ключа: {len(data['public_key'])}")
        
        try:
            self.client_socket.send(json.dumps(data).encode('utf-8'))
            logger.debug(f"send_public_key: Публичный ключ отправлен")
        except Exception as e:
            logger.error(f"send_public_key: Ошибка отправки ключа: {e}")
            self.connected = False
            self.status_label.config(text="Отключен")

    def send_read_receipts_for_unread(self, username):
        """Отправляет уведомления о прочтении для всех непрочитанных сообщений"""
        logger.debug(f"send_read_receipts_for_unread: Отправка уведомлений о прочтении для {username}")

        if not self.connected or not username:
            return

        if username in self.messages:
            # Находим все непрочитанные сообщения
            unread_message_ids = []
            for msg in self.messages[username]:
                if (not msg.get('outgoing', False) and
                        msg.get('status') != 'read' and
                        msg.get('id')):
                    unread_message_ids.append(msg['id'])

            # Отправляем уведомления для каждого сообщения
            for message_id in unread_message_ids:
                data = {
                    'type': 'read_receipt',
                    'message_id': message_id,
                    'to': username
                }

                logger.debug(f"send_read_receipts_for_unread: Отправка read_receipt для сообщения {message_id}")

                try:
                    self.client_socket.send(json.dumps(data).encode('utf-8'))
                    logger.debug(f"send_read_receipts_for_unread: Read_receipt отправлен")
                except Exception as e:
                    logger.error(f"send_read_receipts_for_unread: Ошибка отправки: {e}")

    def mark_messages_as_read(self, username):
        """Помечает все сообщения от пользователя как прочитанные"""
        logger.debug(f"mark_messages_as_read: Помечаем сообщения от {username} как прочитанные")

        if username in self.messages:
            for msg in self.messages[username]:
                if not msg.get('outgoing', False):
                    msg['status'] = 'read'
                    msg['read'] = True
                    logger.debug(f"mark_messages_as_read: Сообщение {msg.get('id')} помечено как прочитанное")
            #self.save_messages_delayed()

    def on_contact_select(self, event):
        """Обработка выбора контакта в списке"""
        selection = self.contacts_listbox.curselection()
        if not selection:
            logger.debug(f"on_contact_select: Не выбран контакт")
            return

        display_text = self.contacts_listbox.get(selection[0])
        username = self.get_username_from_display(display_text)
        logger.debug(f"on_contact_select: Выбран контакт: {username}")

        # Помечаем все сообщения от этого пользователя как прочитанные
        self.mark_messages_as_read(username)

        # Сбрасываем счетчик непрочитанных для этого пользователя
        if username in self.unread_counts:
            del self.unread_counts[username]

        # Устанавливаем активный чат
        self.active_chat = username
        self.chat_header.config(text=f"Чат с {username}")
        logger.debug(f"on_contact_select: Активный чат установлен: {self.active_chat}")

        # Загружаем историю чата
        self.load_chat()

        # Отправляем уведомления о прочтении для последних сообщений
        self.send_read_receipts_for_unread(username)

        # Обновляем список контактов (чтобы убрать счетчик непрочитанных)
        self.load_history_contacts()

        # Запрашиваем публичный ключ, если его нет
        if username not in self.contacts:
            logger.debug(f"on_contact_select: Ключ для {username} не найден, запрос...")
            self.request_public_key(username)
        else:
            logger.debug(f"on_contact_select: Ключ для {username} уже загружен")
            self.update_verification_status()

        # Фокус на поле ввода
        self.message_entry.focus_set()
    
    def request_public_key(self, username):
        if not self.connected:
            logger.warning(f"request_public_key: Нет подключения, запрос ключа не отправлен")
            return
        
        data = {
            'type': 'get_key',
            'username': username
        }
        
        logger.debug(f"request_public_key: Запрос ключа для {username}")
        
        try:
            self.client_socket.send(json.dumps(data).encode('utf-8'))
            logger.debug(f"request_public_key: Запрос ключа отправлен")
        except Exception as e:
            logger.error(f"request_public_key: Ошибка отправки запроса ключа: {e}")
    
    def generate_verification_code(self, other_public_key_pem):
        logger.debug(f"generate_verification_code: Генерация кода верификации")
        
        if not other_public_key_pem:
            logger.warning(f"generate_verification_code: Нет публичного ключа собеседника")
            return "-----"
        
        my_hash = hashlib.sha256(self.public_key_pem).digest()[:20]
        other_hash = hashlib.sha256(other_public_key_pem).digest()[:20]
        
        xor_result = bytes(a ^ b for a, b in zip(my_hash, other_hash))
        num = int.from_bytes(xor_result[:4], 'big')
        code = ""
        
        for _ in range(5):
            digit = num % 10
            code = str(digit) + code
            num //= 10
        
        logger.debug(f"generate_verification_code: Сгенерирован код: {code}")
        return code if code else "-----"
    
    def show_verification_dialog(self):
        if not self.active_chat or self.active_chat not in self.contacts:
            logger.warning(f"show_verification_dialog: Нет активного чата или контакта")
            return
        
        logger.debug(f"show_verification_dialog: Показ диалога верификации для {self.active_chat}")
        
        dialog = tk.Toplevel(self.root)
        dialog.title("Проверка ключа")
        dialog.geometry("360x250")
        dialog.transient(self.root)
        
        contact = self.contacts[self.active_chat]
        
        if contact.get('verified', False):
            logger.debug(f"show_verification_dialog: Ключ уже проверен")
            ttk.Label(dialog, text="Ключ уже проверен ✓",
                     font=('Arial', 10), foreground="green").pack(pady=30)
            ttk.Button(dialog, text="OK", command=dialog.destroy).pack(pady=10)
            return
        
        try:
            contact_key_pem = contact['public_key'].public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            code = self.generate_verification_code(contact_key_pem)
            logger.debug(f"show_verification_dialog: Код верификации: {code}")
        except Exception as e:
            logger.error(f"show_verification_dialog: Ошибка генерации кода: {e}")
            code = "-----"
        
        ttk.Label(dialog, text="Проверка ключа безопасности",
                 font=('Arial', 11, 'bold')).pack(pady=20)
        
        ttk.Label(dialog, text=f"Код верификации для {self.active_chat}:",
                 font=('Arial', 9)).pack()
        
        ttk.Label(dialog, text=code, font=('Courier', 18, 'bold')).pack(pady=10)
        
        ttk.Label(dialog, text="Сравните этот код с кодом у собеседника.",
                 font=('Arial', 9)).pack(pady=5)
        
        ttk.Label(dialog, text="Если коды совпадают - ключи безопасны.",
                 font=('Arial', 9)).pack(pady=5)
        
        btn_frame = ttk.Frame(dialog)
        btn_frame.pack(pady=20)
        
        def confirm():
            contact['verified'] = True
            self.verify_status.config(text="✓ Проверен", foreground="green")
            self.verify_btn.config(state='disabled')
            logger.debug(f"show_verification_dialog: Ключ подтвержден для {self.active_chat}")
            dialog.destroy()
        
        ttk.Button(btn_frame, text="Подтвердить проверку", command=confirm).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Отмена", command=dialog.destroy).pack(side=tk.LEFT, padx=5)
    
    def update_verification_status(self):
        logger.debug(f"update_verification_status: Обновление статуса верификации")
        
        if not self.active_chat or self.active_chat not in self.contacts:
            logger.debug(f"update_verification_status: Нет активного чата или контакта")
            self.verify_status.config(text="")
            self.verify_btn.config(state='disabled')
            return
        
        contact = self.contacts[self.active_chat]
        logger.debug(f"update_verification_status: Контакт {self.active_chat}, verified={contact.get('verified', False)}")
        
        if contact.get('verified', False):
            self.verify_status.config(text="✓ Проверен", foreground="green")
            self.verify_btn.config(state='disabled')
            logger.debug(f"update_verification_status: Статус установлен: Проверен")
        else:
            self.verify_status.config(text="✗ Не проверен", foreground="red")
            self.verify_btn.config(state='normal')
            logger.debug(f"update_verification_status: Статус установлен: Не проверен")
    
    def on_typing(self, event):
        if not self.active_chat or not self.connected:
            logger.debug(f"on_typing: Нет активного чата или подключения")
            return
        
        data = {
            'type': 'typing',
            'to': self.active_chat,
            'is_typing': True
        }
        
        logger.debug(f"on_typing: Отправка статуса печатания: {data}")
        
        try:
            self.client_socket.send(json.dumps(data).encode('utf-8'))
            logger.debug(f"on_typing: Статус печатания отправлен")
        except Exception as e:
            logger.error(f"on_typing: Ошибка отправки статуса печатания: {e}")
        
        if self.typing_timeout:
            self.root.after_cancel(self.typing_timeout)
        
        self.typing_timeout = self.root.after(2000, self.stop_typing)
    
    def stop_typing(self):
        if not self.active_chat or not self.connected:
            return
        
        data = {
            'type': 'typing',
            'to': self.active_chat,
            'is_typing': False
        }
        
        logger.debug(f"stop_typing: Отправка статуса остановки печатания: {data}")
        
        try:
            self.client_socket.send(json.dumps(data).encode('utf-8'))
            logger.debug(f"stop_typing: Статус остановки печатания отправлен")
        except Exception as e:
            logger.error(f"stop_typing: Ошибка отправки статуса: {e}")
    
    def attach_file(self):
        logger.debug(f"attach_file: Прикрепление файла")
        
        filename = filedialog.askopenfilename(
            title="Выберите файл",
            filetypes=[
                ("Все файлы", "*.*"),
                ("Текстовые", "*.txt *.py *.js *.html *.css *.json *.xml"),
                ("Изображения", "*.png *.jpg *.jpeg *.gif *.bmp *.ico"),
                ("Документы", "*.pdf *.doc *.docx *.xls *.xlsx *.ppt *.pptx"),
                ("Архивы", "*.zip *.rar *.7z *.tar *.gz")
            ]
        )
        
        if filename:
            logger.debug(f"attach_file: Выбран файл: {filename}")
            file_size = os.path.getsize(filename)
            MAX_FILE_SIZE =  512 *1024 * 1024 * 1024 
            
            if file_size > MAX_FILE_SIZE:
                logger.warning(f"attach_file: Файл слишком большой: {file_size} > {MAX_FILE_SIZE}")
                messagebox.showerror("Ошибка", 
                    f"Файл слишком большой ({self.format_file_size(file_size)}).\n"
                    f"Максимальный размер: {self.format_file_size(MAX_FILE_SIZE)}")
                return
            
            self.attached_file = filename
            self.attached_filename = os.path.basename(filename)
            
            size_str = self.format_file_size(file_size)
            file_type = mimetypes.guess_type(filename)[0] or "Неизвестный тип"
            
            self.file_label.config(
                text=f"{self.attached_filename} ({size_str}, {file_type})"
            )
            self.remove_file_btn.config(state='normal')
            
            logger.debug(f"attach_file: Файл прикреплен: {self.attached_filename}, размер: {size_str}")
    
    def format_file_size(self, size_bytes):
        if size_bytes < 1024:
            return f"{size_bytes} Б"
        elif size_bytes < 1024 * 1024:
            return f"{size_bytes/1024:.1f} КБ"
        elif size_bytes < 1024 * 1024 * 1024:
            return f"{size_bytes/(1024*1024):.1f} МБ"
        else:
            return f"{size_bytes/(1024*1024*1024):.1f} ГБ"
    
    def clear_attachment(self):
        logger.debug(f"clear_attachment: Удаление прикрепленного файла")
        self.attached_file = None
        self.attached_filename = None
        self.file_label.config(text="")
        self.remove_file_btn.config(state='disabled')
    
    def send_message(self):
        logger.debug(f"send_message: Начало отправки сообщения")
        logger.debug(f"send_message: Активный чат: {self.active_chat}, Подключен: {self.connected}")
        
        if not self.active_chat or not self.connected:
            logger.warning(f"send_message: Нет активного чата или подключения")
            messagebox.showwarning("Ошибка", "Выберите контакт для общения")
            return
        
        message_text = self.message_entry.get("1.0", tk.END).strip()
        logger.debug(f"send_message: Текст сообщения: '{message_text[:50]}...'")
        logger.debug(f"send_message: Прикрепленный файл: {self.attached_file}")
        
        if not message_text and not self.attached_file:
            logger.warning(f"send_message: Пустое сообщение и нет файла")
            return
        
        if self.active_chat not in self.contacts:
            logger.warning(f"send_message: Ключ для {self.active_chat} не найден")
            messagebox.showwarning("Ожидание", "Ожидаем получение ключа собеседника")
            self.request_public_key(self.active_chat)
            return
        
        try:
            recipient_key = self.contacts[self.active_chat]['public_key']
            logger.debug(f"send_message: Ключ получателя получен: {type(recipient_key)}")
            
            message_id = f"{int(time.time() * 1000)}_{hashlib.md5(os.urandom(16)).hexdigest()[:8]}"
            logger.debug(f"send_message: Сгенерирован ID сообщения: {message_id}")
            
            message_data = {
                'text': message_text,
                'timestamp': datetime.now().isoformat(),
                'message_id': message_id,
                'sender': self.username,
                'has_file': False
            }
            
            file_content_encrypted = None
            file_session_key = None
            
            if self.attached_file:
                logger.debug(f"send_message: Обработка прикрепленного файла: {self.attached_file}")
                try:
                    with open(self.attached_file, 'rb') as f:
                        file_content = f.read()
                    
                    logger.debug(f"send_message: Файл прочитан, размер: {len(file_content)} байт")
                    
                    file_session_key = os.urandom(32)
                    file_cipher = Fernet(base64.urlsafe_b64encode(file_session_key))
                    file_content_encrypted = file_cipher.encrypt(file_content)
                    
                    logger.debug(f"send_message: Файл зашифрован, размер: {len(file_content_encrypted)} байт")
                    
                    file_stats = os.stat(self.attached_file)
                    
                    message_data['has_file'] = True
                    message_data['file_info'] = {
                        'name': self.attached_filename,
                        'size': len(file_content),
                        'encrypted_size': len(file_content_encrypted),
                        'type': mimetypes.guess_type(self.attached_file)[0] or 'application/octet-stream',
                        'modified': file_stats.st_mtime
                    }
                    
                    encrypted_file_session_key = recipient_key.encrypt(
                        file_session_key,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )
                    message_data['file_info']['encrypted_session_key'] = base64.b64encode(
                        encrypted_file_session_key
                    ).decode('utf-8')
                    
                    # Вставляем зашифрованное содержимое файла в сообщение
                    message_data['file_info']['content'] = base64.b64encode(
                        file_content_encrypted
                    ).decode('utf-8')
                    
                    logger.debug(f"send_message: Информация о файле добавлена в сообщение")
                    
                except Exception as e:
                    logger.error(f"send_message: Ошибка обработки файла: {e}")
                    messagebox.showerror("Ошибка", f"Не удалось прочитать файл: {str(e)}")
                    return
            
            session_key = os.urandom(32)
            cipher = Fernet(base64.urlsafe_b64encode(session_key))
            logger.debug(f"send_message: Сгенерирован сессионный ключ для сообщения")
            
            json_data = json.dumps(message_data, ensure_ascii=False)
            logger.debug(f"send_message: JSON данные сообщения: {json_data[:100]}...")
            
            encrypted_message = cipher.encrypt(json_data.encode('utf-8'))
            logger.debug(f"send_message: Сообщение зашифровано, размер: {len(encrypted_message)} байт")
            
            encrypted_session_key = recipient_key.encrypt(
                session_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            logger.debug(f"send_message: Сессионный ключ зашифрован публичным ключом получателя")
            
            data = {
                'type': 'message',
                'to': self.active_chat,
                'message': base64.b64encode(encrypted_message).decode('utf-8'),
                'session_key': base64.b64encode(encrypted_session_key).decode('utf-8'),
                'message_id': message_id,
                'timestamp': datetime.now().isoformat()
            }
            
            logger.debug(f"send_message: Подготовлены данные для отправки:")
            logger.debug(f"  Тип: {data['type']}")
            logger.debug(f"  Кому: {data['to']}")
            logger.debug(f"  ID сообщения: {data['message_id']}")
            logger.debug(f"  Длина зашифрованного сообщения: {len(data['message'])}")
            logger.debug(f"  Длина зашифрованного ключа: {len(data['session_key'])}")
            
            logger.debug(f"send_message: Отправка сообщения на сервер")
            self.client_socket.send(json.dumps(data).encode('utf-8'))
            logger.info(f"send_message: Сообщение {message_id} отправлено на сервер")
            
            self.add_message_to_chat(
                self.username,
                message_text,
                outgoing=True,
                message_id=message_id,
                status='sent',
                file_info={
                    'name': self.attached_filename,
                    'size': os.path.getsize(self.attached_file) if self.attached_file else 0
                } if self.attached_file else None
            )
            
            if self.attached_file and file_content_encrypted:
                self.file_storage[message_id] = {
                    'encrypted_content': file_content_encrypted,
                    'session_key': file_session_key
                }
                logger.debug(f"send_message: Файл сохранен в хранилище под ID: {message_id}")
            
            self.message_entry.delete("1.0", tk.END)
            self.clear_attachment()
            logger.debug(f"send_message: Поля очищены")
            
        except Exception as e:
            logger.error(f"send_message: Ошибка отправки сообщения: {e}")
            messagebox.showerror("Ошибка", f"Не удалось отправить сообщение: {str(e)}")
    
    def add_message_to_chat(self, sender, text, outgoing=False, message_id=None,
                           status='sent', file_info=None):
        logger.debug(f"add_message_to_chat: Добавление сообщения в чат")
        logger.debug(f"add_message_to_chat: Параметры: sender={sender}, text='{text[:50]}...', outgoing={outgoing}, message_id={message_id}, status={status}, file_info={file_info}")
        logger.debug(f"add_message_to_chat: Активный чат: {self.active_chat}")
        
        if self.active_chat not in self.messages:
            self.messages[self.active_chat] = []
            logger.debug(f"add_message_to_chat: Создана новая история для {self.active_chat}")
        
        existing_msg = None
        for msg in self.messages[self.active_chat]:
            if msg.get('id') == message_id:
                existing_msg = msg
                logger.debug(f"add_message_to_chat: Найдено существующее сообщение с ID {message_id}")
                break
        
        if existing_msg:
            logger.debug(f"add_message_to_chat: Обновление существующего сообщения, старый статус: {existing_msg.get('status')}, новый: {status}")
            existing_msg['status'] = status
            if file_info:
                existing_msg['file_info'] = file_info
        else:
            logger.debug(f"add_message_to_chat: Создание нового сообщения")
            message_data = {
                'from': sender,
                'text': text,
                'timestamp': datetime.now().isoformat(),
                'outgoing': outgoing,
                'status': status,
                'id': message_id or f"msg_{int(time.time() * 1000)}"
            }
            
            if file_info:
                message_data['file_info'] = file_info
            
            self.messages[self.active_chat].append(message_data)
            logger.debug(f"add_message_to_chat: Сообщение добавлено в историю, всего сообщений: {len(self.messages[self.active_chat])}")
        
        self.load_chat()
        logger.debug(f"add_message_to_chat: Чат перезагружен")
        
        #self.save_messages_delayed()
    
    def get_status_symbol(self, status):
        symbols = {
            'sent': '✓',
            'delivered': '✓✓',
            'read': '✓✓✓'
        }
        symbol = symbols.get(status, '')
        logger.debug(f"get_status_symbol: Статус {status} -> символ '{symbol}'")
        return symbol
    
    def get_status_color(self, status):
        colors = {
            'sent': 'gray',
            'delivered': 'blue',
            'read': 'green'
        }
        color = colors.get(status, 'gray')
        logger.debug(f"get_status_color: Статус {status} -> цвет '{color}'")
        return color
    
    def save_decrypted_file(self, filename, message_id):
        logger.debug(f"save_decrypted_file: Сохранение расшифрованного файла {filename}, ID: {message_id}")
        
        file_data = None
        file_session_key = None
        
        for msg in self.messages.get(self.active_chat, []):
            if msg.get('id') == message_id and 'file_info' in msg:
                logger.debug(f"save_decrypted_file: Найдено сообщение с файлом в истории")
                if message_id in self.file_storage:
                    file_data = self.file_storage[message_id]['encrypted_content']
                    file_session_key = self.file_storage[message_id]['session_key']
                    logger.debug(f"save_decrypted_file: Данные файла найдены в хранилище")
                    break
        
        if not file_data and message_id in self.file_storage:
            logger.debug(f"save_decrypted_file: Данные файла найдены только в хранилище")
            file_data = self.file_storage[message_id]['encrypted_content']
            file_session_key = self.file_storage[message_id]['session_key']
        
        if not file_data or not file_session_key:
            logger.warning(f"save_decrypted_file: Содержимое файла не найдено для ID {message_id}")
            messagebox.showinfo("Информация", 
                "Содержимое файла не найдено. Возможно, файл был отправлен ранее.")
            return
        
        try:
            logger.debug(f"save_decrypted_file: Дешифрование файла, размер: {len(file_data)} байт")
            file_cipher = Fernet(base64.urlsafe_b64encode(file_session_key))
            decrypted_content = file_cipher.decrypt(file_data)
            logger.debug(f"save_decrypted_file: Файл дешифрован, размер: {len(decrypted_content)} байт")
            
            save_path = filedialog.asksaveasfilename(
                title="Сохранить файл",
                initialfile=filename,
                defaultextension=os.path.splitext(filename)[1] if '.' in filename else ''
            )
            
            if save_path:
                logger.debug(f"save_decrypted_file: Сохранение файла в: {save_path}")
                with open(save_path, 'wb') as f:
                    f.write(decrypted_content)
                
                file_size = len(decrypted_content)
                size_str = self.format_file_size(file_size)
                
                logger.info(f"save_decrypted_file: Файл успешно сохранен: {filename}, размер: {size_str}")
                messagebox.showinfo("Успех", 
                    f"Файл успешно сохранен:\n"
                    f"Имя: {filename}\n"
                    f"Размер: {size_str}\n"
                    f"Путь: {save_path}")
                
        except Exception as e:
            logger.error(f"save_decrypted_file: Ошибка сохранения файла: {e}")
            messagebox.showerror("Ошибка", f"Не удалось сохранить файл: {str(e)}")
    
    def update_message_status(self, message_id, status):
        """Обновление статуса сообщения"""
        logger.debug(f"update_message_status: Обновление статуса для сообщения {message_id} на {status}")
        
        # Обновляем в message_status
        if message_id in self.message_status:
            logger.debug(f"update_message_status: Найдено в message_status")
            self.message_status[message_id]['status'] = status
        
        # Обновляем в истории сообщений
        if self.active_chat:
            updated = False
            for msg in self.messages.get(self.active_chat, []):
                if msg.get('id') == message_id:
                    old_status = msg.get('status', 'unknown')
                    msg['status'] = status
                    updated = True
                    logger.debug(f"update_message_status: Найдено в истории, обновлен статус: {old_status} -> {status}")
                    break
            
            if updated:
                logger.debug(f"update_message_status: Перезагрузка чата для отображения обновленного статуса")
                self.load_chat()
                #self.save_messages_delayed()
        else:
            # Ищем во всех чатах
            for username, messages in self.messages.items():
                for msg in messages:
                    if msg.get('id') == message_id:
                        msg['status'] = status
                        logger.debug(f"update_message_status: Найдено в чате с {username}, обновлен статус")
                        break

    def load_chat(self):
        logger.debug(f"load_chat: Загрузка истории чата для {self.active_chat}")

        self.chat_display.config(state='normal')
        self.chat_display.delete('1.0', tk.END)
        logger.debug(f"load_chat: Очистка области чата")

        if self.active_chat and self.active_chat in self.messages:
            messages_count = len(self.messages[self.active_chat])
            logger.debug(f"load_chat: Загрузка {messages_count} сообщений из истории")

            for msg_idx, msg in enumerate(self.messages[self.active_chat]):
                sender = msg.get('from')
                text = msg.get('text', '')
                outgoing = msg.get('outgoing', False)
                status = msg.get('status', 'sent')
                message_id = msg.get('id')
                file_info = msg.get('file_info')
                timestamp = datetime.fromisoformat(msg['timestamp']).strftime("%H:%M")

                logger.debug(f"load_chat: [{msg_idx+1}/{messages_count}] Обработка сообщения {message_id}")
                logger.debug(f"load_chat:   Отправитель: {sender}, Исходящее: {outgoing}")
                logger.debug(f"load_chat:   Статус: {status}")

                tag_name = f"msg_{msg_idx}"

                # Настройка тега для сообщения
                self.chat_display.tag_config(tag_name, spacing1=2, spacing3=2,
                                           lmargin1=5, lmargin2=5, rmargin=5)

                if outgoing:
                    status_tag = f"status_{tag_name}"
                    status_symbol = self.get_status_symbol(status)
                    status_color = self.get_status_color(status)

                    self.chat_display.tag_config(status_tag, foreground=status_color,
                                               lmargin1=5, rmargin=5)

                    self.chat_display.insert(tk.END, f"{status_symbol} ", status_tag)

                    if message_id:
                        self.message_status[message_id] = {'status': status, 'tag': status_tag}

                header = f"[{timestamp}] {sender if not outgoing else 'Вы'}: "
                self.chat_display.insert(tk.END, header, tag_name)

                if text:
                    self.chat_display.insert(tk.END, f"{text}", tag_name)

                if file_info:
                    file_tag = f"file_{tag_name}"
                    size_str = self.format_file_size(file_info.get('size', 0))
                    file_text = f"\n{file_info['name']} ({size_str})"

                    self.chat_display.insert(tk.END, file_text, file_tag)
                    self.chat_display.tag_config(file_tag, foreground="blue", underline=True)

                    if not outgoing:
                        self.chat_display.tag_bind(file_tag, '<Button-1>',
                            lambda e, fn=file_info['name'], mid=message_id:
                            self.save_decrypted_file(fn, mid))

                self.chat_display.insert(tk.END, "\n\n")

            logger.debug(f"load_chat: Загрузка завершена, всего обработано {messages_count} сообщений")
        else:
            logger.debug(f"load_chat: Нет сообщений для активного чата или чат не выбран")

        self.chat_display.config(state='disabled')
        self.chat_display.yview(tk.END)
        logger.debug(f"load_chat: Чат отображен")
    
    def receive_messages(self):
        logger.debug(f"receive_messages: Начало потока приема сообщений")
        buffer = ""
        
        while self.connected:
            try:
                data = self.client_socket.recv(65536)
                if not data:
                    logger.debug(f"receive_messages: Получены пустые данные, отключение")
                    break
                
                logger.debug(f"receive_messages: Получено {len(data)} байт")
                
                try:
                    decoded_data = data.decode('utf-8')
                except UnicodeDecodeError:
                    logger.error(f"receive_messages: Некорректная кодировка данных, пропускаем")
                    continue
                
                buffer += decoded_data
                logger.debug(f"receive_messages: Буфер после добавления: {len(buffer)} символов")
                
                # Обрабатываем все полные JSON-сообщения в буфере
                while True:
                    start_idx = buffer.find('{')
                    if start_idx == -1:
                        buffer = ""
                        break
                    
                    balance = 0
                    end_idx = -1
                    
                    for i in range(start_idx, len(buffer)):
                        char = buffer[i]
                        if char == '{':
                            balance += 1
                        elif char == '}':
                            balance -= 1
                            if balance == 0:
                                end_idx = i
                                break
                    
                    if end_idx == -1:
                        break
                    
                    json_str = buffer[start_idx:end_idx+1]
                    logger.debug(f"receive_messages: Извлечен JSON: {json_str[:200]}...")
                    
                    try:
                        message = json.loads(json_str)
                        logger.debug(f"receive_messages: Успешный парсинг JSON, тип: {message.get('type')}")
                        self.process_server_message(message)
                    except json.JSONDecodeError as e:
                        logger.error(f"receive_messages: Ошибка парсинга JSON: {e}")
                        logger.debug(f"receive_messages: Проблемная строка: {json_str}")
                    
                    buffer = buffer[end_idx+1:].lstrip()
                    logger.debug(f"receive_messages: Буфер очищен, осталось: {len(buffer)} символов")
                    
            except socket.timeout:
                continue
            except Exception as e:
                logger.error(f"receive_messages: Ошибка приема сообщений: {e}")
                break
        
        self.connected = False
        self.status_label.config(text="❌ Отключен")
        logger.warning(f"receive_messages: Поток приема сообщений завершен")
    
    def process_server_message(self, message):
        msg_type = message.get('type')
        logger.debug(f"process_server_message: Обработка сообщения типа '{msg_type}'")
        
        if msg_type == 'pong':
            logger.debug(f"process_server_message: Получен pong")
            return
            
        elif msg_type == 'all_users':
            users = message.get('users', [])
            self.all_users = users
            logger.debug(f"process_server_message: Получен список всех пользователей: {len(users)} пользователей")
            
        elif msg_type == 'search_results':
            results = message.get('results', [])
            search_term = message.get('search_term', '')
            
            logger.debug(f"process_server_message: Результаты поиска для '{search_term}': {len(results)} результатов")
            
            self.show_search_results(results, search_term)
            
        elif msg_type == 'key_response':
            username = message.get('username')
            public_key_pem = message.get('public_key')
            is_online = message.get('online', False)
            
            logger.debug(f"process_server_message: Получен ключ для {username}, онлайн: {is_online}")
            
            if username and public_key_pem:
                try:
                    public_key = serialization.load_pem_public_key(
                        public_key_pem.encode('utf-8'),
                        backend=default_backend()
                    )
                    self.contacts[username] = {
                        'public_key': public_key,
                        'verified': False,
                        'online': is_online
                    }
                    
                    logger.debug(f"process_server_message: Ключ загружен для {username}, всего контактов: {len(self.contacts)}")
                    
                    if self.active_chat == username:
                        logger.debug(f"process_server_message: Активный чат совпадает, обновление статуса верификации")
                        self.root.after(0, self.update_verification_status)
                        
                except Exception as e:
                    logger.error(f"process_server_message: Ошибка загрузки ключа для {username}: {e}")
                    
        elif msg_type == 'message':
            logger.debug(f"process_server_message: Получено новое сообщение")
            self.root.after(0, lambda: self.process_incoming_message(message))
            
        elif msg_type == 'typing':
            from_user = message.get('from')
            is_typing = message.get('is_typing', False)
            
            logger.debug(f"process_server_message: Тайпинг от {from_user}: {is_typing}")
            
            if from_user == self.active_chat:
                if is_typing:
                    self.typing_label.config(text=f"{from_user} печатает...")
                    logger.debug(f"process_server_message: Установлена метка тайпинга для {from_user}")
                else:
                    self.typing_label.config(text="")
                    logger.debug(f"process_server_message: Метка тайпинга очищена")
                    
        elif msg_type == 'delivery_status':
            message_id = message.get('message_id')
            status = message.get('status')
            
            logger.debug(f"process_server_message: Статус доставки для сообщения {message_id}: {status}")
            
            if message_id:
                self.root.after(0, lambda: self.update_message_status(message_id, status))
                
        elif msg_type == 'read_receipt':
            message_id = message.get('message_id')
            logger.debug(f"process_server_message: Read receipt для сообщения {message_id}")
            
            if message_id:
                self.root.after(0, lambda: self.update_message_status(message_id, 'read'))
                
        elif msg_type == 'error':
            error_msg = message.get('message', '')
            if error_msg:
                logger.error(f"process_server_message: Ошибка от сервера: {error_msg}")
                self.root.after(0, lambda: messagebox.showerror("Ошибка", error_msg))
                
        elif msg_type == 'register_ok':
            logger.debug(f"process_server_message: Регистрация/авторизация успешна")
            
        elif msg_type == 'disconnect':
            disconnect_msg = message.get('message', '')
            logger.warning(f"process_server_message: Отключение от сервера: {disconnect_msg}")
            self.connected = False
            self.status_label.config(text="Отключен")
            
        else:
            logger.warning(f"process_server_message: Неизвестный тип сообщения: {msg_type}")
    
    def show_search_results(self, results, search_term):
        logger.debug(f"show_search_results: Отображение результатов поиска: {len(results)} результатов")
        
        if hasattr(self, 'results_listbox'):
            self.results_listbox.delete(0, tk.END)
            logger.debug(f"show_search_results: Очистка списка результатов")
            
            if not results:
                logger.debug(f"show_search_results: Нет результатов, добавление заглушки")
                self.results_listbox.insert(tk.END, "Пользователи не найдены")
                return
            
            for user in results:
                username = user.get('username')
                online = user.get('online', False)
                status = "🟢 Онлайн" if online else "Оффлайн"
                display_text = f"{username} - {status}"
                self.results_listbox.insert(tk.END, display_text)
                logger.debug(f"show_search_results: Добавлен результат: {display_text}")
        else:
            logger.warning(f"show_search_results: results_listbox не существует")

    def process_incoming_message(self, message):
        from_user = message.get('from')
        encrypted_msg = message.get('message')
        encrypted_session_key = message.get('session_key')
        message_id = message.get('message_id')

        logger.debug(f"process_incoming_message: Обработка входящего сообщения")
        logger.debug(f"process_incoming_message: От: {from_user}, ID: {message_id}")

        try:
            logger.debug(f"process_incoming_message: Дешифрование сессионного ключа")
            session_key = self.private_key.decrypt(
                base64.b64decode(encrypted_session_key),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            logger.debug(f"process_incoming_message: Дешифрование содержимого сообщения")
            cipher = Fernet(base64.urlsafe_b64encode(session_key))
            decrypted_data = cipher.decrypt(base64.b64decode(encrypted_msg))

            message_data = json.loads(decrypted_data.decode('utf-8'))

            text = message_data.get('text', '')
            has_file = message_data.get('has_file', False)
            file_info = message_data.get('file_info')
            file_content_encrypted = file_info.get('content') if file_info else None
            sender = message_data.get('sender', from_user)

            logger.debug(f"process_incoming_message: Данные сообщения:")
            logger.debug(f"  Текст: '{text[:50]}...'")
            logger.debug(f"  Отправитель: {sender}")
            logger.debug(f"  Есть файл: {has_file}")

            # Увеличиваем счетчик непрочитанных, если чат не активен
            if self.active_chat != from_user:
                current_count = self.unread_counts.get(from_user, 0)
                self.unread_counts[from_user] = current_count + 1
                logger.debug(f"process_incoming_message: Увеличен счетчик непрочитанных для {from_user}: {current_count + 1}")

            if has_file and file_info and file_content_encrypted:
                logger.debug(f"process_incoming_message: Обработка прикрепленного файла")
                encrypted_content = base64.b64decode(file_content_encrypted)
                encrypted_session_key_data = base64.b64decode(file_info.get('encrypted_session_key'))

                file_session_key = self.private_key.decrypt(
                    encrypted_session_key_data,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )

                logger.debug(f"process_incoming_message: Ключ файла дешифрован")

                self.file_storage[message_id] = {
                    'encrypted_content': encrypted_content,
                    'session_key': file_session_key
                }

                logger.debug(f"process_incoming_message: Файл сохранен в хранилище под ID {message_id}")

                file_info['size'] = file_info.get('size', 0)

            # Проверяем, есть ли уже этот контакт в списке
            contacts_list = self.contacts_listbox.get(0, tk.END)
            found = False
            for i in range(self.contacts_listbox.size()):
                item = self.contacts_listbox.get(i)
                item_username = self.get_username_from_display(item)
                if item_username == from_user:
                    found = True
                    break

            if not found:
                logger.debug(f"process_incoming_message: Добавление нового контакта: {from_user}")
                # Показываем счетчик непрочитанных
                unread_count = self.unread_counts.get(from_user, 0)
                display_name = f"{from_user} ({unread_count})" if unread_count > 0 else from_user
                self.contacts_listbox.insert(tk.END, display_name)

            if self.active_chat == from_user:
                logger.debug(f"process_incoming_message: Активный чат совпадает, отображение сообщения")
                
                # Помечаем как прочитанное (так как чат активен)
                message_status = 'read'

                self.add_message_to_chat(
                    sender,
                    text,
                    outgoing=False,
                    message_id=message_id,
                    status=message_status,
                    file_info={
                        'name': file_info.get('name') if file_info else None,
                        'size': file_info.get('size') if file_info else 0
                    } if has_file else None
                )

                # Отправляем статус прочтения
                self.send_delivery_status(message_id, 'read')

                # Сбрасываем счетчик непрочитанных для активного чата
                if from_user in self.unread_counts:
                    del self.unread_counts[from_user]
                    self.load_history_contacts()

            else:
                logger.debug(f"process_incoming_message: Активный чат не совпадает, сохранение в историю")
                if from_user not in self.messages:
                    self.messages[from_user] = []

                # Для неактивного чата сообщение не прочитано
                msg_record = {
                    'from': sender,
                    'text': text,
                    'timestamp': message_data.get('timestamp'),
                    'outgoing': False,
                    'id': message_id,
                    'has_file': has_file,
                    'status': 'delivered',  # Только доставлено
                    'read': False  # Не прочитано
                }

                if has_file and file_info:
                    msg_record['file_info'] = file_info

                self.messages[from_user].append(msg_record)
                logger.debug(f"process_incoming_message: Сообщение сохранено в историю")

                # Обновляем список контактов с учетом счетчика
                self.load_history_contacts()

                # Отправляем статус доставки
                self.send_delivery_status(message_id, 'delivered', from_user)

                #self.save_messages_delayed()

        except Exception as e:
            logger.error(f"process_incoming_message: Ошибка обработки сообщения {message_id}: {e}")
    
    def send_delivery_status(self, message_id, status, recipient=None):
        logger.debug(f"send_delivery_status: Отправка статуса {status} для сообщения {message_id}")
        
        if not self.connected:
            logger.warning(f"send_delivery_status: Нет подключения, статус не отправлен")
            return
        
        if not recipient:
            recipient = self.active_chat
            logger.debug(f"send_delivery_status: Получатель не указан, используем активный чат: {recipient}")
        
        if not recipient:
            logger.warning(f"send_delivery_status: Не указан получатель статуса")
            return
        
        data = {
            'type': 'delivery_status',
            'message_id': message_id,
            'status': status,
            'to': recipient
        }
        
        logger.debug(f"send_delivery_status: Данные для отправки: {data}")
        
        try:
            self.client_socket.send(json.dumps(data).encode('utf-8'))
            logger.info(f"send_delivery_status: Статус {status} для сообщения {message_id} отправлен получателю {recipient}")
        except Exception as e:
            logger.error(f"send_delivery_status: Ошибка отправки статуса: {e}")
    
    def load_messages(self):
        logger.debug(f"load_messages: Загрузка сообщений из файла")
        
        try:
            if os.path.exists("messages.dat"):
                with open("messages.dat", "rb") as f:
                    messages = pickle.load(f)
                    logger.debug(f"load_messages: Сообщения загружены, ключи: {list(messages.keys())}")
                    return messages
            else:
                logger.debug(f"load_messages: Файл messages.dat не найден")
        except Exception as e:
            logger.error(f"load_messages: Ошибка загрузки сообщений: {e}")
        
        return {}
    
    def save_messages_delayed(self):
        logger.debug(f"save_messages_delayed: Отложенное сохранение сообщений")
        
        if self.save_timer:
            self.root.after_cancel(self.save_timer)
            logger.debug(f"save_messages_delayed: Предыдущий таймер отменен")
        
        self.save_timer = self.root.after(5000, self.save_messages)
        logger.debug(f"save_messages_delayed: Новый таймер установлен")
    
    def save_messages(self):
        logger.debug(f"save_messages: Сохранение сообщений в файл")
        logger.debug(f"save_messages: Количество диалогов: {len(self.messages)}")
        
        for user, msgs in self.messages.items():
            logger.debug(f"save_messages:   {user}: {len(msgs)} сообщений")
        
        try:
            with open("messages.dat", "wb") as f:
                pickle.dump(self.messages, f)
            logger.debug(f"save_messages: Сообщения успешно сохранены")
        except Exception as e:
            logger.error(f"save_messages: Ошибка сохранения сообщений: {e}")
    
    def on_closing(self):
        logger.debug(f"on_closing: Закрытие приложения")
        
        #self.save_messages()
        #logger.debug(f"on_closing: Сообщения сохранены")
        
        if self.client_socket:
            logger.debug(f"on_closing: Закрытие сокета клиента")
            self.client_socket.close()
        
        if self.search_dialog:
            logger.debug(f"on_closing: Закрытие диалога поиска")
            self.search_dialog.destroy()
        
        self.root.destroy()
        logger.debug(f"on_closing: Приложение закрыто")
    
    def run(self):
        logger.debug(f"run: Запуск главного цикла приложения")
        self.root.mainloop()

if __name__ == "__main__":
    app = SecureMessengerClient()
    app.run()
