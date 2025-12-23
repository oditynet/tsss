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
import secrets
import string
import re

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
        self.root.geometry("1200x800")
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        # Скрываем главное окно до подключения
       # self.root.withdraw()
        self.root.deiconify()

        # Значения по умолчанию
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
        self.active_chat_type = None  # 'private' или 'group'
        self.messages = self.load_messages()
        self.all_users = []

        # Групповые чаты
        self.group_chats = self.load_group_chats()  # group_id -> {name, members, admin, symmetric_key}
        self.group_messages = self.load_group_messages()  # group_id -> [messages]

        self.typing_status = {}
        self.typing_timers = {}

        self.message_status = {}

        self.save_timer = None
        self.typing_timeout = None

        self.attached_file = None
        self.attached_filename = None

        self.message_counter = 0

        self.file_storage = {}

        # Счетчики непрочитанных сообщений
        self.unread_counts = {}
        self.group_unread_counts = {}

        # Состояние поиска
        self.is_search_mode = False
        self.original_contacts = []

        # Текущая вкладка
        self.current_tab = "private"

        # Состояние создания группы
        self.creating_group = False
        self.selected_for_group = set()

        logger.debug(f"__init__: Инициализация клиента")

        self.setup_ui()
        self.show_connection_dialog()

    def show_connection_dialog(self):
        """Диалог для ввода IP и порта сервера"""
        logger.debug(f"show_connection_dialog: Показ диалога подключения")
        
        self.conn_dialog = tk.Toplevel(self.root)
        self.conn_dialog.title("Подключение к серверу")
        self.conn_dialog.geometry("400x200")
        self.conn_dialog.transient(self.root)
        self.conn_dialog.grab_set()
        
        # Центрирование диалога
        self.conn_dialog.geometry("+{}+{}".format(
            self.root.winfo_rootx() + 50,
            self.root.winfo_rooty() + 50
        ))
        
        # Запрет закрытия через крестик
        self.conn_dialog.protocol("WM_DELETE_WINDOW", lambda: None)
        
        main_frame = ttk.Frame(self.conn_dialog, padding=20)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(main_frame, text="Настройки подключения", 
                 font=('Arial', 12, 'bold')).pack(pady=(0, 20))
        
        # Поле для IP адреса
        ip_frame = ttk.Frame(main_frame)
        ip_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(ip_frame, text="IP адрес сервера:", width=20).pack(side=tk.LEFT)
        self.server_host_var = tk.StringVar(value=self.server_host)
        self.server_host_entry = ttk.Entry(ip_frame, textvariable=self.server_host_var, width=25)
        self.server_host_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # Поле для порта
        port_frame = ttk.Frame(main_frame)
        port_frame.pack(fill=tk.X, pady=(0, 20))
        
        ttk.Label(port_frame, text="Порт сервера:", width=20).pack(side=tk.LEFT)
        self.server_port_var = tk.StringVar(value=str(self.server_port))
        self.server_port_entry = ttk.Entry(port_frame, textvariable=self.server_port_var, width=25)
        self.server_port_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # Кнопки
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill=tk.X)
        
        connect_btn = ttk.Button(btn_frame, text="Подключиться", 
                                command=self.connect_from_dialog)
        connect_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        exit_btn = ttk.Button(btn_frame, text="Выход", 
                             command=self.exit_app)
        exit_btn.pack(side=tk.LEFT)
        
        # Бинд Enter на подключение
        self.server_port_entry.bind('<Return>', lambda e: self.connect_from_dialog())
        self.server_host_entry.focus_set()

    def safe_send(self, data, max_retries=3, retry_delay=0.5):
        """
        Безопасная отправка данных с повторными попытками
        """
        if not self.connected or not self.client_socket:
            logger.warning(f"safe_send: Нет подключения, отправка невозможна")
            return False

        for attempt in range(max_retries):
            try:
                # Сохраняем оригинальный таймаут
                original_timeout = self.client_socket.gettimeout()

                # Устанавливаем таймаут для отправки
                self.client_socket.settimeout(5.0)

                # Отправляем данные
                sent = self.client_socket.send(data)

                # Восстанавливаем таймаут
                self.client_socket.settimeout(original_timeout)

                if sent == len(data):
                    logger.debug(f"safe_send: Данные успешно отправлены, попытка {attempt + 1}")
                    return True
                else:
                    logger.warning(f"safe_send: Отправлены не все данные: {sent}/{len(data)} байт")

            except socket.timeout:
                logger.warning(f"safe_send: Таймаут отправки, попытка {attempt + 1}/{max_retries}")

            except socket.error as e:
                if e.errno == socket.errno.EWOULDBLOCK or e.errno == socket.errno.EAGAIN:
                    logger.debug(f"safe_send: Сокет заблокирован, попытка {attempt + 1}/{max_retries}")
                elif e.errno == socket.errno.ECONNRESET:
                    logger.error(f"safe_send: Соединение разорвано сервером")
                    self.connected = False
                    self.status_label.config(text="Отключен")
                    return False
                else:
                    logger.error(f"safe_send: Ошибка сокета: {e}")

            except BrokenPipeError:
                logger.error(f"safe_send: Соединение разорвано (Broken Pipe)")
                self.connected = False
                self.status_label.config(text="Отключен")
                return False

            except Exception as e:
                logger.error(f"safe_send: Неизвестная ошибка: {e}")

            # Задержка перед следующей попыткой (экспоненциальная)
            if attempt < max_retries - 1:
                delay = retry_delay * (2 ** attempt)  # 0.5, 1.0, 2.0 секунды
                logger.debug(f"safe_send: Ожидание {delay:.1f}с перед повторной попыткой")
                time.sleep(delay)

        logger.error(f"safe_send: Не удалось отправить данные после {max_retries} попыток")
        return False
    
    def connect_from_dialog(self):
        """Подключение к серверу с введенными параметрами"""
        logger.debug(f"connect_from_dialog: Подключение с параметрами из диалога")
        
        host = self.server_host_var.get().strip()
        port_str = self.server_port_var.get().strip()
        
        if not host:
            messagebox.showerror("Ошибка", "Введите IP адрес сервера")
            return
        
        if not port_str:
            messagebox.showerror("Ошибка", "Введите порт сервера")
            return
        
        try:
            port = int(port_str)
            if port < 1 or port > 65535:
                raise ValueError
        except ValueError:
            messagebox.showerror("Ошибка", "Порт должен быть числом от 1 до 65535")
            return
        
        self.server_host = host
        self.server_port = port
        
        # Пробуем подключиться к серверу
        if self.test_server_connection():
            self.conn_dialog.destroy()
            self.load_or_register()
        else:
            messagebox.showerror("Ошибка", 
                "Не удалось подключиться к серверу.\n"
                "Проверьте правильность IP адреса и порта.")
    
    def test_server_connection(self):
        """Тестовое подключение к серверу"""
        logger.debug(f"test_server_connection: Тест подключения к {self.server_host}:{self.server_port}")
        
        test_socket = None
        try:
            test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_socket.settimeout(3.0)
            test_socket.connect((self.server_host, self.server_port))
            test_socket.close()
            logger.debug(f"test_server_connection: Подключение успешно")
            return True
        except Exception as e:
            logger.error(f"test_server_connection: Ошибка подключения: {e}")
            if test_socket:
                try:
                    test_socket.close()
                except:
                    pass
            return False
    
    def exit_app(self):
        """Выход из приложения"""
        logger.debug(f"exit_app: Выход из приложения")
        self.root.destroy()

    def setup_ui(self):
        logger.debug(f"setup_ui: Настройка пользовательского интерфейса")

        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Левая панель - вкладки и списки
        left_panel = ttk.Frame(main_frame, width=250)
        left_panel.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 10))
        left_panel.pack_propagate(False)

        # Профиль пользователя
        profile_frame = ttk.LabelFrame(left_panel, text="Мой профиль", padding=10)
        profile_frame.pack(fill=tk.X, pady=(0, 10))

        self.profile_label = ttk.Label(profile_frame, text="", font=('Arial', 12, 'bold'))
        self.profile_label.pack(anchor=tk.W)

        # Кнопка создания группового чата
        self.create_group_btn = ttk.Button(profile_frame, text="Создать группу",
                                          command=self.show_group_creation_dialog,
                                          state='disabled')
        self.create_group_btn.pack(fill=tk.X, pady=(5, 0))

        # Вкладки
        self.tab_control = ttk.Notebook(left_panel)
        self.tab_control.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

        # Вкладка личных чатов
        self.private_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.private_tab, text='Личные чаты')

        # Вкладка групповых чатов
        self.group_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.group_tab, text='Групповые чаты')

        self.tab_control.bind('<<NotebookTabChanged>>', self.on_tab_changed)

        # Контейнер для личных чатов
        private_container = ttk.Frame(self.private_tab)
        private_container.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Поле поиска для личных чатов
        private_search_frame = ttk.Frame(private_container)
        private_search_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(private_search_frame, text="Поиск:").pack(anchor=tk.W, pady=(0, 5))

        self.private_search_var = tk.StringVar()
        self.private_search_entry = ttk.Entry(private_search_frame,
                                            textvariable=self.private_search_var,
                                            width=20)
        self.private_search_entry.pack(fill=tk.X)
        self.private_search_entry.bind('<KeyRelease>',
                                      lambda e: self.search_private_contacts())

        # Список личных контактов
        self.private_listbox = tk.Listbox(
            private_container,
            height=25,
            font=('Arial', 10),
            selectbackground='#007ACC',
            selectforeground='white',
            bg='white',
            relief='flat',
            highlightthickness=0
        )
        self.private_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        private_scrollbar = ttk.Scrollbar(private_container)
        private_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.private_listbox.config(yscrollcommand=private_scrollbar.set)
        private_scrollbar.config(command=self.private_listbox.yview)

        self.private_listbox.bind('<<ListboxSelect>>',
                                lambda e: self.on_private_contact_select())

        # Контейнер для групповых чатов
        group_container = ttk.Frame(self.group_tab)
        group_container.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Поиск для добавления в группу
        group_search_frame = ttk.Frame(group_container)
        group_search_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(group_search_frame, text="Поиск для добавления:").pack(anchor=tk.W, pady=(0, 5))

        self.group_search_var = tk.StringVar()
        self.group_search_entry = ttk.Entry(group_search_frame,
                                          textvariable=self.group_search_var,
                                          width=20)
        self.group_search_entry.pack(fill=tk.X)
        self.group_search_entry.bind('<KeyRelease>',
                                   lambda e: self.search_users_for_group())

        # Список результатов поиска для групп
        self.search_results_listbox = tk.Listbox(
            group_container,
            height=5,
            font=('Arial', 10),
            selectbackground='#28a745',
            selectforeground='white',
            bg='white',
            relief='flat',
            highlightthickness=0
        )
        self.search_results_listbox.pack(fill=tk.X, pady=(0, 10))

        search_scrollbar = ttk.Scrollbar(self.search_results_listbox)
        search_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.search_results_listbox.config(yscrollcommand=search_scrollbar.set)
        search_scrollbar.config(command=self.search_results_listbox.yview)

        self.search_results_listbox.bind('<<ListboxSelect>>',
                                       lambda e: self.on_user_selected_for_group())

        # Кнопка добавления в группу
        self.add_to_group_btn = ttk.Button(group_container,
                                         text="Добавить в группу",
                                         command=self.add_user_to_group,
                                         state='disabled')
        self.add_to_group_btn.pack(fill=tk.X, pady=(0, 10))

        # Список групповых чатов
        ttk.Label(group_container, text="Мои группы:",
                 font=('Arial', 10, 'bold')).pack(anchor=tk.W, pady=(5, 5))

        self.groups_listbox = tk.Listbox(
            group_container,
            height=15,
            font=('Arial', 10),
            selectbackground='#ffc107',
            selectforeground='black',
            bg='white',
            relief='flat',
            highlightthickness=0
        )
        self.groups_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        groups_scrollbar = ttk.Scrollbar(group_container)
        groups_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.groups_listbox.config(yscrollcommand=groups_scrollbar.set)
        groups_scrollbar.config(command=self.groups_listbox.yview)

        self.groups_listbox.bind('<<ListboxSelect>>',
                               lambda e: self.on_group_select())

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

        # Кнопка управления группой (для админа)
        self.group_manage_btn = ttk.Button(header_frame, text="Управление", width=12,
                                          command=self.show_group_management,
                                          state='disabled')
        self.group_manage_btn.pack(side=tk.RIGHT, padx=(0, 5))

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

        # Подсказка
        hint_frame = ttk.Frame(right_panel)
        hint_frame.pack(fill=tk.X, pady=(5, 0))

        hint_label = ttk.Label(hint_frame,
                              text="Enter - отправить | Ctrl+Enter или Shift+Enter - новая строка",
                              font=('Arial', 8),
                              foreground="gray",
                              justify=tk.LEFT)
        hint_label.pack(anchor=tk.W)

        logger.debug(f"setup_ui: Интерфейс настроен")

    def on_tab_changed(self, event):
        """Обработка смены вкладки"""
        selected_tab = self.tab_control.select()
        tab_text = self.tab_control.tab(selected_tab, "text")
        
        logger.debug(f"on_tab_changed: Переключение на вкладку: {tab_text}")
        
        if tab_text == "Личные чаты":
            self.current_tab = "private"
            self.create_group_btn.config(state='normal')
            self.group_manage_btn.config(state='disabled')
            self.load_private_contacts()
            self.add_to_group_btn.config(state='disabled')

        elif tab_text == "Групповые чаты":
            self.current_tab = "group"
            self.create_group_btn.config(state='normal')
            self.load_group_chats_list()

            # Очищаем поле поиска
            self.group_search_var.set("")
            self.search_results_listbox.delete(0, tk.END)
            self.add_to_group_btn.config(state='disabled')

            # Сбрасываем активный чат если он был личным
            if self.active_chat_type == 'private':
                self.active_chat = None
                self.active_chat_type = None
                self.chat_header.config(text="Выберите группу")
                self.chat_display.config(state='normal')
                self.chat_display.delete('1.0', tk.END)
                self.chat_display.config(state='disabled')
                self.message_entry.delete('1.0', tk.END)
                self.verify_status.config(text="")
                self.verify_btn.config(state='disabled')
                self.group_manage_btn.config(state='disabled')

        # Обновляем состояние кнопки создания группы
        if self.connected and self.username:
            self.create_group_btn.config(state='normal')
        else:
            self.create_group_btn.config(state='disabled')

    def search_private_contacts(self):
        """Поиск в личных контактах"""
        search_text = self.private_search_var.get().strip().lower()

        if not search_text:
            # Если поиск пустой, показываем обычные контакты
            self.load_private_contacts()
            return

        if not self.connected:
            messagebox.showerror("Ошибка", "Нет подключения к серверу")
            return

        # Отправляем запрос на поиск
        data = {
            'type': 'search',
            'username': search_text,
            'online_only': False
        }

        try:
            self.safe_send(json.dumps(data).encode('utf-8'))
            logger.debug(f"search_private_contacts: Запрос поиска отправлен")
        except Exception as e:
            logger.error(f"search_private_contacts: Ошибка отправки запроса поиска: {e}")

    def search_users_for_group(self):
        """Поиск пользователей для добавления в группу"""
        search_text = self.group_search_var.get().strip().lower()

        if not search_text:
            self.search_results_listbox.delete(0, tk.END)
            self.add_to_group_btn.config(state='disabled')
            return

        if not self.connected:
            messagebox.showerror("Ошибка", "Нет подключения к серверу")
            return

        # Отправляем запрос на поиск
        data = {
            'type': 'search',
            'username': search_text,
            'online_only': False
        }

        try:
            self.safe_send(json.dumps(data).encode('utf-8'))
            logger.debug(f"search_users_for_group: Запрос поиска отправлен")
        except Exception as e:
            logger.error(f"search_users_for_group: Ошибка отправки запроса поиска: {e}")

    def show_search_results_in_listbox(self, results, search_term):
        """Отображение результатов поиска в списке контактов"""
        logger.debug(f"show_search_results_in_listbox: Отображение результатов поиска в списке")

        # Для личного поиска
        if self.current_tab == 'private':
            self.is_search_mode = True

            # Сохраняем оригинальный список, если еще не сохранен
            if not self.original_contacts:
                self.original_contacts = list(self.private_listbox.get(0, tk.END))
                logger.debug(f"show_search_results_in_listbox: Сохранено оригинальных контактов: {len(self.original_contacts)}")

            # Очищаем список
            self.private_listbox.delete(0, tk.END)

            if not results:
                logger.debug(f"show_search_results_in_listbox: Нет результатов, добавление заглушки")
                self.private_listbox.insert(tk.END, f"По запросу '{search_term}' ничего не найдено")
                return

            logger.debug(f"show_search_results_in_listbox: Добавление {len(results)} результатов")

            for user in results:
                username = user.get('username')
                online = user.get('online', False)
                status = "🟢" if online else "⚫"
                display_text = f"{status} {username}"

                if username != self.username:
                    self.private_listbox.insert(tk.END, display_text)
                    logger.debug(f"show_search_results_in_listbox: Добавлен результат: {display_text}")

            if self.private_listbox.size() > 0:
                # Автоматически выбираем первый результат
                self.private_listbox.selection_set(0)
                self.private_listbox.activate(0)
                logger.debug(f"show_search_results_in_listbox: Автоматически выбран первый результат")

        # Для группового поиска
        else:
            self.search_results_listbox.delete(0, tk.END)

            if not results:
                self.search_results_listbox.insert(tk.END, f"По запросу '{search_term}' ничего не найдено")
                self.add_to_group_btn.config(state='disabled')
                return

            for user in results:
                username = user.get('username')
                online = user.get('online', False)
                status = "🟢" if online else "⚫"
                display_text = f"{status} {username}"

                if username != self.username:
                    self.search_results_listbox.insert(tk.END, display_text)
                    logger.debug(f"show_search_results_in_listbox: Добавлен результат для группы: {display_text}")

            self.add_to_group_btn.config(state='normal')

    def load_private_contacts(self):
        """Загрузка списка личных контактов"""
        logger.debug(f"load_private_contacts: Загрузка личных контактов")

        self.private_listbox.delete(0, tk.END)

        # Очищаем состояние поиска
        self.is_search_mode = False
        self.original_contacts = []

        for username in self.messages.keys():
            if username != self.username:
                unread_count = self.unread_counts.get(username, 0)
                display_name = f"{username} ({unread_count})" if unread_count > 0 else username
                self.private_listbox.insert(tk.END, display_name)

        if self.private_listbox.size() > 0:
            self.private_listbox.selection_set(0)
            self.private_listbox.activate(0)

    def on_private_contact_select(self):
        """Обработка выбора личного контакта"""
        selection = self.private_listbox.curselection()
        if not selection:
            return

        display_text = self.private_listbox.get(selection[0])

        # Извлекаем имя пользователя (без эмодзи)
        username = self.get_username_from_display(display_text)
        logger.debug(f"on_private_contact_select: Выбран контакт: {username} (оригинал: {display_text})")

        # Помечаем сообщения как прочитанные
        self.mark_messages_as_read(username)

        if username in self.unread_counts:
            del self.unread_counts[username]

        # Устанавливаем активный чат
        self.active_chat = username
        self.active_chat_type = 'private'
        self.chat_header.config(text=f"Чат с {username}")
        logger.debug(f"on_private_contact_select: Активный чат установлен: {self.active_chat}")

        # Загружаем историю чата
        self.load_chat()

        # Отправляем уведомления о прочтении
        self.send_read_receipts_for_unread(username)

        # Обновляем список контактов
        self.load_private_contacts()

        # Запрашиваем публичный ключ если его нет
        if username not in self.contacts:
            logger.debug(f"on_private_contact_select: Ключ для {username} не найден, запрос...")
            self.request_public_key(username)
        else:
            logger.debug(f"on_private_contact_select: Ключ для {username} уже загружен")
            self.update_verification_status()

        self.message_entry.focus_set()

    def get_username_from_display(self, display_text):
        """Извлекает имя пользователя из отображаемого текста"""
        # Убираем эмодзи и счетчик
        match = re.match(r'^[🟢⚫👑👥]\s+(.+?)(?:\s*\(\d+\))?$', display_text)
        if match:
            return match.group(1).strip()

        # Если нет эмодзи, убираем только счетчик
        match = re.match(r'^(.+?)(?:\s*\(\d+\))?$', display_text)
        if match:
            return match.group(1).strip()

        return display_text.strip()


    def load_or_register(self):
        logger.debug(f"load_or_register: Проверка существования пользователя")

        if os.path.exists("user_data.bin"):
            logger.debug(f"load_or_register: Файл пользователя найден, показ логина")
            self.show_login_dialog()
        else:
            logger.debug(f"load_or_register: Файл пользователя не найдена, показ регистрации")
            self.show_register_dialog()

    def show_register_dialog(self):
        logger.debug(f"show_register_dialog: Показ диалога регистрации")

        self.dialog = tk.Toplevel(self.root)
        self.dialog.title("Регистрация")
        self.dialog.geometry("350x300")
        self.dialog.transient(self.root)
        self.dialog.grab_set()

        # Центрирование
        self.dialog.geometry("+{}+{}".format(
            self.root.winfo_rootx() + 100,
            self.root.winfo_rooty() + 100
        ))

        main_frame = ttk.Frame(self.dialog, padding=20)
        main_frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(main_frame, text="Регистрация", font=('Arial', 12, 'bold')).pack(pady=(0, 15))

        # Поля ввода
        fields_frame = ttk.Frame(main_frame)
        fields_frame.pack(fill=tk.X)

        ttk.Label(fields_frame, text="Логин:").grid(row=0, column=0, sticky=tk.W, pady=(0, 5))
        self.reg_username = ttk.Entry(fields_frame, width=30)
        self.reg_username.grid(row=0, column=1, sticky=tk.W+tk.E, pady=(0, 5), padx=(10, 0))

        ttk.Label(fields_frame, text="Пароль:").grid(row=1, column=0, sticky=tk.W, pady=(0, 5))
        self.reg_password = ttk.Entry(fields_frame, width=30, show="*")
        self.reg_password.grid(row=1, column=1, sticky=tk.W+tk.E, pady=(0, 5), padx=(10, 0))

        ttk.Label(fields_frame, text="Повторите пароль:").grid(row=2, column=0, sticky=tk.W, pady=(0, 5))
        self.reg_password_confirm = ttk.Entry(fields_frame, width=30, show="*")
        self.reg_password_confirm.grid(row=2, column=1, sticky=tk.W+tk.E, pady=(0, 5), padx=(10, 0))

        # Кнопка регистрации
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(pady=(15, 0))

        reg_btn = ttk.Button(btn_frame, text="Зарегистрироваться", command=self.do_register)
        reg_btn.pack(side=tk.LEFT, padx=(0, 10))

        back_btn = ttk.Button(btn_frame, text="Назад", command=self.show_connection_dialog_from_reg)
        back_btn.pack(side=tk.LEFT)

        # Бинды на Enter
        self.reg_password_confirm.bind('<Return>', lambda e: self.do_register())
        self.reg_username.focus_set()

        fields_frame.columnconfigure(1, weight=1)

    def show_connection_dialog_from_reg(self):
        """Возврат к диалогу подключения из регистрации"""
        if self.dialog:
            self.dialog.destroy()
        self.show_connection_dialog()

    def show_login_dialog(self):
        logger.debug(f"show_login_dialog: Показ диалога входа")

        self.dialog = tk.Toplevel(self.root)
        self.dialog.title("Вход")
        self.dialog.geometry("300x250")
        self.dialog.transient(self.root)
        self.dialog.grab_set()

        # Центрирование
        self.dialog.geometry("+{}+{}".format(
            self.root.winfo_rootx() + 100,
            self.root.winfo_rooty() + 100
        ))

        main_frame = ttk.Frame(self.dialog, padding=20)
        main_frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(main_frame, text="Вход", font=('Arial', 12, 'bold')).pack(pady=(0, 15))

        # Поля ввода
        fields_frame = ttk.Frame(main_frame)
        fields_frame.pack(fill=tk.X)

        ttk.Label(fields_frame, text="Логин:").grid(row=0, column=0, sticky=tk.W, pady=(0, 10))
        self.login_username = ttk.Entry(fields_frame, width=30)
        self.login_username.grid(row=0, column=1, sticky=tk.W+tk.E, pady=(0, 10), padx=(10, 0))

        ttk.Label(fields_frame, text="Пароль:").grid(row=1, column=0, sticky=tk.W, pady=(0, 10))
        self.login_password = ttk.Entry(fields_frame, width=30, show="*")
        self.login_password.grid(row=1, column=1, sticky=tk.W+tk.E, pady=(0, 10), padx=(10, 0))

        # Кнопки
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(pady=(15, 0))

        login_btn = ttk.Button(btn_frame, text="Войти", command=self.do_login)
        login_btn.pack(side=tk.LEFT, padx=(0, 10))

        back_btn = ttk.Button(btn_frame, text="Назад", command=self.show_connection_dialog_from_login)
        back_btn.pack(side=tk.LEFT)

        # Бинды на Enter
        self.login_password.bind('<Return>', lambda e: self.do_login())
        self.login_username.focus_set()

        fields_frame.columnconfigure(1, weight=1)

    def show_connection_dialog_from_login(self):
        """Возврат к диалогу подключения из логина"""
        if self.dialog:
            self.dialog.destroy()
        self.show_connection_dialog()

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
            if self.send_public_key():
                self.dialog.destroy()
                self.root.deiconify()
                self.profile_label.config(text=f"{username}")
                self.load_private_contacts()
                logger.debug(f"do_register: Регистрация успешна для {username}")
            else:
                logger.error(f"do_register: Регистрация отклонена сервером")
        else:
            logger.error(f"do_register: Не удалось подключиться к серверу")
            messagebox.showerror("Ошибка", "Не удалось подключиться к серверу")

    def do_login(self):
        username = self.login_username.get().strip()
        password = self.login_password.get()

        logger.debug(f"do_login: Вход пользователя {username}")

        if self.load_keys(username, password):
            if self.connect_to_server():
                if self.send_public_key():
                    self.dialog.destroy()
                    self.root.deiconify()
                    self.profile_label.config(text=f"{username}")
                    self.load_private_contacts()
                    logger.debug(f"do_login: Вход успешен для {username}")
                else:
                    logger.error(f"do_login: Авторизация отклонена сервером")
            else:
                logger.error(f"do_login: Не удалось подключиться к серверу")
                messagebox.showerror("Ошибка", "Не удалось подключиться к серверу")
        else:
            logger.warning(f"do_login: Неверный логин или пароль")
            messagebox.showerror("Ошибка", "Неверный логин или пароль")

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
            self.safe_send(json.dumps(data).encode('utf-8'))
            logger.debug(f"send_ping: Ping отправлен")
        except Exception as e:
            logger.error(f"send_ping: Ошибка отправки ping: {e}")
            self.connected = False
            self.status_label.config(text="Отключен")

    def send_public_key(self):
        if not self.connected:
            logger.warning(f"send_public_key: Нет подключения, ключ не отправлен")
            return False

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
            return True
        except Exception as e:
            logger.error(f"send_public_key: Ошибка отправки ключа: {e}")
            self.connected = False
            self.status_label.config(text="Отключен")
            return False

    def send_read_receipts_for_unread(self, username):
        """Отправляет уведомления о прочтении для всех непрочитанных сообщений"""
        logger.debug(f"send_read_receipts_for_unread: Отправка уведомлений о прочтении для {username}")

        if not self.connected or not username:
            return

        if username in self.messages:
            unread_message_ids = []
            for msg in self.messages[username]:
                if (not msg.get('outgoing', False) and
                        msg.get('status') != 'read' and
                        msg.get('id')):
                    unread_message_ids.append(msg['id'])

            for message_id in unread_message_ids:
                data = {
                    'type': 'read_receipt',
                    'message_id': message_id,
                    'to': username
                }

                logger.debug(f"send_read_receipts_for_unread: Отправка read_receipt для сообщения {message_id}")

                try:
                    self.safe_send(json.dumps(data).encode('utf-8'))
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

    def request_public_key(self, username):
        # Извлекаем чистое имя пользователя (без эмодзи)
        clean_username = self.get_username_from_display(username)

        if not self.connected:
            logger.warning(f"request_public_key: Нет подключения, запрос ключа не отправлен")
            return

        data = {
            'type': 'get_key',
            'username': clean_username  # Отправляем только имя без эмодзи
        }

        logger.debug(f"request_public_key: Запрос ключа для {clean_username}")

        try:
            self.safe_send(json.dumps(data).encode('utf-8'))
            logger.debug(f"request_public_key: Запрос ключа отправлен")
        except Exception as e:
            logger.error(f"request_public_key: Ошибка отправки запроса ключа: {e}")

    def show_group_creation_dialog(self):
        """Показ диалога создания группы"""
        logger.debug(f"show_group_creation_dialog: Показ диалога создания группы")

        if not self.connected:
            messagebox.showerror("Ошибка", "Нет подключения к серверу")
            return

        dialog = tk.Toplevel(self.root)
        dialog.title("Создание группового чата")
        dialog.geometry("400x200")
        dialog.transient(self.root)
        dialog.grab_set()

        # Центрирование
        dialog.geometry("+{}+{}".format(
            self.root.winfo_rootx() + 200,
            self.root.winfo_rooty() + 150
        ))

        main_frame = ttk.Frame(dialog, padding=20)
        main_frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(main_frame, text="Создание группового чата",
                 font=('Arial', 12, 'bold')).pack(pady=(0, 15))

        # Название группы
        name_frame = ttk.Frame(main_frame)
        name_frame.pack(fill=tk.X, pady=(0, 15))

        ttk.Label(name_frame, text="Название группы:", width=15).pack(side=tk.LEFT)
        group_name_var = tk.StringVar()
        group_name_entry = ttk.Entry(name_frame, textvariable=group_name_var, width=30)
        group_name_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)

        # Кнопки
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill=tk.X)

        def create_group():
            group_name = group_name_var.get().strip()

            if not group_name:
                messagebox.showerror("Ошибка", "Введите название группы")
                return

            # Генерируем ID группы
            group_id = self.generate_group_id()

            # Генерируем симметричный ключ для группы
            group_key = Fernet.generate_key()

            # Сохраняем группу локально
            self.group_chats[group_id] = {
                'name': group_name,
                'members': [self.username],  # Только создатель
                'admin': self.username,
                'symmetric_key': group_key,
                'created_at': datetime.now().isoformat()
            }

            # Создаем запись для сообщений группы
            if group_id not in self.group_messages:
                self.group_messages[group_id] = []

            # Добавляем системное сообщение
            system_msg = {
                'sender': 'Система',
                'text': f'Группа "{group_name}" создана',
                'timestamp': datetime.now().isoformat(),
                'system': True
            }

            self.group_messages[group_id].append(system_msg)

            # Отправляем информацию о создании группы на сервер
            self.send_group_create_request(group_id, group_name, group_key)

            # Закрываем диалог
            dialog.destroy()

            # Добавляем группу в список
            self.load_group_chats_list()

            # Выбираем созданную группу
            for i in range(self.groups_listbox.size()):
                if self.groups_listbox.get(i).startswith(f"👑 {group_name}"):
                    self.groups_listbox.selection_set(i)
                    self.groups_listbox.activate(i)
                    self.root.after(100, lambda: self.on_group_select())
                    break

            logger.info(f"show_group_creation_dialog: Группа '{group_name}' создана с ID {group_id}")
            messagebox.showinfo("Успех", f"Группа '{group_name}' создана")

        create_btn = ttk.Button(btn_frame, text="Создать", command=create_group)
        create_btn.pack(side=tk.LEFT, padx=(0, 10))

        cancel_btn = ttk.Button(btn_frame, text="Отмена", command=dialog.destroy)
        cancel_btn.pack(side=tk.LEFT)

        # Бинд Enter на создание
        group_name_entry.bind('<Return>', lambda e: create_group())
        group_name_entry.focus_set()

    def generate_group_id(self):
        """Генерация уникального ID группы из 12 символов"""
        alphabet = string.ascii_letters + string.digits
        return ''.join(secrets.choice(alphabet) for _ in range(12))

    def send_group_create_request(self, group_id, group_name, group_key):
        """Отправка запроса на создание группы на сервер"""
        logger.debug(f"send_group_create_request: Отправка запроса создания группы {group_id}")

        # В этом упрощенном варианте создатель группы - единственный участник
        # Позже можно добавить других участников через кнопку "Добавить в группу"

        data = {
            'type': 'group_create',
            'group_id': group_id,
            'group_name': group_name,
            'admin': self.username,
            'members': [],  # Пустой список участников (кроме создателя)
            'encrypted_keys': {},  # Пустой словарь ключей
            'timestamp': datetime.now().isoformat()
        }

        try:
            self.safe_send(json.dumps(data).encode('utf-8'))
            logger.debug(f"send_group_create_request: Запрос создания группы отправлен")
        except Exception as e:
            logger.error(f"send_group_create_request: Ошибка отправки запроса: {e}")

    def load_group_chats(self):
        """Загрузка списка групповых чатов из файла"""
        logger.debug(f"load_group_chats: Загрузка групповых чатов")
        
        try:
            if os.path.exists("group_chats.dat"):
                with open("group_chats.dat", "rb") as f:
                    group_chats = pickle.load(f)
                    logger.debug(f"load_group_chats: Загружено {len(group_chats)} групп")
                    return group_chats
            else:
                logger.debug(f"load_group_chats: Файл group_chats.dat не найден")
        except Exception as e:
            logger.error(f"load_group_chats: Ошибка загрузки: {e}")
        
        return {}

    def load_group_messages(self):
        """Загрузка сообщений групповых чатов из файла"""
        logger.debug(f"load_group_messages: Загрузка групповых сообщений")
        
        try:
            if os.path.exists("group_messages.dat"):
                with open("group_messages.dat", "rb") as f:
                    group_messages = pickle.load(f)
                    logger.debug(f"load_group_messages: Загружено сообщений для {len(group_messages)} групп")
                    return group_messages
            else:
                logger.debug(f"load_group_messages: Файл group_messages.dat не найден")
        except Exception as e:
            logger.error(f"load_group_messages: Ошибка загрузки: {e}")
        
        return {}

    def save_group_chats(self):
        """Сохранение списка групповых чатов в файл"""
        logger.debug(f"save_group_chats: Сохранение {len(self.group_chats)} групп")
        
        try:
            with open("group_chats.dat", "wb") as f:
                pickle.dump(self.group_chats, f)
            logger.debug(f"save_group_chats: Групповые чаты сохранены")
        except Exception as e:
            logger.error(f"save_group_chats: Ошибка сохранения: {e}")

    def save_group_messages(self):
        """Сохранение сообщений групповых чатов в файл"""
        logger.debug(f"save_group_messages: Сохранение сообщений для {len(self.group_messages)} групп")
        
        try:
            with open("group_messages.dat", "wb") as f:
                pickle.dump(self.group_messages, f)
            logger.debug(f"save_group_messages: Сообщения групп сохранены")
        except Exception as e:
            logger.error(f"save_group_messages: Ошибка сохранения: {e}")

    def load_group_chats_list(self):
        """Загрузка списка групп в интерфейс"""
        logger.debug(f"load_group_chats_list: Загрузка списка групп")
        
        self.groups_listbox.delete(0, tk.END)
        
        for group_id, group_info in self.group_chats.items():
            group_name = group_info['name']
            unread_count = self.group_unread_counts.get(group_id, 0)
            
            # Добавляем эмодзи для админа
            prefix = "👑" if group_info['admin'] == self.username else "👥"
            
            display_text = f"{prefix} {group_name}"
            if unread_count > 0:
                display_text += f" ({unread_count})"
            
            self.groups_listbox.insert(tk.END, display_text)
            logger.debug(f"load_group_chats_list: Добавлена группа: {display_text}")
        
        if self.groups_listbox.size() > 0:
            self.groups_listbox.selection_set(0)
            self.groups_listbox.activate(0)

    def on_group_select(self):
        """Обработка выбора группы"""
        selection = self.groups_listbox.curselection()
        if not selection:
            return
        
        display_text = self.groups_listbox.get(selection[0])
        
        # Извлекаем название группы (убираем эмодзи и счетчик)
        match = re.match(r'^[👑👥]\s+(.+?)(?:\s+\(\d+\))?$', display_text)
        if not match:
            return
        
        group_name = match.group(1)
        
        # Находим ID группы по имени
        group_id = None
        for gid, info in self.group_chats.items():
            if info['name'] == group_name:
                group_id = gid
                break
        
        if not group_id:
            logger.warning(f"on_group_select: Группа с именем '{group_name}' не найдена")
            return
        
        logger.debug(f"on_group_select: Выбрана группа: {group_name} (ID: {group_id})")
        
        # Устанавливаем активный чат
        self.active_chat = group_id
        self.active_chat_type = 'group'
        
        # Обновляем заголовок
        admin_marker = " (Вы администратор)" if self.group_chats[group_id]['admin'] == self.username else ""
        self.chat_header.config(text=f"Группа: {group_name}{admin_marker}")
        
        # Показываем кнопку управления если мы админ
        if self.group_chats[group_id]['admin'] == self.username:
            self.group_manage_btn.config(state='normal')
        else:
            self.group_manage_btn.config(state='disabled')
        
        # Скрываем кнопки верификации для групп
        self.verify_status.config(text="")
        self.verify_btn.config(state='disabled')
        
        # Загружаем историю чата
        self.load_group_chat(group_id)
        
        # Сбрасываем счетчик непрочитанных
        if group_id in self.group_unread_counts:
            del self.group_unread_counts[group_id]
            self.load_group_chats_list()
        
        self.message_entry.focus_set()

    def load_group_chat(self, group_id):
        """Загрузка истории группового чата"""
        logger.debug(f"load_group_chat: Загрузка чата группы {group_id}")
        
        self.chat_display.config(state='normal')
        self.chat_display.delete('1.0', tk.END)
        
        if group_id in self.group_messages:
            messages = self.group_messages[group_id]
            logger.debug(f"load_group_chat: Загружено {len(messages)} сообщений")
            
            for msg in messages:
                sender = msg.get('sender', 'Неизвестно')
                text = msg.get('text', '')
                timestamp = msg.get('timestamp', '')
                is_system = msg.get('system', False)
                
                if timestamp:
                    try:
                        time_display = datetime.fromisoformat(timestamp).strftime("%H:%M")
                    except:
                        time_display = timestamp
                else:
                    time_display = ""
                
                if is_system:
                    # Системное сообщение
                    self.chat_display.insert(tk.END, f"[{time_display}] {text}\n", "system")
                    self.chat_display.tag_config("system", foreground="gray", font=('Arial', 9, 'italic'))
                else:
                    # Обычное сообщение
                    display_text = f"[{time_display}] {sender}: {text}\n"
                    self.chat_display.insert(tk.END, display_text)
                
                self.chat_display.insert(tk.END, "\n")
        
        self.chat_display.config(state='disabled')
        self.chat_display.yview(tk.END)

    def on_user_selected_for_group(self):
        """Обработка выбора пользователя для добавления в группу"""
        selection = self.search_results_listbox.curselection()
        if selection:
            self.add_to_group_btn.config(state='normal')
        else:
            self.add_to_group_btn.config(state='disabled')

    def add_user_to_group(self):
        """Добавление пользователя в активную группу"""
        selection = self.search_results_listbox.curselection()
        if not selection:
            return

        display_text = self.search_results_listbox.get(selection[0])

        # Извлекаем имя пользователя
        match = re.match(r'^[🟢⚫]\s+(.+)$', display_text)
        if not match:
            username = display_text
        else:
            username = match.group(1)

        if not self.active_chat or self.active_chat_type != 'group':
            messagebox.showwarning("Ошибка", "Выберите группу для добавления пользователя")
            return

        group_id = self.active_chat
        group_info = self.group_chats.get(group_id)

        if not group_info:
            logger.error(f"add_user_to_group: Группа {group_id} не найдена")
            return

        if group_info['admin'] != self.username:
            messagebox.showwarning("Ошибка", "Только администратор может добавлять участников")
            return

        if username in group_info['members']:
            messagebox.showinfo("Информация", "Пользователь уже в группе")
            return

        logger.debug(f"add_user_to_group: Добавление {username} в группу {group_id}")

        # Добавляем пользователя в группу
        group_info['members'].append(username)

        # Генерируем новый ключ для группы
        new_key = Fernet.generate_key()
        group_info['symmetric_key'] = new_key

        # Отправляем уведомление о добавлении и новый ключ
        self.send_group_member_added(group_id, username, new_key)

        # Добавляем системное сообщение
        system_msg = {
            'sender': 'Система',
            'text': f'Участник {username} добавлен в группу',
            'timestamp': datetime.now().isoformat(),
            'system': True
        }

        if group_id not in self.group_messages:
            self.group_messages[group_id] = []

        self.group_messages[group_id].append(system_msg)

        # Сохраняем изменения
        self.save_group_chats()
        self.save_group_messages()

        # Обновляем интерфейс
        self.load_group_chat(group_id)

        # Очищаем поле поиска
        self.group_search_var.set("")
        self.search_results_listbox.delete(0, tk.END)
        self.add_to_group_btn.config(state='disabled')

        messagebox.showinfo("Успех", f"Пользователь {username} добавлен в группу")
        logger.info(f"add_user_to_group: Пользователь {username} добавлен в группу {group_id}")

    def send_group_member_added(self, group_id, new_member, new_key):
        """Отправка уведомления о добавлении участника и нового ключа"""
        logger.debug(f"send_group_member_added: Отправка нового ключа для группы {group_id}")

        group_info = self.group_chats[group_id]
        encrypted_keys = {}

        # Шифруем новый ключ для всех участников (включая нового)
        for member in group_info['members']:
            if member in self.contacts:
                recipient_key = self.contacts[member]['public_key']
                try:
                    encrypted_key = recipient_key.encrypt(
                        new_key,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )
                    encrypted_keys[member] = base64.b64encode(encrypted_key).decode('utf-8')
                except Exception as e:
                    logger.error(f"send_group_member_added: Ошибка шифрования для {member}: {e}")

        data = {
            'type': 'group_member_added',
            'group_id': group_id,
            'new_member': new_member,
            'admin': self.username,
            'encrypted_keys': encrypted_keys,
            'timestamp': datetime.now().isoformat()
        }

        try:
            self.safe_send(json.dumps(data).encode('utf-8'))
            logger.debug(f"send_group_member_added: Уведомление о добавлении отправлено")
        except Exception as e:
            logger.error(f"send_group_member_added: Ошибка отправки: {e}")

    def show_group_management(self):
        """Показ диалога управления группой"""
        if not self.active_chat or self.active_chat_type != 'group':
            return
        
        group_id = self.active_chat
        group_info = self.group_chats.get(group_id)
        
        if not group_info or group_info['admin'] != self.username:
            messagebox.showwarning("Ошибка", "Вы не администратор этой группы")
            return
        
        logger.debug(f"show_group_management: Управление группой {group_id}")
        
        dialog = tk.Toplevel(self.root)
        dialog.title(f"Управление группой: {group_info['name']}")
        dialog.geometry("400x300")
        dialog.transient(self.root)
        
        main_frame = ttk.Frame(dialog, padding=20)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(main_frame, text=f"Управление группой: {group_info['name']}", 
                 font=('Arial', 11, 'bold')).pack(pady=(0, 15))
        
        # Список участников
        members_frame = ttk.LabelFrame(main_frame, text="Участники", padding=10)
        members_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 15))
        
        members_listbox = tk.Listbox(
            members_frame,
            font=('Arial', 10),
            bg='white'
        )
        members_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        scrollbar = ttk.Scrollbar(members_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        members_listbox.config(yscrollcommand=scrollbar.set)
        scrollbar.config(command=members_listbox.yview)
        
        for member in group_info['members']:
            if member == self.username:
                members_listbox.insert(tk.END, f"{member} (Вы)")
            else:
                members_listbox.insert(tk.END, member)
        
        # Кнопка удаления участника
        def remove_member():
            selection = members_listbox.curselection()
            if not selection:
                return
            
            selected_member = members_listbox.get(selection[0])
            # Убираем "(Вы)" из текста если есть
            if "(Вы)" in selected_member:
                selected_member = selected_member.replace(" (Вы)", "")
            
            if selected_member == self.username:
                messagebox.showinfo("Информация", "Нельзя удалить себя из группы")
                return
            
            if messagebox.askyesno("Подтверждение", 
                                 f"Удалить участника {selected_member} из группы?"):
                self.remove_member_from_group(group_id, selected_member)
                dialog.destroy()
        
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill=tk.X)
        
        remove_btn = ttk.Button(btn_frame, text="Удалить участника", 
                               command=remove_member)
        remove_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        close_btn = ttk.Button(btn_frame, text="Закрыть", 
                              command=dialog.destroy)
        close_btn.pack(side=tk.LEFT)

    def remove_member_from_group(self, group_id, member_username):
        """Удаление участника из группы"""
        logger.debug(f"remove_member_from_group: Удаление {member_username} из группы {group_id}")
        
        if group_id not in self.group_chats:
            logger.error(f"remove_member_from_group: Группа {group_id} не найдена")
            return
        
        group_info = self.group_chats[group_id]
        
        if member_username not in group_info['members']:
            logger.warning(f"remove_member_from_group: Участник {member_username} не в группе")
            return
        
        # Удаляем участника из списка
        group_info['members'].remove(member_username)
        
        # Генерируем новый ключ
        new_key = Fernet.generate_key()
        group_info['symmetric_key'] = new_key
        
        # Отправляем уведомление об удалении
        self.send_group_member_removed(group_id, member_username, new_key)
        
        # Добавляем системное сообщение
        system_msg = {
            'sender': 'Система',
            'text': f'Участник {member_username} удален из группы',
            'timestamp': datetime.now().isoformat(),
            'system': True
        }
        
        if group_id not in self.group_messages:
            self.group_messages[group_id] = []
        
        self.group_messages[group_id].append(system_msg)
        
        # Сохраняем изменения
        self.save_group_chats()
        self.save_group_messages()
        
        # Обновляем интерфейс если эта группа активна
        if self.active_chat == group_id:
            self.load_group_chat(group_id)
        
        logger.info(f"remove_member_from_group: Участник {member_username} удален из группы {group_id}")

    def send_group_member_removed(self, group_id, removed_member, new_key):
        """Отправка уведомления об удалении участника и нового ключа"""
        logger.debug(f"send_group_member_removed: Отправка нового ключа для группы {group_id}")
        
        group_info = self.group_chats[group_id]
        encrypted_keys = {}
        
        # Шифруем новый ключ для оставшихся участников
        for member in group_info['members']:
            if member != removed_member and member in self.contacts:
                recipient_key = self.contacts[member]['public_key']
                try:
                    encrypted_key = recipient_key.encrypt(
                        new_key,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )
                    encrypted_keys[member] = base64.b64encode(encrypted_key).decode('utf-8')
                except Exception as e:
                    logger.error(f"send_group_member_removed: Ошибка шифрования для {member}: {e}")
        
        data = {
            'type': 'group_member_removed',
            'group_id': group_id,
            'removed_member': removed_member,
            'admin': self.username,
            'encrypted_keys': encrypted_keys,
            'timestamp': datetime.now().isoformat()
        }
        
        try:
            self.safe_send(json.dumps(data).encode('utf-8'))
            logger.debug(f"send_group_member_removed: Уведомление об удалении отправлено")
        except Exception as e:
            logger.error(f"send_group_member_removed: Ошибка отправки: {e}")

    def send_message(self):
        """Отправка сообщения (личного или группового)"""
        logger.debug(f"send_message: Начало отправки сообщения")
        logger.debug(f"send_message: Тип чата: {self.active_chat_type}, ID: {self.active_chat}")

        if not self.active_chat or not self.connected:
            messagebox.showwarning("Ошибка", "Выберите чат для общения")
            return

        message_text = self.message_entry.get("1.0", tk.END).strip()

        if not message_text and not self.attached_file:
            return

        if self.active_chat_type == 'private':
            # Отправка личного сообщения
            self.send_private_message()
        elif self.active_chat_type == 'group':
            # Отправка группового сообщения
            self.send_group_message(message_text)
        else:
            logger.warning(f"send_message: Неизвестный тип чата: {self.active_chat_type}")

    def send_private_message(self):
        """Отправка личного сообщения"""
        if not self.active_chat or not self.connected:
            logger.warning(f"send_private_message: Нет активного чата или подключения")
            messagebox.showwarning("Ошибка", "Выберите контакт для общения")
            return

        message_text = self.message_entry.get("1.0", tk.END).strip()
        logger.debug(f"send_private_message: Текст сообщения: '{message_text[:50]}...'")
        logger.debug(f"send_private_message: Прикрепленный файл: {self.attached_file}")

        if not message_text and not self.attached_file:
            logger.warning(f"send_private_message: Пустое сообщение и нет файла")
            return

        if self.active_chat not in self.contacts:
            logger.warning(f"send_private_message: Ключ для {self.active_chat} не найден")
            messagebox.showwarning("Ожидание", "Ожидаем получение ключа собеседника")
            self.request_public_key(self.active_chat)
            return

        try:
            recipient_key = self.contacts[self.active_chat]['public_key']
            logger.debug(f"send_private_message: Ключ получателя получен: {type(recipient_key)}")

            message_id = f"{int(time.time() * 1000)}_{hashlib.md5(os.urandom(16)).hexdigest()[:8]}"
            logger.debug(f"send_private_message: Сгенерирован ID сообщения: {message_id}")

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
                logger.debug(f"send_private_message: Обработка прикрепленного файла: {self.attached_file}")
                try:
                    with open(self.attached_file, 'rb') as f:
                        file_content = f.read()

                    logger.debug(f"send_private_message: Файл прочитан, размер: {len(file_content)} байт")

                    file_session_key = os.urandom(32)
                    file_cipher = Fernet(base64.urlsafe_b64encode(file_session_key))
                    file_content_encrypted = file_cipher.encrypt(file_content)

                    logger.debug(f"send_private_message: Файл зашифрован, размер: {len(file_content_encrypted)} байт")

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

                    message_data['file_info']['content'] = base64.b64encode(
                        file_content_encrypted
                    ).decode('utf-8')

                    logger.debug(f"send_private_message: Информация о файле добавлена в сообщение")

                except Exception as e:
                    logger.error(f"send_private_message: Ошибка обработки файла: {e}")
                    messagebox.showerror("Ошибка", f"Не удалось прочитать файл: {str(e)}")
                    return

            session_key = os.urandom(32)
            cipher = Fernet(base64.urlsafe_b64encode(session_key))
            logger.debug(f"send_private_message: Сгенерирован сессионный ключ для сообщения")

            json_data = json.dumps(message_data, ensure_ascii=False)
            logger.debug(f"send_private_message: JSON данные сообщения: {json_data[:100]}...")

            encrypted_message = cipher.encrypt(json_data.encode('utf-8'))
            logger.debug(f"send_private_message: Сообщение зашифровано, размер: {len(encrypted_message)} байт")

            encrypted_session_key = recipient_key.encrypt(
                session_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            logger.debug(f"send_private_message: Сессионный ключ зашифрован публичным ключом получателя")

            data = {
                'type': 'message',
                'to': self.active_chat,
                'message': base64.b64encode(encrypted_message).decode('utf-8'),
                'session_key': base64.b64encode(encrypted_session_key).decode('utf-8'),
                'message_id': message_id,
                'timestamp': datetime.now().isoformat()
            }

            logger.debug(f"send_private_message: Подготовлены данные для отправки:")
            logger.debug(f"  Тип: {data['type']}")
            logger.debug(f"  Кому: {data['to']}")
            logger.debug(f"  ID сообщения: {data['message_id']}")
            logger.debug(f"  Длина зашифрованного сообщения: {len(data['message'])}")
            logger.debug(f"  Длина зашифрованного ключа: {len(data['session_key'])}")

            logger.debug(f"send_private_message: Отправка сообщения на сервер")
            self.safe_send(json.dumps(data).encode('utf-8'))
            logger.info(f"send_private_message: Сообщение {message_id} отправлено на сервер")

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
                logger.debug(f"send_private_message: Файл сохранен в хранилище под ID: {message_id}")

            self.message_entry.delete("1.0", tk.END)
            self.clear_attachment()
            logger.debug(f"send_private_message: Поля очищены")

        except Exception as e:
            logger.error(f"send_private_message: Ошибка отправки сообщения: {e}")
            messagebox.showerror("Ошибка", f"Не удалось отправить сообщение: {str(e)}")

    def send_group_message(self, message_text):
        """Отправка сообщения в группу"""
        group_id = self.active_chat

        if group_id not in self.group_chats:
            logger.error(f"send_group_message: Группа {group_id} не найдена")
            return

        group_info = self.group_chats[group_id]

        # Шифруем сообщение симметричным ключом группы
        try:
            cipher = Fernet(group_info['symmetric_key'])
            encrypted_message = cipher.encrypt(message_text.encode('utf-8'))

            message_id = f"{int(time.time() * 1000)}_{hashlib.md5(os.urandom(16)).hexdigest()[:8]}"

            data = {
                'type': 'group_message',
                'group_id': group_id,
                'message': base64.b64encode(encrypted_message).decode('utf-8'),
                'sender': self.username,
                'message_id': message_id,
                'timestamp': datetime.now().isoformat()
            }

            logger.debug(f"send_group_message: Отправка группового сообщения: {data['message_id']}")

            self.safe_send(json.dumps(data).encode('utf-8'))

            # Добавляем сообщение в локальную историю
            msg_record = {
                'sender': self.username,
                'text': message_text,
                'timestamp': data['timestamp'],
                'message_id': message_id
            }

            if group_id not in self.group_messages:
                self.group_messages[group_id] = []

            self.group_messages[group_id].append(msg_record)

            # Отображаем в чате
            self.load_group_chat(group_id)

            self.message_entry.delete("1.0", tk.END)
            self.clear_attachment()

            # Сохраняем сообщения
            self.save_group_messages()

            logger.info(f"send_group_message: Сообщение {message_id} отправлено в группу {group_id}")

        except Exception as e:
            logger.error(f"send_group_message: Ошибка отправки группового сообщения: {e}")
            messagebox.showerror("Ошибка", f"Не удалось отправить сообщение: {str(e)}")

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
        if not self.active_chat or self.active_chat_type != 'private' or self.active_chat not in self.contacts:
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

        if not self.active_chat or self.active_chat_type != 'private' or self.active_chat not in self.contacts:
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
        if not self.active_chat or not self.connected or self.active_chat_type != 'private':
            logger.debug(f"on_typing: Нет активного чата или подключения")
            return

        data = {
            'type': 'typing',
            'to': self.active_chat,
            'is_typing': True
        }

        logger.debug(f"on_typing: Отправка статуса печатания: {data}")

        try:
            self.safe_send(json.dumps(data).encode('utf-8'))
            logger.debug(f"on_typing: Статус печатания отправлен")
        except Exception as e:
            logger.error(f"on_typing: Ошибка отправки статуса печатания: {e}")

        if self.typing_timeout:
            self.root.after_cancel(self.typing_timeout)

        self.typing_timeout = self.root.after(2000, self.stop_typing)

    def stop_typing(self):
        if not self.active_chat or not self.connected or self.active_chat_type != 'private':
            return

        data = {
            'type': 'typing',
            'to': self.active_chat,
            'is_typing': False
        }

        logger.debug(f"stop_typing: Отправка статуса остановки печатания: {data}")

        try:
            self.safe_send(json.dumps(data).encode('utf-8'))
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
            MAX_FILE_SIZE = 512 * 1024 * 1024  # 512 МБ

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

    def add_message_to_chat(self, sender, text, outgoing=False, message_id=None,
                           status='sent', file_info=None):
        logger.debug(f"add_message_to_chat: Добавление сообщения в чат")
        logger.debug(f"add_message_to_chat: Параметры: sender={sender}, text='{text[:50]}...', outgoing={outgoing}, message_id={message_id}, status={status}, file_info={file_info}")
        logger.debug(f"add_message_to_chat: Активный чат: {self.active_chat}")

        if self.active_chat_type != 'private':
            logger.warning(f"add_message_to_chat: Не личный чат, сообщение не добавлено")
            return

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

        if message_id in self.message_status:
            logger.debug(f"update_message_status: Найдено в message_status")
            self.message_status[message_id]['status'] = status

        if self.active_chat and self.active_chat_type == 'private':
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
        else:
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

        if self.active_chat and self.active_chat_type == 'private' and self.active_chat in self.messages:
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
        """Обработка сообщений от сервера (расширенная для групп)"""
        msg_type = message.get('type')
        logger.debug(f"process_server_message: Обработка сообщения типа '{msg_type}'")

        # Обработка новых типов сообщений для групп
        if msg_type == 'group_create':
            self.handle_group_create(message)
        elif msg_type == 'group_invite':
            self.handle_group_invite(message)
        elif msg_type == 'group_message':
            self.handle_group_message(message)
        elif msg_type == 'group_member_added':
            self.handle_group_member_added(message)
        elif msg_type == 'group_member_removed':
            self.handle_group_member_removed(message)
        elif msg_type == 'group_create_ok':
            logger.debug(f"process_server_message: Группа создана успешно")
        else:
            # Обработка старых типов сообщений
            self.process_legacy_server_message(message)

    def process_legacy_server_message(self, message):
        """Обработка старых типов сообщений от сервера"""
        msg_type = message.get('type')
        logger.debug(f"process_legacy_server_message: Обработка сообщения типа '{msg_type}'")

        if msg_type == 'pong':
            logger.debug(f"process_legacy_server_message: Получен pong")
            return

        elif msg_type == 'all_users':
            users = message.get('users', [])
            self.all_users = users
            logger.debug(f"process_legacy_server_message: Получен список всех пользователей: {len(users)} пользователей")

        elif msg_type == 'search_results':
            results = message.get('results', [])
            search_term = message.get('search_term', '')

            logger.debug(f"process_legacy_server_message: Результаты поиска для '{search_term}': {len(results)} результатов")

            # Отображаем результаты в списке контактов
            self.root.after(0, lambda: self.show_search_results_in_listbox(results, search_term))

        elif msg_type == 'key_response':
            username = message.get('username')
            public_key_pem = message.get('public_key')
            is_online = message.get('online', False)

            logger.debug(f"process_legacy_server_message: Получен ключ для {username}, онлайн: {is_online}")

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

                    logger.debug(f"process_legacy_server_message: Ключ загружен для {username}, всего контактов: {len(self.contacts)}")

                    if self.active_chat == username and self.active_chat_type == 'private':
                        logger.debug(f"process_legacy_server_message: Активный чат совпадает, обновление статуса верификации")
                        self.root.after(0, self.update_verification_status)

                except Exception as e:
                    logger.error(f"process_legacy_server_message: Ошибка загрузки ключа для {username}: {e}")

        elif msg_type == 'message':
            logger.debug(f"process_legacy_server_message: Получено новое сообщение")
            self.root.after(0, lambda: self.process_incoming_message(message))

        elif msg_type == 'typing':
            from_user = message.get('from')
            is_typing = message.get('is_typing', False)

            logger.debug(f"process_legacy_server_message: Тайпинг от {from_user}: {is_typing}")

            if from_user == self.active_chat and self.active_chat_type == 'private':
                if is_typing:
                    self.typing_label.config(text=f"{from_user} печатает...")
                    logger.debug(f"process_legacy_server_message: Установлена метка тайпинга для {from_user}")
                else:
                    self.typing_label.config(text="")
                    logger.debug(f"process_legacy_server_message: Метка тайпинга очищена")

        elif msg_type == 'delivery_status':
            message_id = message.get('message_id')
            status = message.get('status')

            logger.debug(f"process_legacy_server_message: Статус доставки для сообщения {message_id}: {status}")

            if message_id:
                self.root.after(0, lambda: self.update_message_status(message_id, status))

        elif msg_type == 'read_receipt':
            message_id = message.get('message_id')
            logger.debug(f"process_legacy_server_message: Read receipt для сообщения {message_id}")

            if message_id:
                self.root.after(0, lambda: self.update_message_status(message_id, 'read'))

        elif msg_type == 'error':
            error_msg = message.get('message', '')
            if error_msg:
                logger.error(f"process_legacy_server_message: Ошибка от сервера: {error_msg}")
                self.root.after(0, lambda: messagebox.showerror("Ошибка", error_msg))

        elif msg_type == 'register_ok':
            logger.debug(f"process_legacy_server_message: Регистрация/авторизация успешна")

        elif msg_type == 'register_denied':
            error_msg = message.get('message', 'Регистрация/авторизация отклонена')
            logger.error(f"process_legacy_server_message: Регистрация/авторизация отклонена: {error_msg}")
            if os.path.exists("user_data.bin"):
                os.remove("user_data.bin")
            self.root.after(0, lambda: self.handle_registration_denied(error_msg))

        elif msg_type == 'disconnect':
            disconnect_msg = message.get('message', '')
            logger.warning(f"process_legacy_server_message: Отключение от сервера: {disconnect_msg}")
            self.connected = False
            self.status_label.config(text="Отключен")

        else:
            logger.warning(f"process_legacy_server_message: Неизвестный тип сообщения: {msg_type}")

    def handle_group_create(self, message):
        """Обработка приглашения в группу"""
        logger.debug(f"handle_group_create: Обработка создания/приглашения в группу")

        group_id = message.get('group_id')
        group_name = message.get('group_name')
        admin = message.get('admin')
        encrypted_key = message.get('encrypted_key')

        if not group_id or not encrypted_key:
            logger.warning(f"handle_group_create: Неполные данные для создания группы")
            return

        # Расшифровываем ключ группы
        try:
            encrypted_key_data = base64.b64decode(encrypted_key)
            group_key = self.private_key.decrypt(
                encrypted_key_data,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            logger.debug(f"handle_group_create: Ключ группы расшифрован")

            # Сохраняем информацию о группе
            self.group_chats[group_id] = {
                'name': group_name or f"Группа {group_id[:8]}",
                'members': [],  # Будет заполнено позже
                'admin': admin,
                'symmetric_key': group_key,
                'received_at': datetime.now().isoformat()
            }

            # Создаем запись для сообщений
            if group_id not in self.group_messages:
                self.group_messages[group_id] = []

            # Добавляем системное сообщение
            system_msg = {
                'sender': 'Система',
                'text': f'Вы добавлены в группу "{self.group_chats[group_id]["name"]}"',
                'timestamp': datetime.now().isoformat(),
                'system': True
            }

            self.group_messages[group_id].append(system_msg)

            # Сохраняем изменения
            self.save_group_chats()
            self.save_group_messages()

            # Обновляем интерфейс если мы на вкладке групп
            if self.current_tab == 'group':
                self.load_group_chats_list()

            logger.info(f"handle_group_create: Добавлена новая группа {group_id}")

            # Показываем уведомление
            self.root.after(0, lambda: messagebox.showinfo(
                "Новая группа",
                f'Вы добавлены в группу "{self.group_chats[group_id]["name"]}"'
            ))

        except Exception as e:
            logger.error(f"handle_group_create: Ошибка обработки приглашения в группу: {e}")

    def handle_group_invite(self, message):
        """Обработка приглашения в группу (альтернативное название)"""
        self.handle_group_create(message)

    def handle_group_message(self, message):
        """Обработка входящего группового сообщения"""
        group_id = message.get('group_id')
        sender = message.get('sender')
        encrypted_msg = message.get('message')
        message_id = message.get('message_id')
        timestamp = message.get('timestamp')

        logger.debug(f"handle_group_message: Получено сообщение для группы {group_id} от {sender}")

        if group_id not in self.group_chats:
            logger.warning(f"handle_group_message: Группа {group_id} не найдена")
            return

        # Расшифровываем сообщение
        try:
            group_info = self.group_chats[group_id]
            cipher = Fernet(group_info['symmetric_key'])

            encrypted_data = base64.b64decode(encrypted_msg)
            decrypted_text = cipher.decrypt(encrypted_data).decode('utf-8')

            logger.debug(f"handle_group_message: Сообщение расшифровано: '{decrypted_text[:50]}...'")

            # Сохраняем сообщение
            msg_record = {
                'sender': sender,
                'text': decrypted_text,
                'timestamp': timestamp,
                'message_id': message_id
            }

            if group_id not in self.group_messages:
                self.group_messages[group_id] = []

            self.group_messages[group_id].append(msg_record)

            # Увеличиваем счетчик непрочитанных если группа не активна
            if self.active_chat != group_id or self.current_tab != 'group':
                current_count = self.group_unread_counts.get(group_id, 0)
                self.group_unread_counts[group_id] = current_count + 1
                logger.debug(f"handle_group_message: Непрочитанных для группы {group_id}: {current_count + 1}")

            # Обновляем интерфейс если группа активна
            if self.active_chat == group_id and self.current_tab == 'group':
                self.load_group_chat(group_id)
                # Сбрасываем счетчик
                if group_id in self.group_unread_counts:
                    del self.group_unread_counts[group_id]
                    self.load_group_chats_list()
            else:
                # Обновляем список групп
                self.load_group_chats_list()

            # Сохраняем сообщения
            self.save_group_messages()

            logger.info(f"handle_group_message: Сообщение {message_id} сохранено для группы {group_id}")

        except Exception as e:
            logger.error(f"handle_group_message: Ошибка обработки группового сообщения: {e}")

    def handle_group_member_added(self, message):
        """Обработка добавления участника в группу"""
        group_id = message.get('group_id')
        new_member = message.get('new_member')  # Теперь это реальное имя
        admin = message.get('admin')
        encrypted_key = message.get('encrypted_key')

        logger.debug(f"handle_group_member_added: Обработка добавления участника в группу {group_id}")
        logger.debug(f"handle_group_member_added: Новый участник: {new_member}")

        if group_id not in self.group_chats:
            logger.warning(f"handle_group_member_added: Группа {group_id} не найдена")

            # Если группа не найдена, это может быть приглашение НАМ
            if new_member == self.username:
                logger.debug(f"handle_group_member_added: Это приглашение для нас!")
                # Расшифровываем ключ и создаем группу
                try:
                    encrypted_key_data = base64.b64decode(encrypted_key)
                    group_key = self.private_key.decrypt(
                        encrypted_key_data,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )

                    # Получаем имя группы (может прийти в сообщении или использовать дефолтное)
                    group_name = message.get('group_name', f"Группа {group_id[:8]}")

                    # Создаем новую группу
                    self.group_chats[group_id] = {
                        'name': group_name,
                        'members': [self.username, admin],  # Мы и администратор
                        'admin': admin,
                        'symmetric_key': group_key,
                        'created_at': datetime.now().isoformat()
                    }

                    # Создаем запись для сообщений
                    if group_id not in self.group_messages:
                        self.group_messages[group_id] = []

                    # Добавляем системное сообщение
                    system_msg = {
                        'sender': 'Система',
                        'text': f'Вы добавлены в группу "{group_name}" администратором {admin}',
                        'timestamp': datetime.now().isoformat(),
                        'system': True
                    }

                    self.group_messages[group_id].append(system_msg)

                    # Сохраняем изменения
                    self.save_group_chats()
                    self.save_group_messages()

                    # Обновляем интерфейс если мы на вкладке групп
                    if self.current_tab == 'group':
                        self.load_group_chats_list()

                    logger.info(f"handle_group_member_added: Создана новая группа {group_id}")

                    # Показываем уведомление
                    self.root.after(0, lambda: messagebox.showinfo(
                        "Новая группа",
                        f'Вы добавлены в группу "{group_name}"'
                    ))

                    return
                except Exception as e:
                    logger.error(f"handle_group_member_added: Ошибка создания группы: {e}")
                    return
            return

    def handle_group_member_removed(self, message):
        """Обработка удаления участника из группы"""
        group_id = message.get('group_id')
        removed_member = message.get('removed_member')
        admin = message.get('admin')
        encrypted_key = message.get('encrypted_key')

        logger.debug(f"handle_group_member_removed: Обработка удаления участника из группы {group_id}")

        if group_id not in self.group_chats:
            logger.warning(f"handle_group_member_removed: Группа {group_id} не найдена")
            return

        # Если это мы удалены
        if removed_member == self.username:
            # Удаляем группу
            del self.group_chats[group_id]
            if group_id in self.group_messages:
                del self.group_messages[group_id]

            # Сохраняем изменения
            self.save_group_chats()
            self.save_group_messages()

            # Обновляем интерфейс
            if self.current_tab == 'group':
                self.load_group_chats_list()

            # Если эта группа была активной, сбрасываем чат
            if self.active_chat == group_id:
                self.active_chat = None
                self.active_chat_type = None
                self.chat_header.config(text="Выберите группу")
                self.chat_display.config(state='normal')
                self.chat_display.delete('1.0', tk.END)
                self.chat_display.config(state='disabled')
                self.group_manage_btn.config(state='disabled')

            logger.info(f"handle_group_member_removed: Вы удалены из группы {group_id}")

            # Показываем уведомление
            self.root.after(0, lambda: messagebox.showinfo(
                "Информация",
                f"Вы удалены из группы {group_id}"
            ))

            return

        # Если удален другой участник
        try:
            # Расшифровываем новый ключ
            encrypted_key_data = base64.b64decode(encrypted_key)
            new_group_key = self.private_key.decrypt(
                encrypted_key_data,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            # Обновляем ключ
            self.group_chats[group_id]['symmetric_key'] = new_group_key

            # Удаляем участника из списка
            if removed_member in self.group_chats[group_id]['members']:
                self.group_chats[group_id]['members'].remove(removed_member)

            # Добавляем системное сообщение
            system_msg = {
                'sender': 'Система',
                'text': f'Участник {removed_member} удален из группы. Ключ обновлен.',
                'timestamp': datetime.now().isoformat(),
                'system': True
            }

            if group_id not in self.group_messages:
                self.group_messages[group_id] = []

            self.group_messages[group_id].append(system_msg)

            # Сохраняем изменения
            self.save_group_chats()
            self.save_group_messages()

            # Обновляем интерфейс если группа активна
            if self.active_chat == group_id and self.current_tab == 'group':
                self.load_group_chat(group_id)

            logger.info(f"handle_group_member_removed: Участник {removed_member} удален из группы {group_id}")

        except Exception as e:
            logger.error(f"handle_group_member_removed: Ошибка обработки: {e}")

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
            if self.active_chat != from_user or self.active_chat_type != 'private':
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
            contacts_list = self.private_listbox.get(0, tk.END)
            found = False
            for i in range(self.private_listbox.size()):
                item = self.private_listbox.get(i)
                item_username = self.get_username_from_display(item)
                if item_username == from_user:
                    found = True
                    break

            if not found:
                logger.debug(f"process_incoming_message: Добавление нового контакта: {from_user}")
                unread_count = self.unread_counts.get(from_user, 0)
                display_name = f"{from_user} ({unread_count})" if unread_count > 0 else from_user
                self.private_listbox.insert(tk.END, display_name)

            if self.active_chat == from_user and self.active_chat_type == 'private':
                logger.debug(f"process_incoming_message: Активный чат совпадает, отображение сообщения")

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

                self.send_delivery_status(message_id, 'read')

                if from_user in self.unread_counts:
                    del self.unread_counts[from_user]
                    self.load_private_contacts()

            else:
                logger.debug(f"process_incoming_message: Активный чат не совпадает, сохранение в историю")
                if from_user not in self.messages:
                    self.messages[from_user] = []

                msg_record = {
                    'from': sender,
                    'text': text,
                    'timestamp': message_data.get('timestamp'),
                    'outgoing': False,
                    'id': message_id,
                    'has_file': has_file,
                    'status': 'delivered',
                    'read': False
                }

                if has_file and file_info:
                    msg_record['file_info'] = file_info

                self.messages[from_user].append(msg_record)
                logger.debug(f"process_incoming_message: Сообщение сохранено в историю")

                self.load_private_contacts()

                self.send_delivery_status(message_id, 'delivered', from_user)

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
            self.safe_send(json.dumps(data).encode('utf-8'))
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

    def handle_registration_denied(self, error_msg):
        """Обработка отказа в регистрации/авторизации"""
        logger.debug(f"handle_registration_denied: Обработка отказа: {error_msg}")

        messagebox.showerror("Отказ в доступе", error_msg)

        # Закрываем соединение
        if self.client_socket:
            try:
                self.client_socket.close()
            except:
                pass

        self.connected = False
        self.status_label.config(text="Отключен")

        # Показываем диалог регистрации/логина заново
        self.load_or_register()

    def on_key_press(self, event):
        """Обработка нажатия клавиш в поле ввода"""
        logger.debug(f"on_key_press: Клавиша: {event.keysym}, состояние: {event.state}")

        # Enter без модификаторов - отправка
        if (event.keysym == 'Return' or event.keysym == 'KP_Enter') and not (event.state & 0x0004) and not (event.state & 0x0001):
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

    def on_closing(self):
        """Обработка закрытия приложения"""
        logger.debug(f"on_closing: Закрытие приложения")

        # Сохраняем все данные
        self.save_messages()
        self.save_group_chats()
        self.save_group_messages()

        if self.client_socket:
            logger.debug(f"on_closing: Закрытие сокета клиента")
            self.client_socket.close()

        self.root.destroy()
        logger.debug(f"on_closing: Приложение закрыто")

    def run(self):
        logger.debug(f"run: Запуск главного цикла приложения")
        self.root.mainloop()

if __name__ == "__main__":
    app = SecureMessengerClient()
    app.run()
