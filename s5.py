import socket
import threading
import json
import sqlite3
from datetime import datetime
import logging
import signal
import sys
import os
import base64

# Настраиваем максимально подробное логирование
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(threadName)s - %(message)s',
    handlers=[
        logging.FileHandler('server_debug.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class SecureMessengerServer:
    def __init__(self, host='0.0.0.0', port=5555):
        self.host = host
        self.port = port
        self.running = True
        
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.settimeout(1.0)
        
        self.clients = {}          # socket -> user info
        self.user_sockets = {}     # username -> socket
        self.public_keys = {}      # username -> public_key
        
        # Групповые чаты
        self.groups = {}           # group_id -> {name, members, admin}
        self.group_pending_keys = {}  # group_id -> {username: encrypted_key}
        
        self.clients_lock = threading.Lock()
        self.db_lock = threading.Lock()
        self.groups_lock = threading.Lock()
        
        self.init_database()
        
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
    
    def init_database(self):
        """Инициализация базы данных"""
        try:
            with self.db_lock:
                self.conn = sqlite3.connect('messenger.db', check_same_thread=False)
                self.conn.row_factory = sqlite3.Row
                cursor = self.conn.cursor()
                
                # Старые таблицы
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS users (
                        username TEXT PRIMARY KEY,
                        public_key TEXT NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS offline_messages (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        recipient TEXT NOT NULL,
                        sender TEXT NOT NULL,
                        message TEXT NOT NULL,
                        session_key TEXT NOT NULL,
                        message_id TEXT,
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                # Новые таблицы для групп
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS groups (
                        group_id TEXT PRIMARY KEY,
                        group_name TEXT NOT NULL,
                        admin TEXT NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS group_members (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        group_id TEXT NOT NULL,
                        username TEXT NOT NULL,
                        joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (group_id) REFERENCES groups(group_id) ON DELETE CASCADE,
                        UNIQUE(group_id, username)
                    )
                ''')
                
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS group_offline_messages (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        group_id TEXT NOT NULL,
                        sender TEXT NOT NULL,
                        message TEXT NOT NULL,
                        message_id TEXT,
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (group_id) REFERENCES groups(group_id) ON DELETE CASCADE
                    )
                ''')
                
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS group_pending_invites (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        group_id TEXT NOT NULL,
                        username TEXT NOT NULL,
                        encrypted_key TEXT NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (group_id) REFERENCES groups(group_id) ON DELETE CASCADE,
                        UNIQUE(group_id, username)
                    )
                ''')
                
                # Загружаем пользователей
                cursor.execute('SELECT username, public_key FROM users')
                rows = cursor.fetchall()
                for row in rows:
                    self.public_keys[row['username']] = row['public_key']
                
                # Загружаем группы
                cursor.execute('''
                    SELECT g.group_id, g.group_name, g.admin, 
                           GROUP_CONCAT(gm.username) as members
                    FROM groups g
                    LEFT JOIN group_members gm ON g.group_id = gm.group_id
                    GROUP BY g.group_id
                ''')
                
                group_rows = cursor.fetchall()
                for row in group_rows:
                    group_id = row['group_id']
                    members = row['members'].split(',') if row['members'] else []
                    
                    self.groups[group_id] = {
                        'name': row['group_name'],
                        'admin': row['admin'],
                        'members': members
                    }
                
                # Загружаем ожидающие приглашения
                cursor.execute('SELECT group_id, username, encrypted_key FROM group_pending_invites')
                invite_rows = cursor.fetchall()
                
                for row in invite_rows:
                    group_id = row['group_id']
                    username = row['username']
                    encrypted_key = row['encrypted_key']
                    
                    if group_id not in self.group_pending_keys:
                        self.group_pending_keys[group_id] = {}
                    
                    self.group_pending_keys[group_id][username] = encrypted_key
                
                self.conn.commit()
                logger.debug(f"init_database: Загружено {len(self.public_keys)} пользователей")
                logger.debug(f"init_database: Загружено {len(self.groups)} групп")
                logger.debug(f"init_database: Загружено {len(self.group_pending_keys)} ожидающих приглашений")
                
        except Exception as e:
            logger.error(f"Ошибка инициализации базы данных: {e}")
            raise
    
    def start(self):
        try:
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            
            logger.info(f"Сервер запущен на {self.host}:{self.port}")
            logger.debug(f"start: Server socket info: {self.server_socket}")
            
            while self.running:
                try:
                    client_socket, address = self.server_socket.accept()
                    client_socket.settimeout(5.0)
                    
                    logger.info(f"Новое подключение от {address}")
                    logger.debug(f"start: Client socket: {client_socket}, address: {address}")
                    
                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(client_socket, address),
                        daemon=True,
                        name=f"Client-{address}"
                    )
                    client_thread.start()
                    
                    logger.debug(f"start: Запущен поток для клиента {address}, активных потоков: {threading.active_count()}")
                    
                except socket.timeout:
                    continue
                except OSError as e:
                    if self.running:
                        logger.error(f"Ошибка accept: {e}")
                    break
                    
        except Exception as e:
            logger.error(f"Ошибка запуска сервера: {e}")
        finally:
            self.cleanup()
    
    def handle_client(self, client_socket, address):
        username = None
        client_id = f"{address}"
        
        logger.debug(f"handle_client: Начало обработки клиента {client_id}, socket: {client_socket}")
        
        try:
            while self.running:
                try:
                    data = client_socket.recv(65536)
                    if not data:
                        logger.debug(f"handle_client: Клиент {client_id} отключился (пустые данные)")
                        break
                    
                    logger.debug(f"handle_client: Получено {len(data)} байт от {client_id}")
                    
                    try:
                        message = json.loads(data.decode('utf-8'))
                        logger.debug(f"handle_client: JSON парсинг успешен, тип: {message.get('type')}")
                        self.process_message(client_socket, message, address)
                    except json.JSONDecodeError as e:
                        logger.warning(f"handle_client: Некорректный JSON от {address}: {str(e)}")
                        self.send_error(client_socket, "Некорректный формат сообщения")
                        
                except socket.timeout:
                    continue
                except ConnectionResetError:
                    logger.info(f"handle_client: Соединение разорвано: {address}")
                    break
                except Exception as e:
                    logger.error(f"handle_client: Ошибка чтения от {address}: {e}")
                    break
                    
        except Exception as e:
            logger.error(f"handle_client: Критическая ошибка в обработчике клиента {address}: {e}")
        finally:
            logger.debug(f"handle_client: Завершение обработки клиента {client_id}")
            self.disconnect_client(username, client_socket, address)
    
    def process_message(self, client_socket, message, address):
        msg_type = message.get('type')
        logger.debug(f"process_message: Обработка сообщения от {address}, тип: '{msg_type}'")
        
        # Проверяем обязательные поля для message
        if msg_type == 'message':
            required_fields = ['to', 'message', 'session_key', 'message_id']
            for field in required_fields:
                if field not in message or not message[field]:
                    logger.warning(f"process_message: Отсутствует обязательное поле '{field}' в сообщении")
                    self.send_error(client_socket, f"Отсутствует обязательное поле: {field}")
                    return
        
        handlers = {
            'register': self.handle_register,
            'search': self.handle_search,
            'get_key': self.handle_get_key,
            'get_all_users': self.handle_get_all_users,
            'message': self.handle_message,
            'typing': self.handle_typing,
            'delivery_status': self.handle_delivery_status,
            'read_receipt': self.handle_read_receipt,
            'ping': self.handle_ping,
            'group_create': self.handle_group_create,
            'group_message': self.handle_group_message,
            'group_member_added': self.handle_group_member_added,
            'group_member_removed': self.handle_group_member_removed,
        }
        
        handler = handlers.get(msg_type)
        if handler:
            logger.debug(f"process_message: Вызов обработчика для типа '{msg_type}'")
            handler(client_socket, message, address)
        else:
            logger.warning(f"process_message: Неизвестный тип сообщения от {address}: {msg_type}")
    
    def handle_ping(self, client_socket, message, address):
        """Обработка ping-сообщений"""
        logger.debug(f"handle_ping: Ping от {address}")
        try:
            self.send_json(client_socket, {'type': 'pong'})
            logger.debug(f"handle_ping: Pong отправлен {address}")
        except Exception as e:
            logger.error(f"handle_ping: Ошибка отправки pong: {e}")
    
    def handle_register(self, client_socket, message, address):
        """Регистрация пользователя с проверкой уникальности ключа и отправкой ожидающих приглашений"""
        username = message.get('username')
        public_key = message.get('public_key')
        
        logger.debug(f"handle_register: Регистрация пользователя {username} с {address}")
        logger.debug(f"handle_register: Длина публичного ключа: {len(public_key) if public_key else 0}")
        
        if not username or not isinstance(username, str) or len(username) > 50:
            logger.warning(f"handle_register: Неверное имя пользователя: {username}")
            self.send_error(client_socket, "Неверное имя пользователя")
            return
        
        if not public_key or not isinstance(public_key, str) or len(public_key) > 10000:
            logger.warning(f"handle_register: Неверный публичный ключ, длина: {len(public_key) if public_key else 0}")
            self.send_error(client_socket, "Неверный публичный ключ")
            return
        
        # Проверяем уникальность логина и ключа
        with self.db_lock:
            cursor = self.conn.cursor()
            
            # Проверяем, существует ли пользователь с таким логином
            cursor.execute('SELECT username FROM users WHERE username = ?', (username,))
            existing_user = cursor.fetchone()
            
            if existing_user:
                logger.warning(f"handle_register: Пользователь {username} уже существует")
                
                # Проверяем, совпадает ли ключ
                cursor.execute('SELECT public_key FROM users WHERE username = ?', (username,))
                existing_key_row = cursor.fetchone()
                
                if existing_key_row and existing_key_row['public_key'] == public_key:
                    logger.debug(f"handle_register: Ключ совпадает, разрешаем вход")
                    # Ключ совпадает - это тот же пользователь
                else:
                    logger.error(f"handle_register: Пользователь {username} уже существует с другим ключом")
                    self.send_json(client_socket, {
                        'type': 'register_denied',
                        'message': f'Пользователь "{username}" уже зарегистрирован с другим ключом'
                    })
                    return
            
            # Проверяем, не используется ли этот ключ другим пользователем
            cursor.execute('SELECT username FROM users WHERE public_key = ?', (public_key,))
            key_owner = cursor.fetchone()
            
            if key_owner and key_owner['username'] != username:
                logger.error(f"handle_register: Публичный ключ уже используется пользователем {key_owner['username']}")
                self.send_json(client_socket, {
                    'type': 'register_denied',
                    'message': f'Публичный ключ уже используется пользователем "{key_owner["username"]}"'
                })
                return
        
        with self.clients_lock:
            logger.debug(f"handle_register: Проверка существующего подключения для {username}")
            logger.debug(f"handle_register: Текущие онлайн пользователи: {list(self.user_sockets.keys())}")
            
            if username in self.user_sockets:
                old_socket = self.user_sockets[username]
                if old_socket != client_socket:
                    logger.info(f"handle_register: Пользователь {username} переподключается, отключаем старое соединение")
                    try:
                        self.send_json(old_socket, {
                            'type': 'disconnect',
                            'message': 'Вы подключены с другого устройства'
                        })
                        old_socket.close()
                        logger.debug(f"handle_register: Старый сокет закрыт для {username}")
                    except Exception as e:
                        logger.error(f"handle_register: Ошибка отключения старого клиента: {e}")
        
        try:
            with self.clients_lock:
                logger.debug(f"handle_register: Сохранение клиента в память")
                self.clients[client_socket] = {
                    'username': username,
                    'public_key': public_key,
                    'address': address,
                    'connected_at': datetime.now()
                }
                self.user_sockets[username] = client_socket
                self.public_keys[username] = public_key
                
                logger.debug(f"handle_register: Текущее состояние:")
                logger.debug(f"  clients: {len(self.clients)} записей")
                logger.debug(f"  user_sockets: {len(self.user_sockets)} записей: {list(self.user_sockets.keys())}")
                logger.debug(f"  public_keys: {len(self.public_keys)} записей: {list(self.public_keys.keys())}")
            
            with self.db_lock:
                cursor = self.conn.cursor()
                cursor.execute('''
                    INSERT OR REPLACE INTO users (username, public_key) 
                    VALUES (?, ?)
                ''', (username, public_key))
                self.conn.commit()
                logger.debug(f"handle_register: Пользователь {username} сохранен в БД")
            
            logger.info(f"handle_register: Пользователь {username} успешно зарегистрирован/авторизован с {address}")
            
            response = {
                'type': 'register_ok',
                'message': 'Регистрация/авторизация успешна',
                'username': username
            }
            self.send_json(client_socket, response)
            logger.debug(f"handle_register: Отправлен register_ok пользователю {username}")
            
            # Отправляем оффлайн сообщения и приглашения в группы
            self.send_offline_messages(username, client_socket)
            self.send_pending_group_invites(username, client_socket)
            
        except Exception as e:
            logger.error(f"handle_register: Ошибка регистрации пользователя {username}: {e}")
            with self.clients_lock:
                logger.debug(f"handle_register: Откат изменений в памяти из-за ошибки")
                if client_socket in self.clients:
                    del self.clients[client_socket]
                if username in self.user_sockets:
                    del self.user_sockets[username]
                if username in self.public_keys:
                    del self.public_keys[username]
            self.send_error(client_socket, f"Ошибка регистрации: {str(e)}")
    
    def send_pending_group_invites(self, username, client_socket):
        """Отправка ожидающих приглашений в группы - ИСПРАВЛЕННАЯ ВЕРСИЯ"""
        logger.debug(f"send_pending_group_invites: Проверка приглашений для {username}")

        try:
            with self.db_lock:
                cursor = self.conn.cursor()

                # Исправленный запрос - ищем приглашения для пользователя
                cursor.execute("""
                    SELECT gp.group_id, g.group_name, g.admin, gp.encrypted_key
                    FROM group_pending_invites gp
                    JOIN groups g ON gp.group_id = g.group_id
                    WHERE gp.username = ?
                """, (username,))

                pending_invites = cursor.fetchall()

                logger.debug(f"send_pending_group_invites: Найдено {len(pending_invites)} ожидающих приглашений")

                for invite in pending_invites:
                    group_id, group_name, admin, encrypted_key = invite

                    logger.debug(f"send_pending_group_invites: Отправка приглашения для группы {group_id}")

                    # Отправляем приглашение
                    self.send_group_invite(group_id, group_name, admin, username, encrypted_key)

                    # Удаляем приглашение из таблицы ожидания
                    cursor.execute("""
                        DELETE FROM group_pending_invites 
                        WHERE group_id = ? AND username = ?
                    """, (group_id, username))

                self.conn.commit()

        except Exception as e:
            logger.error(f"send_pending_group_invites: Ошибка отправки приглашений: {e}")

    
    def remove_pending_invite(self, group_id, username):
        """Удаление ожидающего приглашения"""
        try:
            with self.groups_lock:
                if group_id in self.group_pending_keys:
                    if username in self.group_pending_keys[group_id]:
                        del self.group_pending_keys[group_id][username]
                        if not self.group_pending_keys[group_id]:
                            del self.group_pending_keys[group_id]
            
            with self.db_lock:
                cursor = self.conn.cursor()
                cursor.execute('''
                    DELETE FROM group_pending_invites 
                    WHERE group_id = ? AND username = ?
                ''', (group_id, username))
                self.conn.commit()
                
            logger.debug(f"remove_pending_invite: Приглашение удалено для {username}")
            
        except Exception as e:
            logger.error(f"remove_pending_invite: Ошибка удаления приглашения: {e}")
    
    def handle_search(self, client_socket, message, address):
        """Обработка поиска пользователей"""
        search_term = message.get('username', '').strip().lower()
        search_online_only = message.get('online_only', False)
        
        logger.debug(f"handle_search: Запрос поиска от {address}")
        logger.debug(f"handle_search: Параметры: search_term='{search_term}', online_only={search_online_only}")
        
        if not search_term:
            logger.warning(f"handle_search: Пустой поисковый запрос")
            self.send_error(client_socket, "Введите текст для поиска")
            return
        
        with self.clients_lock:
            current_user = self.clients.get(client_socket, {}).get('username')
        
        if not current_user:
            logger.warning(f"handle_search: Поиск от незарегистрированного пользователя")
            self.send_error(client_socket, "Сначала зарегистрируйтесь")
            return
        
        logger.debug(f"handle_search: Текущий пользователь: {current_user}")
        
        results = []
        
        if search_online_only:
            logger.debug(f"handle_search: Поиск только онлайн пользователей")
            with self.clients_lock:
                online_users = list(self.user_sockets.keys())
                logger.debug(f"handle_search: Список онлайн пользователей: {online_users}")
                
                for username in online_users:
                    if username != current_user and search_term in username.lower():
                        results.append({
                            'username': username,
                            'online': True
                        })
                        logger.debug(f"handle_search: Найден онлайн пользователь: {username}")
            
            logger.debug(f"handle_search: Найдено {len(results)} онлайн пользователей")
        else:
            logger.debug(f"handle_search: Поиск всех пользователей")
            all_users_set = set()
            
            with self.clients_lock:
                online_users = list(self.user_sockets.keys())
                logger.debug(f"handle_search: Онлайн пользователи для поиска: {online_users}")
                
                for username in online_users:
                    if username != current_user and search_term in username.lower():
                        all_users_set.add(username)
                        results.append({
                            'username': username,
                            'online': True
                        })
                        logger.debug(f"handle_search: Добавлен онлайн пользователь: {username}")
            
            with self.db_lock:
                cursor = self.conn.cursor()
                query = f'%{search_term}%'
                logger.debug(f"handle_search: SQL запрос: LIKE '{query}', исключая {current_user}")
                cursor.execute('''
                    SELECT username FROM users 
                    WHERE LOWER(username) LIKE ? AND username != ?
                    ORDER BY username
                ''', (query, current_user))
                
                db_users = cursor.fetchall()
                logger.debug(f"handle_search: Найдено {len(db_users)} пользователей в БД")
                
                for row in db_users:
                    username = row['username']
                    if username not in all_users_set:
                        is_online = username in self.user_sockets
                        results.append({
                            'username': username,
                            'online': is_online
                        })
                        logger.debug(f"handle_search: Добавлен пользователь из БД: {username}, онлайн: {is_online}")
            
            logger.debug(f"handle_search: Всего найдено {len(results)} пользователей")
        
        response = {
            'type': 'search_results',
            'results': results,
            'search_term': search_term
        }
        
        logger.debug(f"handle_search: Отправка результатов: {response}")
        self.send_json(client_socket, response)
    
    def handle_get_all_users(self, client_socket, message, address):
        """Обработка запроса всех пользователей"""
        logger.debug(f"handle_get_all_users: Запрос всех пользователей от {address}")
        
        with self.clients_lock:
            current_user = self.clients.get(client_socket, {}).get('username')
        
        if not current_user:
            logger.warning(f"handle_get_all_users: Запрос от незарегистрированного пользователя")
            self.send_error(client_socket, "Сначала зарегистрируйтесь")
            return
        
        logger.debug(f"handle_get_all_users: Текущий пользователь: {current_user}")
        
        results = []
        all_users_set = set()
        
        # Добавляем онлайн пользователей
        with self.clients_lock:
            online_users = list(self.user_sockets.keys())
            logger.debug(f"handle_get_all_users: Онлайн пользователи: {online_users}")
            
            for username in online_users:
                if username != current_user:
                    all_users_set.add(username)
                    results.append({
                        'username': username,
                        'online': True
                    })
                    logger.debug(f"handle_get_all_users: Добавлен онлайн пользователь: {username}")
        
        # Добавляем оффлайн пользователей из БД
        with self.db_lock:
            cursor = self.conn.cursor()
            cursor.execute('''
                SELECT username FROM users 
                WHERE username != ?
                ORDER BY username
            ''', (current_user,))
            
            db_users = cursor.fetchall()
            logger.debug(f"handle_get_all_users: Найдено {len(db_users)} пользователей в БД")
            
            for row in db_users:
                username = row['username']
                if username not in all_users_set:
                    is_online = username in self.user_sockets
                    results.append({
                        'username': username,
                        'online': is_online
                    })
                    logger.debug(f"handle_get_all_users: Добавлен пользователь из БД: {username}, онлайн: {is_online}")
        
        response = {
            'type': 'all_users',
            'users': results
        }
        
        logger.debug(f"handle_get_all_users: Отправка {len(results)} пользователей")
        self.send_json(client_socket, response)
    
    def handle_get_key(self, client_socket, message, address):
        """Обработка запроса публичного ключа"""
        target_username = message.get('username')
        
        logger.debug(f"handle_get_key: Запрос ключа для пользователя {target_username} от {address}")
        
        if not target_username:
            logger.warning(f"handle_get_key: Не указано имя пользователя")
            self.send_error(client_socket, "Не указано имя пользователя")
            return
        
        with self.clients_lock:
            if target_username in self.public_keys:
                is_online = target_username in self.user_sockets
                logger.debug(f"handle_get_key: Ключ найден в памяти, online={is_online}")
                
                response = {
                    'type': 'key_response',
                    'username': target_username,
                    'public_key': self.public_keys[target_username],
                    'online': is_online
                }
                self.send_json(client_socket, response)
                return
        
        logger.debug(f"handle_get_key: Ключ не найден в памяти, поиск в БД")
        
        with self.db_lock:
            cursor = self.conn.cursor()
            cursor.execute(
                'SELECT public_key FROM users WHERE username = ?',
                (target_username,)
            )
            result = cursor.fetchone()
            
            if result:
                public_key = result['public_key']
                with self.clients_lock:
                    self.public_keys[target_username] = public_key
                    is_online = target_username in self.user_sockets
                
                logger.debug(f"handle_get_key: Ключ найден в БД, online={is_online}")
                
                response = {
                    'type': 'key_response',
                    'username': target_username,
                    'public_key': public_key,
                    'online': is_online
                }
                self.send_json(client_socket, response)
            else:
                logger.warning(f"handle_get_key: Пользователь {target_username} не найден в БД")
                self.send_error(client_socket, "Пользователь не найден")
    
    def handle_message(self, client_socket, message, address):
        """Обработка сообщения"""
        logger.debug(f"handle_message: Обработка сообщения от {address}")
        
        with self.clients_lock:
            sender_info = self.clients.get(client_socket)
        
        if not sender_info:
            logger.warning(f"handle_message: Сообщение от незарегистрированного клиента {address}")
            self.send_error(client_socket, "Сначала зарегистрируйтесь")
            return
        
        sender = sender_info['username']
        recipient = message.get('to')
        msg_data = message.get('message')
        session_key = message.get('session_key')
        message_id = message.get('message_id')
        timestamp = message.get('timestamp')
        
        logger.debug(f"handle_message: Детали сообщения:")
        logger.debug(f"  Отправитель: {sender}")
        logger.debug(f"  Получатель: {recipient}")
        logger.debug(f"  ID сообщения: {message_id}")
        logger.debug(f"  Длина данных: {len(msg_data) if msg_data else 0}")
        logger.debug(f"  Длина ключа сессии: {len(session_key) if session_key else 0}")
        
        # Проверка размера сообщения (например, 10 МБ)
        MAX_MESSAGE_SIZE = 10 * 1024 * 1024
        
        if msg_data and len(msg_data) > MAX_MESSAGE_SIZE:
            logger.warning(f"handle_message: Сообщение слишком большое: {len(msg_data)} > {MAX_MESSAGE_SIZE}")
            self.send_error(client_socket, "Сообщение слишком большое")
            return
        
        if not recipient:
            logger.warning(f"handle_message: Не указан получатель")
            self.send_error(client_socket, "Не указан получатель")
            return
        
        if not msg_data or not session_key:
            logger.warning(f"handle_message: Неверное сообщение - отсутствуют данные или ключ")
            self.send_error(client_socket, "Неверное сообщение")
            return
        
        if sender == recipient:
            logger.warning(f"handle_message: Попытка отправить сообщение самому себе: {sender}")
            self.send_error(client_socket, "Нельзя отправлять сообщения самому себе")
            return
        
        recipient_exists = False
        with self.clients_lock:
            recipient_exists = recipient in self.public_keys
            logger.debug(f"handle_message: Получатель {recipient} в public_keys: {recipient_exists}")
        
        if not recipient_exists:
            with self.db_lock:
                cursor = self.conn.cursor()
                cursor.execute('SELECT 1 FROM users WHERE username = ?', (recipient,))
                recipient_exists = cursor.fetchone() is not None
                logger.debug(f"handle_message: Получатель {recipient} в БД: {recipient_exists}")
        
        if not recipient_exists:
            logger.warning(f"handle_message: Получатель {recipient} не найден")
            self.send_error(client_socket, "Получатель не найден")
            return
        
        forward_message = {
            'type': 'message',
            'from': sender,
            'message': msg_data,
            'session_key': session_key,
            'message_id': message_id,
            'timestamp': timestamp or datetime.now().isoformat()
        }
        
        with self.clients_lock:
            recipient_socket = self.user_sockets.get(recipient)
            logger.debug(f"handle_message: Получатель {recipient} онлайн: {recipient_socket is not None}")
        
        if recipient_socket:
            try:
                logger.debug(f"handle_message: Попытка доставки сообщения {message_id} онлайн получателю {recipient}")
                self.send_json(recipient_socket, forward_message)
                logger.info(f"handle_message: Сообщение {message_id} от {sender} к {recipient} доставлено онлайн")
                
                logger.debug(f"handle_message: Отправка статуса 'delivered' отправителю {sender}")
                self.send_delivery_status(sender, message_id, 'delivered')
                
            except Exception as e:
                logger.error(f"handle_message: Ошибка доставки сообщения {sender}->{recipient}: {e}")
                logger.debug(f"handle_message: Сохранение как оффлайн из-за ошибки")
                self.save_offline_message(sender, recipient, msg_data, session_key, message_id)
        else:
            logger.debug(f"handle_message: Получатель {recipient} оффлайн, сохранение сообщения")
            self.save_offline_message(sender, recipient, msg_data, session_key, message_id)
            logger.info(f"handle_message: Сообщение {message_id} от {sender} к {recipient} сохранено оффлайн")
        
        logger.debug(f"handle_message: Отправка статуса 'sent' для сообщения {message_id}")
        self.send_delivery_status(sender, message_id, 'sent')
    
    def handle_typing(self, client_socket, message, address):
        """Обработка статуса печатания"""
        logger.debug(f"handle_typing: Обработка тайпинга от {address}")
        
        with self.clients_lock:
            sender_info = self.clients.get(client_socket)
        
        if not sender_info:
            logger.warning(f"handle_typing: Тайпинг от незарегистрированного клиента")
            return
        
        sender = sender_info['username']
        recipient = message.get('to')
        is_typing = message.get('is_typing', False)
        
        if not recipient:
            logger.warning(f"handle_typing: Не указан получатель тайпинга")
            return
        
        logger.debug(f"handle_typing: Тайпинг от {sender} к {recipient}: {is_typing}")
        
        with self.clients_lock:
            recipient_socket = self.user_sockets.get(recipient)
            logger.debug(f"handle_typing: Получатель {recipient} онлайн: {recipient_socket is not None}")
        
        if recipient_socket:
            try:
                self.send_json(recipient_socket, {
                    'type': 'typing',
                    'from': sender,
                    'is_typing': is_typing
                })
                logger.debug(f"handle_typing: Тайпинг отправлен получателю {recipient}")
            except Exception as e:
                logger.error(f"handle_typing: Ошибка отправки тайпинга: {e}")
        else:
            logger.debug(f"handle_typing: Получатель {recipient} не в сети, тайпинг не отправлен")
    
    def handle_delivery_status(self, client_socket, message, address):
        """Обработка статуса доставки"""
        logger.debug(f"handle_delivery_status: Обработка статуса доставки от {address}")
        
        with self.clients_lock:
            sender_info = self.clients.get(client_socket)
        
        if not sender_info:
            logger.warning(f"handle_delivery_status: Статус от незарегистрированного клиента")
            return
        
        message_id = message.get('message_id')
        status = message.get('status')
        recipient = message.get('to')
        sender_username = sender_info['username']
        
        if not recipient:
            recipient = sender_username
            logger.debug(f"handle_delivery_status: Получатель не указан, используем отправителя: {recipient}")
        
        logger.debug(f"handle_delivery_status: Статус {status} для сообщения {message_id}")
        logger.debug(f"handle_delivery_status: Отправитель статуса: {sender_username}")
        logger.debug(f"handle_delivery_status: Получатель статуса: {recipient}")
        
        with self.clients_lock:
            if recipient in self.user_sockets:
                try:
                    status_message = {
                        'type': 'delivery_status',
                        'message_id': message_id,
                        'status': status
                    }
                    
                    self.send_json(self.user_sockets[recipient], status_message)
                    logger.debug(f"handle_delivery_status: Статус {status} для {message_id} отправлен {recipient}")
                    
                except Exception as e:
                    logger.error(f"handle_delivery_status: Ошибка отправки статуса: {e}")
            else:
                logger.debug(f"handle_delivery_status: Получатель статуса {recipient} не в сети, статус не отправлен")
    
    def handle_read_receipt(self, client_socket, message, address):
        """Обработка уведомления о прочтении"""
        logger.debug(f"handle_read_receipt: Обработка read_receipt от {address}")
        
        with self.clients_lock:
            sender_info = self.clients.get(client_socket)
        
        if not sender_info:
            logger.warning(f"handle_read_receipt: Read receipt от незарегистрированного клиента")
            return
        
        reader = sender_info['username']
        message_id = message.get('message_id')
        original_sender = message.get('to')
        
        logger.debug(f"handle_read_receipt: Read receipt от {reader} для сообщения {message_id} от {original_sender}")
        
        if not original_sender:
            logger.warning(f"handle_read_receipt: Read receipt без указания отправителя оригинала")
            return
        
        with self.clients_lock:
            if original_sender in self.user_sockets:
                try:
                    receipt_message = {
                        'type': 'read_receipt',
                        'message_id': message_id,
                        'reader': reader
                    }
                    
                    self.send_json(self.user_sockets[original_sender], receipt_message)
                    logger.debug(f"handle_read_receipt: Read receipt отправлен {original_sender}")
                    
                except Exception as e:
                    logger.error(f"handle_read_receipt: Ошибка отправки read_receipt: {e}")
            else:
                logger.debug(f"handle_read_receipt: Отправитель {original_sender} не в сети, read_receipt не отправлен")
    
    def handle_group_create(self, client_socket, message, address):
        """Обработка создания группы"""
        logger.debug(f"handle_group_create: Обработка создания группы")
        
        with self.clients_lock:
            sender_info = self.clients.get(client_socket)
        
        if not sender_info:
            logger.warning(f"handle_group_create: Запрос от незарегистрированного клиента")
            self.send_error(client_socket, "Сначала зарегистрируйтесь")
            return
        
        sender = sender_info['username']
        group_id = message.get('group_id')
        group_name = message.get('group_name')
        members = message.get('members', [])
        encrypted_keys = message.get('encrypted_keys', {})
        
        logger.debug(f"handle_group_create: Создание группы {group_id} '{group_name}'")
        logger.debug(f"handle_group_create: Админ: {sender}, Участники: {members}")
        
        # Проверяем, существует ли уже группа с таким ID
        with self.groups_lock:
            if group_id in self.groups:
                logger.warning(f"handle_group_create: Группа {group_id} уже существует")
                self.send_error(client_socket, "Группа с таким ID уже существует")
                return
        
        # Сохраняем группу в памяти
        with self.groups_lock:
            self.groups[group_id] = {
                'name': group_name,
                'admin': sender,
                'members': members + [sender]  # Добавляем админа в участники
            }
            
            logger.debug(f"handle_group_create: Группа сохранена в памяти")
        
        # Сохраняем в БД
        with self.db_lock:
            try:
                cursor = self.conn.cursor()
                
                # Сохраняем группу
                cursor.execute('''
                    INSERT INTO groups (group_id, group_name, admin)
                    VALUES (?, ?, ?)
                ''', (group_id, group_name, sender))
                
                # Сохраняем участников
                all_members = members + [sender]
                for member in all_members:
                    cursor.execute('''
                        INSERT INTO group_members (group_id, username)
                        VALUES (?, ?)
                    ''', (group_id, member))
                
                # Сохраняем зашифрованные ключи для оффлайн пользователей
                for member, encrypted_key in encrypted_keys.items():
                    cursor.execute('''
                        INSERT INTO group_pending_invites (group_id, username, encrypted_key)
                        VALUES (?, ?, ?)
                    ''', (group_id, member, encrypted_key))
                    
                    # Сохраняем в памяти
                    if group_id not in self.group_pending_keys:
                        self.group_pending_keys[group_id] = {}
                    self.group_pending_keys[group_id][member] = encrypted_key
                
                self.conn.commit()
                logger.debug(f"handle_group_create: Группа сохранена в БД")
                
            except Exception as e:
                logger.error(f"handle_group_create: Ошибка сохранения группы в БД: {e}")
                with self.groups_lock:
                    if group_id in self.groups:
                        del self.groups[group_id]
                self.send_error(client_socket, f"Ошибка создания группы: {str(e)}")
                return
        
        # Отправляем приглашения онлайн участникам
        for member in members:
            if member in encrypted_keys:
                self.send_group_invite(group_id, group_name, sender, member, encrypted_keys[member])
        
        logger.info(f"handle_group_create: Группа {group_id} создана успешно")
        
        # Отправляем подтверждение создателю
        self.send_json(client_socket, {
            'type': 'group_create_ok',
            'group_id': group_id,
            'message': 'Группа создана успешно'
        })
    
    def send_group_invite(self, group_id, group_name, admin, member, encrypted_key):
        """Отправка приглашения в группу"""
        logger.debug(f"send_group_invite: Отправка приглашения {member} в группу {group_id}")
        
        with self.clients_lock:
            member_socket = self.user_sockets.get(member)
        
        if member_socket:
            # Пользователь онлайн - отправляем сразу
            try:
                self.send_json(member_socket, {
                    'type': 'group_invite',
                    'group_id': group_id,
                    'group_name': group_name,
                    'admin': admin,
                    'encrypted_key': encrypted_key,
                    'timestamp': datetime.now().isoformat()
                })
                logger.debug(f"send_group_invite: Приглашение отправлено онлайн пользователю {member}")
                
                # Удаляем из ожидающих
                self.remove_pending_invite(group_id, member)
                
            except Exception as e:
                logger.error(f"send_group_invite: Ошибка отправки приглашения {member}: {e}")
        else:
            logger.debug(f"send_group_invite: Пользователь {member} оффлайн, приглашение сохранено")
    
    def handle_group_message(self, client_socket, message, address):
        """Обработка группового сообщения"""
        logger.debug(f"handle_group_message: Обработка группового сообщения")
        
        with self.clients_lock:
            sender_info = self.clients.get(client_socket)
        
        if not sender_info:
            logger.warning(f"handle_group_message: Сообщение от незарегистрированного клиента")
            return
        
        sender = sender_info['username']
        group_id = message.get('group_id')
        encrypted_msg = message.get('message')
        message_id = message.get('message_id')
        timestamp = message.get('timestamp')
        
        logger.debug(f"handle_group_message: От {sender} в группу {group_id}")
        
        # Проверяем, существует ли группа
        with self.groups_lock:
            if group_id not in self.groups:
                logger.warning(f"handle_group_message: Группа {group_id} не найдена")
                self.send_error(client_socket, "Группа не найдена")
                return
            
            group_info = self.groups[group_id]
            
            # Проверяем, является ли отправитель участником группы
            if sender not in group_info['members']:
                logger.warning(f"handle_group_message: Отправитель {sender} не участник группы {group_id}")
                self.send_error(client_socket, "Вы не участник этой группы")
                return
        
        # Отправляем сообщение всем участникам группы
        sent_count = 0
        failed_count = 0
        
        with self.clients_lock:
            for member in group_info['members']:
                if member == sender:
                    continue  # Не отправляем отправителю
                
                member_socket = self.user_sockets.get(member)
                
                if member_socket:
                    try:
                        self.send_json(member_socket, {
                            'type': 'group_message',
                            'group_id': group_id,
                            'sender': sender,
                            'message': encrypted_msg,
                            'message_id': message_id,
                            'timestamp': timestamp
                        })
                        sent_count += 1
                        logger.debug(f"handle_group_message: Сообщение отправлено {member}")
                    except Exception as e:
                        logger.error(f"handle_group_message: Ошибка отправки {member}: {e}")
                        failed_count += 1
                else:
                    # Сохраняем оффлайн сообщение
                    self.save_group_offline_message(group_id, sender, encrypted_msg, message_id, timestamp)
                    logger.debug(f"handle_group_message: Сообщение сохранено оффлайн для {member}")
        
        logger.info(f"handle_group_message: Сообщение {message_id} отправлено {sent_count} участникам, {failed_count} ошибок")
    
    def save_group_offline_message(self, group_id, sender, message, message_id, timestamp):
        """Сохранение оффлайн сообщения для группы"""
        try:
            with self.db_lock:
                cursor = self.conn.cursor()
                cursor.execute('''
                    INSERT INTO group_offline_messages (group_id, sender, message, message_id, timestamp)
                    VALUES (?, ?, ?, ?, ?)
                ''', (group_id, sender, message, message_id, timestamp))
                self.conn.commit()
                logger.debug(f"save_group_offline_message: Сообщение сохранено оффлайн")
                
        except Exception as e:
            logger.error(f"save_group_offline_message: Ошибка сохранения: {e}")
    
    def handle_group_member_added(self, client_socket, message, address):
        """Обработка добавления участника в группу"""
        logger.debug(f"handle_group_member_added: Обработка добавления участника")
        
        with self.clients_lock:
            sender_info = self.clients.get(client_socket)
        
        if not sender_info:
            logger.warning(f"handle_group_member_added: Запрос от незарегистрированного клиента")
            return
        
        sender = sender_info['username']
        group_id = message.get('group_id')
        new_member = message.get('new_member')
        encrypted_keys = message.get('encrypted_keys', {})
        
        logger.debug(f"handle_group_member_added: Добавление {new_member} в группу {group_id}")
        
        # Проверяем, существует ли группа
        with self.groups_lock:
            if group_id not in self.groups:
                logger.warning(f"handle_group_member_added: Группа {group_id} не найдена")
                self.send_error(client_socket, "Группа не найдена")
                return
            
            group_info = self.groups[group_id]
            
            # Проверяем, является ли отправитель администратором
            if group_info['admin'] != sender:
                logger.warning(f"handle_group_member_added: {sender} не администратор группы {group_id}")
                self.send_error(client_socket, "Только администратор может добавлять участников")
                return
            
            # Проверяем, не состоит ли уже пользователь в группе
            if new_member in group_info['members']:
                logger.warning(f"handle_group_member_added: {new_member} уже в группе")
                self.send_error(client_socket, "Пользователь уже в группе")
                return
        
        # Добавляем пользователя в группу
        with self.groups_lock:
            group_info['members'].append(new_member)
        
        # Обновляем БД
        with self.db_lock:
            try:
                cursor = self.conn.cursor()
                cursor.execute('''
                    INSERT INTO group_members (group_id, username)
                    VALUES (?, ?)
                ''', (group_id, new_member))
                self.conn.commit()
                logger.debug(f"handle_group_member_added: Участник добавлен в БД")
                
            except Exception as e:
                logger.error(f"handle_group_member_added: Ошибка обновления БД: {e}")
                with self.groups_lock:
                    if new_member in group_info['members']:
                        group_info['members'].remove(new_member)
                return
        
        # Отправляем новый ключ всем участникам (включая нового)
        all_members = group_info['members']
        
        for member in all_members:
            if member in encrypted_keys:
                encrypted_key = encrypted_keys[member]
                
                if member == new_member:
                    # Для нового участника отправляем приглашение
                    self.send_group_invite(group_id, group_info['name'], sender, member, encrypted_key)
                else:
                    # Для существующих участников отправляем обновление ключа
                    self.send_group_key_update(group_id, sender, member, encrypted_key)
        
        logger.info(f"handle_group_member_added: Участник {new_member} добавлен в группу {group_id}")
    
    def send_group_key_update(self, group_id, admin, member, encrypted_key):
        """Отправка обновления ключа группового чата"""
        logger.debug(f"send_group_key_update: Отправка обновления ключа для {member}")
        
        with self.clients_lock:
            member_socket = self.user_sockets.get(member)
        
        if member_socket:
            try:
                self.send_json(member_socket, {
                    'type': 'group_member_added',
                    'group_id': group_id,
                    'new_member': member,
                    'admin': admin,
                    'encrypted_key': encrypted_key,
                    'timestamp': datetime.now().isoformat()
                })
                logger.debug(f"send_group_key_update: Обновление ключа отправлено {member}")
            except Exception as e:
                logger.error(f"send_group_key_update: Ошибка отправки {member}: {e}")
        else:
            logger.debug(f"send_group_key_update: Пользователь {member} оффлайн, обновление не отправлено")
    
    def handle_group_member_removed(self, client_socket, message, address):
        """Обработка удаления участника из группы"""
        logger.debug(f"handle_group_member_removed: Обработка удаления участника")
        
        with self.clients_lock:
            sender_info = self.clients.get(client_socket)
        
        if not sender_info:
            logger.warning(f"handle_group_member_removed: Запрос от незарегистрированного клиента")
            return
        
        sender = sender_info['username']
        group_id = message.get('group_id')
        removed_member = message.get('removed_member')
        encrypted_keys = message.get('encrypted_keys', {})
        
        logger.debug(f"handle_group_member_removed: Удаление {removed_member} из группы {group_id}")
        
        # Проверяем, существует ли группа
        with self.groups_lock:
            if group_id not in self.groups:
                logger.warning(f"handle_group_member_removed: Группа {group_id} не найдена")
                self.send_error(client_socket, "Группа не найдена")
                return
            
            group_info = self.groups[group_id]
            
            # Проверяем, является ли отправитель администратором
            if group_info['admin'] != sender:
                logger.warning(f"handle_group_member_removed: {sender} не администратор группы {group_id}")
                self.send_error(client_socket, "Только администратор может удалять участников")
                return
            
            # Проверяем, состоит ли пользователь в группе
            if removed_member not in group_info['members']:
                logger.warning(f"handle_group_member_removed: {removed_member} не в группе")
                self.send_error(client_socket, "Пользователь не в группе")
                return
        
        # Удаляем пользователя из группы
        with self.groups_lock:
            group_info['members'].remove(removed_member)
        
        # Обновляем БД
        with self.db_lock:
            try:
                cursor = self.conn.cursor()
                cursor.execute('''
                    DELETE FROM group_members 
                    WHERE group_id = ? AND username = ?
                ''', (group_id, removed_member))
                self.conn.commit()
                logger.debug(f"handle_group_member_removed: Участник удален из БД")
                
            except Exception as e:
                logger.error(f"handle_group_member_removed: Ошибка обновления БД: {e}")
                with self.groups_lock:
                    group_info['members'].append(removed_member)
                return
        
        # Отправляем уведомление удаленному пользователю
        self.send_group_removal_notification(group_id, removed_member, sender)
        
        # Отправляем новый ключ оставшимся участникам
        remaining_members = [m for m in group_info['members'] if m != removed_member]
        
        for member in remaining_members:
            if member in encrypted_keys:
                self.send_group_key_update_removal(group_id, sender, member, 
                                                 removed_member, encrypted_keys[member])
        
        logger.info(f"handle_group_member_removed: Участник {removed_member} удален из группы {group_id}")
    
    def send_group_removal_notification(self, group_id, removed_member, admin):
        """Отправка уведомления об удалении из группы"""
        logger.debug(f"send_group_removal_notification: Уведомление {removed_member} об удалении")
        
        with self.clients_lock:
            member_socket = self.user_sockets.get(removed_member)
        
        if member_socket:
            try:
                self.send_json(member_socket, {
                    'type': 'group_member_removed',
                    'group_id': group_id,
                    'removed_member': removed_member,
                    'admin': admin,
                    'encrypted_key': '',  # Пустой ключ, так как пользователь удален
                    'timestamp': datetime.now().isoformat()
                })
                logger.debug(f"send_group_removal_notification: Уведомление отправлено {removed_member}")
            except Exception as e:
                logger.error(f"send_group_removal_notification: Ошибка отправки {removed_member}: {e}")
        else:
            logger.debug(f"send_group_removal_notification: Пользователь {removed_member} оффлайн")
    
    def send_group_key_update_removal(self, group_id, admin, member, removed_member, encrypted_key):
        """Отправка обновления ключа после удаления участника"""
        logger.debug(f"send_group_key_update_removal: Отправка обновления ключа для {member}")
        
        with self.clients_lock:
            member_socket = self.user_sockets.get(member)
        
        if member_socket:
            try:
                self.send_json(member_socket, {
                    'type': 'group_member_removed',
                    'group_id': group_id,
                    'removed_member': removed_member,
                    'admin': admin,
                    'encrypted_key': encrypted_key,
                    'timestamp': datetime.now().isoformat()
                })
                logger.debug(f"send_group_key_update_removal: Обновление ключа отправлено {member}")
            except Exception as e:
                logger.error(f"send_group_key_update_removal: Ошибка отправки {member}: {e}")
        else:
            logger.debug(f"send_group_key_update_removal: Пользователь {member} оффлайн, обновление не отправлено")
    
    def save_offline_message(self, sender, recipient, message, session_key, message_id):
        """Сохранение оффлайн сообщения"""
        try:
            logger.debug(f"save_offline_message: Сохранение оффлайн сообщения {message_id}")
            logger.debug(f"save_offline_message: От {sender} к {recipient}")
            
            with self.db_lock:
                cursor = self.conn.cursor()
                cursor.execute('''
                    INSERT INTO offline_messages 
                    (recipient, sender, message, session_key, message_id) 
                    VALUES (?, ?, ?, ?, ?)
                ''', (recipient, sender, message, session_key, message_id))
                self.conn.commit()
                
                logger.debug(f"save_offline_message: Сообщение {message_id} сохранено в БД")
                
        except Exception as e:
            logger.error(f"save_offline_message: Ошибка сохранения оффлайн сообщения: {e}")
    
    def send_offline_messages(self, username, client_socket):
        """Отправка накопленных оффлайн сообщений"""
        try:
            logger.debug(f"send_offline_messages: Проверка оффлайн сообщений для {username}")
            
            with self.db_lock:
                cursor = self.conn.cursor()
                cursor.execute('''
                    SELECT sender, message, session_key, message_id, timestamp 
                    FROM offline_messages 
                    WHERE recipient = ? 
                    ORDER BY timestamp
                ''', (username,))
                
                messages = cursor.fetchall()
                logger.debug(f"send_offline_messages: Найдено {len(messages)} оффлайн сообщений для {username}")
                
                for i, msg in enumerate(messages):
                    sender, message, session_key, message_id, timestamp = msg
                    
                    logger.debug(f"send_offline_messages: [{i+1}/{len(messages)}] Обработка сообщения {message_id} от {sender}")
                    
                    try:
                        forward_message = {
                            'type': 'message',
                            'from': sender,
                            'message': message,
                            'session_key': session_key,
                            'message_id': message_id,
                            'timestamp': timestamp,
                            'offline': True
                        }
                        
                        self.send_json(client_socket, forward_message)
                        logger.debug(f"send_offline_messages: Оффлайн сообщение {message_id} отправлено")
                        
                        self.send_delivery_status(sender, message_id, 'delivered')
                        logger.debug(f"send_offline_messages: Статус 'delivered' отправлен отправителю {sender}")
                        
                    except Exception as e:
                        logger.error(f"send_offline_messages: Ошибка отправки оффлайн сообщения {message_id}: {e}")
                        break
                
                if messages:
                    cursor.execute('DELETE FROM offline_messages WHERE recipient = ?', (username,))
                    self.conn.commit()
                    logger.info(f"send_offline_messages: Отправлено {len(messages)} оффлайн сообщений для {username}")
                else:
                    logger.debug(f"send_offline_messages: Нет оффлайн сообщений для {username}")
                
        except Exception as e:
            logger.error(f"send_offline_messages: Ошибка получения оффлайн сообщений: {e}")
    
    def send_delivery_status(self, recipient, message_id, status):
        """Отправка статуса доставки"""
        logger.debug(f"send_delivery_status: Вызов функции: recipient={recipient}, message_id={message_id}, status={status}")
        
        with self.clients_lock:
            recipient_socket = self.user_sockets.get(recipient)
            logger.debug(f"send_delivery_status: Поиск сокета для {recipient}: {'найден' if recipient_socket else 'не найден'}")
        
        if recipient_socket:
            try:
                status_message = {
                    'type': 'delivery_status',
                    'message_id': message_id,
                    'status': status
                }
                
                logger.debug(f"send_delivery_status: Отправка статуса: {status_message}")
                self.send_json(recipient_socket, status_message)
                logger.debug(f"send_delivery_status: Статус {status} для {message_id} отправлен {recipient}")
                
            except Exception as e:
                logger.error(f"send_delivery_status: Ошибка отправки статуса доставки: {e}")
        else:
            logger.debug(f"send_delivery_status: Получатель {recipient} не в сети, статус не отправлен")
    
    def send_json(self, socket_obj, data):
        """Безопасная отправка JSON"""
        try:
            json_data = json.dumps(data, ensure_ascii=False)
            logger.debug(f"send_json: Отправка JSON, тип: {data.get('type')}, длина: {len(json_data)}")
            
            socket_obj.send(json_data.encode('utf-8'))
            logger.debug(f"send_json: JSON успешно отправлен")
            
        except Exception as e:
            logger.error(f"send_json: Ошибка отправки данных: {e}")
            raise Exception(f"Ошибка отправки данных: {e}")
    
    def send_error(self, socket_obj, message):
        """Отправка сообщения об ошибке"""
        try:
            logger.debug(f"send_error: Отправка ошибки: {message}")
            self.send_json(socket_obj, {'type': 'error', 'message': message})
        except Exception as e:
            logger.error(f"send_error: Не удалось отправить ошибку: {e}")
    
    def disconnect_client(self, username, client_socket, address):
        """Корректное отключение клиента"""
        logger.debug(f"disconnect_client: Начало отключения клиента {address}, username={username}")
        
        try:
            client_socket.close()
            logger.debug(f"disconnect_client: Сокет закрыт")
        except Exception as e:
            logger.error(f"disconnect_client: Ошибка закрытия сокета: {e}")
        
        with self.clients_lock:
            logger.debug(f"disconnect_client: Текущее состояние перед очисткой:")
            logger.debug(f"  clients: {len(self.clients)} записей")
            logger.debug(f"  user_sockets: {len(self.user_sockets)} записей: {list(self.user_sockets.keys())}")
            
            if client_socket in self.clients:
                user_info = self.clients[client_socket]
                username = user_info.get('username')
                del self.clients[client_socket]
                logger.debug(f"disconnect_client: Удален из clients: {username}")
            
            if username and username in self.user_sockets:
                if self.user_sockets[username] == client_socket:
                    del self.user_sockets[username]
                    logger.debug(f"disconnect_client: Удален из user_sockets: {username}")
                else:
                    logger.debug(f"disconnect_client: Сокет в user_sockets не совпадает с текущим, не удаляем")
            elif username:
                logger.debug(f"disconnect_client: Имя пользователя {username} не найдено в user_sockets")
        
        if username:
            logger.info(f"disconnect_client: Пользователь {username} отключен")
        else:
            logger.info(f"disconnect_client: Анонимный клиент отключен: {address}")
    
    def signal_handler(self, signum, frame):
        """Обработчик сигналов"""
        logger.info(f"signal_handler: Получен сигнал {signum}, завершение работы...")
        self.running = False
    
    def cleanup(self):
        """Очистка ресурсов"""
        logger.info("cleanup: Очистка ресурсов сервера...")
        
        with self.clients_lock:
            logger.debug(f"cleanup: Отключение {len(self.clients)} клиентов")
            for i, client_socket in enumerate(list(self.clients.keys())):
                try:
                    logger.debug(f"cleanup: [{i+1}/{len(self.clients)}] Закрытие сокета {client_socket}")
                    client_socket.close()
                except Exception as e:
                    logger.error(f"cleanup: Ошибка закрытия сокета: {e}")
            
            self.clients.clear()
            self.user_sockets.clear()
            self.public_keys.clear()
            logger.debug(f"cleanup: Все структуры данных очищены")
        
        try:
            self.server_socket.close()
            logger.debug(f"cleanup: Серверный сокет закрыт")
        except Exception as e:
            logger.error(f"cleanup: Ошибка закрытия серверного сокета: {e}")
        
        try:
            self.conn.close()
            logger.debug(f"cleanup: Соединение с БД закрыто")
        except Exception as e:
            logger.error(f"cleanup: Ошибка закрытия БД: {e}")
        
        logger.info("cleanup: Сервер остановлен")

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Secure Messenger Server')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to')
    parser.add_argument('--port', type=int, default=5555, help='Port to listen on')
    
    args = parser.parse_args()
    
    server = SecureMessengerServer(host=args.host, port=args.port)
    
    try:
        server.start()
    except KeyboardInterrupt:
        logger.info("Сервер остановлен пользователем")
    except Exception as e:
        logger.error(f"Критическая ошибка: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
