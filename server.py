from flask import Flask, request, jsonify
from flask_cors import CORS
import sqlite3
import datetime
import hashlib
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

app = Flask(__name__)
CORS(app)

# === НАСТРОЙКИ ===
DB_PATH = 'licenses.db'
SECRET_KEY = b'MySecretKeyForAES256Encryption32!'  # 32 байта для AES-256
MAIN_PY_ENCRYPTED = None  # Будет загружен при старте

# === ФУНКЦИИ БАЗЫ ДАННЫХ ===
def init_db():
    """Создаёт таблицу лицензий при первом запуске"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS licenses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key_code TEXT UNIQUE NOT NULL,
            hwid TEXT,
            expiry_date TEXT,
            is_active BOOLEAN DEFAULT 1,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()
    print("База данных инициализирована")

def load_encrypted_main():
    """Загружает зашифрованный main.py (заранее подготовленный)"""
    global MAIN_PY_ENCRYPTED
    if os.path.exists('main_encrypted.bin'):
        with open('main_encrypted.bin', 'rb') as f:
            MAIN_PY_ENCRYPTED = f.read()
        print("Зашифрованный main.py загружен")
    else:
        print("ВНИМАНИЕ: main_encrypted.bin не найден!")

def encrypt_main_py(source_file, output_file):
    """Шифрует main.py (запускается локально, не на сервере)"""
    with open(source_file, 'rb') as f:
        data = f.read()
    
    cipher = AES.new(SECRET_KEY, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data, AES.block_size))
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    ct = base64.b64encode(ct_bytes).decode('utf-8')
    
    with open(output_file, 'w') as f:
        f.write(f"{iv}\n{ct}")
    print(f"Файл зашифрован: {output_file}")

# === API ЭНДПОИНТЫ ===
@app.route('/verify', methods=['POST'])
def verify_key():
    """Проверяет ключ, привязывает HWID и возвращает зашифрованный main.py"""
    data = request.get_json()
    key = data.get('key', '').strip().upper()
    hwid = data.get('hwid', '')
    
    if not key or not hwid:
        return jsonify({'success': False, 'error': 'Не указан ключ или HWID'})
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    # Проверяем существование ключа
    c.execute('SELECT hwid, expiry_date, is_active FROM licenses WHERE key_code = ?', (key,))
    row = c.fetchone()
    
    if not row:
        conn.close()
        return jsonify({'success': False, 'error': 'Неверный ключ'})
    
    stored_hwid, expiry_date, is_active = row
    
    if not is_active:
        conn.close()
        return jsonify({'success': False, 'error': 'Ключ заблокирован'})
    
    # Проверяем срок действия
    expiry = datetime.datetime.fromisoformat(expiry_date)
    if datetime.datetime.now() > expiry:
        conn.close()
        return jsonify({'success': False, 'error': 'Срок действия ключа истёк'})
    
    # Если ключ новый (без HWID) - привязываем
    if stored_hwid is None or stored_hwid == '':
        c.execute('UPDATE licenses SET hwid = ? WHERE key_code = ?', (hwid, key))
        conn.commit()
        conn.close()
        return jsonify({'success': True, 'encrypted_data': MAIN_PY_ENCRYPTED})
    
    # Если HWID совпадает - отдаём файл
    if stored_hwid == hwid:
        conn.close()
        return jsonify({'success': True, 'encrypted_data': MAIN_PY_ENCRYPTED})
    
    # HWID не совпадает
    conn.close()
    return jsonify({'success': False, 'error': 'Ключ уже активирован на другом устройстве'})

# === ЗАПУСК ===
if __name__ == '__main__':
    init_db()
    load_encrypted_main()
    app.run(host='0.0.0.0', port=5000, debug=False)
