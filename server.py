from flask import Flask, request, jsonify
from flask_cors import CORS
import sqlite3
import datetime
import hashlib
import os
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

app = Flask(__name__)
CORS(app)

# === НАСТРОЙКИ ===
DB_PATH = 'licenses.db'
SECRET_KEY = b'MySecretKeyForAES256Encryption32'
MAIN_PY_ENCRYPTED = None

def init_db():
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
    global MAIN_PY_ENCRYPTED
    if os.path.exists('main_encrypted.bin'):
        with open('main_encrypted.bin', 'r', encoding='utf-8') as f:
            MAIN_PY_ENCRYPTED = f.read()
        print("Зашифрованный main.py загружен")
    else:
        print("ВНИМАНИЕ: main_encrypted.bin не найден!")

@app.route('/verify', methods=['POST'])
def verify_key():
    data = request.get_json()
    key = data.get('key', '').strip().upper()
    hwid = data.get('hwid', '')
    
    if not key or not hwid:
        return jsonify({'success': False, 'error': 'Не указан ключ или HWID'})
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT hwid, expiry_date, is_active FROM licenses WHERE key_code = ?', (key,))
    row = c.fetchone()
    
    if not row:
        conn.close()
        return jsonify({'success': False, 'error': 'Неверный ключ'})
    
    stored_hwid, expiry_date, is_active = row
    
    if not is_active:
        conn.close()
        return jsonify({'success': False, 'error': 'Ключ заблокирован'})
    
    expiry = datetime.datetime.fromisoformat(expiry_date)
    if datetime.datetime.now() > expiry:
        conn.close()
        return jsonify({'success': False, 'error': 'Срок действия ключа истёк'})
    
    if stored_hwid is None or stored_hwid == '':
        c.execute('UPDATE licenses SET hwid = ? WHERE key_code = ?', (hwid, key))
        conn.commit()
        conn.close()
        return jsonify({'success': True, 'encrypted_data': MAIN_PY_ENCRYPTED})
    
    if stored_hwid == hwid:
        conn.close()
        return jsonify({'success': True, 'encrypted_data': MAIN_PY_ENCRYPTED})
    
    conn.close()
    return jsonify({'success': False, 'error': 'Ключ активирован на другом устройстве'})

if __name__ == '__main__':
    init_db()
    load_encrypted_main()
    app.run(host='0.0.0.0', port=5000, debug=False)
