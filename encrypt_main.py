# encrypt_main.py
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import base64

SECRET_KEY = b'MySecretKeyForAES256Encryption32!'

def encrypt_file(source, output):
    with open(source, 'rb') as f:
        data = f.read()
    
    cipher = AES.new(SECRET_KEY, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data, AES.block_size))
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    ct = base64.b64encode(ct_bytes).decode('utf-8')
    
    with open(output, 'w') as f:
        f.write(f"{iv}\n{ct}")
    print(f"Файл зашифрован: {output}")

encrypt_file('main.py', 'main_encrypted.bin')