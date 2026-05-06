import base64
import binascii
import urllib.parse
import hashlib
import os

from Crypto.Cipher import AES, DES, DES3
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


# ═══════════════════════════════════
# SYMMETRIC ENCRYPTION
# ═══════════════════════════════════

def get_valid_key(key_str, algo):
    key_bytes = key_str.encode('utf-8')
    if algo == "AES":
        if len(key_bytes) not in [16, 24, 32]:
            raise ValueError("AES key must be exactly 16, 24, or 32 characters.")
        return key_bytes
    if algo == "DES":
        if len(key_bytes) != 8:
            raise ValueError("DES key must be exactly 8 characters.")
        return key_bytes
    if algo == "3DES":
        if len(key_bytes) not in [16, 24]:
            raise ValueError("3DES key must be exactly 16 or 24 characters.")
        return key_bytes


def symmetric_encrypt(algo, key_str, text):
    key  = get_valid_key(key_str, algo)
    data = text.encode('utf-8')
    if   algo == "AES":  cipher = AES.new(key, AES.MODE_CBC)
    elif algo == "DES":  cipher = DES.new(key, DES.MODE_CBC)
    elif algo == "3DES": cipher = DES3.new(key, DES3.MODE_CBC)
    encrypted = cipher.encrypt(pad(data, cipher.block_size))
    # Prepend IV so we can decrypt later
    return base64.b64encode(cipher.iv + encrypted).decode('utf-8')


def symmetric_decrypt(algo, key_str, encrypted_text):
    key  = get_valid_key(key_str, algo)
    raw  = base64.b64decode(encrypted_text)
    if   algo == "AES":  iv, data = raw[:16], raw[16:]; cipher = AES.new(key, AES.MODE_CBC, iv)
    elif algo == "DES":  iv, data = raw[:8],  raw[8:];  cipher = DES.new(key, DES.MODE_CBC, iv)
    elif algo == "3DES": iv, data = raw[:8],  raw[8:];  cipher = DES3.new(key, DES3.MODE_CBC, iv)
    return unpad(cipher.decrypt(data), cipher.block_size).decode('utf-8')


# ═══════════════════════════════════
# ASYMMETRIC (RSA)
# ═══════════════════════════════════

def generate_rsa_keys(bits=2048):
    key = RSA.generate(bits)
    private_pem = key.export_key().decode('utf-8')
    public_pem  = key.publickey().export_key().decode('utf-8')
    return private_pem, public_pem


def asymmetric_encrypt(public_pem, text):
    if not public_pem:
        raise ValueError("Please generate RSA keys first.")
    pub_key   = RSA.import_key(public_pem)
    cipher    = PKCS1_OAEP.new(pub_key)
    encrypted = cipher.encrypt(text.encode('utf-8'))
    return base64.b64encode(encrypted).decode('utf-8')


def asymmetric_decrypt(private_pem, encrypted_text):
    if not private_pem:
        raise ValueError("Please generate RSA keys first.")
    priv_key  = RSA.import_key(private_pem)
    cipher    = PKCS1_OAEP.new(priv_key)
    data      = base64.b64decode(encrypted_text)
    return cipher.decrypt(data).decode('utf-8')


# ═══════════════════════════════════
# ENCODING / DECODING
# ═══════════════════════════════════

def encode_data(algo, text):
    if   algo == "Base64":       return base64.b64encode(text.encode('utf-8')).decode('utf-8')
    elif algo == "Hex":          return binascii.hexlify(text.encode('utf-8')).decode('utf-8')
    elif algo == "URL Encoding": return urllib.parse.quote(text)


def decode_data(algo, text):
    if   algo == "Base64":       return base64.b64decode(text).decode('utf-8')
    elif algo == "Hex":          return binascii.unhexlify(text).decode('utf-8')
    elif algo == "URL Encoding": return urllib.parse.unquote(text)


# ═══════════════════════════════════
# HASHING
# ═══════════════════════════════════

def hash_data(algo, text, salt_str=""):
    data = text.encode('utf-8')

    if algo == "SHA-256":
        return hashlib.sha256(data).hexdigest(), ""

    elif algo == "SHA-512":
        return hashlib.sha512(data).hexdigest(), ""

    elif algo == "Salted Hashing":
        if salt_str:
            salt = salt_str.encode('utf-8')
        else:
            salt = os.urandom(16)          # random salt if not provided
        salt_hex = salt.hex()
        digest   = hashlib.sha256(salt + data).hexdigest()
        return digest, salt_hex
