from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key

users_private_keys = {}


def get_keys(user):
    """Получение пары ключей"""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    users_private_keys['user'] = private_key
    pem_priv = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(f"{user}_private.pem", "wb") as f:
        f.write(pem_priv)
    public_key = private_key.public_key()
    pem_pub = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(f"{user}_public.pem", "wb") as f:
        f.write(pem_pub)
    return pem_pub


def converting_to_bytes(word: str):
    """Перевод строки в байты"""
    message = word.encode('utf-8')
    return message


def create_signature(user: str, word):
    """Получение подписи"""
    message = word.encode('utf-8')
    with open(f"{user}_private.pem", 'r') as f:
        text = f.read()
        pem_priv = text.encode('utf-8')
        private_key = load_pem_private_key(pem_priv, password=None)
        print(private_key)
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature


def get_public_key(file):
    """Распаковка publick_key"""
    with open(file, 'r') as f:
        text = f.read()
        pem_pub = text.encode('utf-8')
        key = load_pem_public_key(pem_pub)
    return key


def check_signature(key, signature, text):
    """Проверка подписи"""
    message = converting_to_bytes(text)
    code_key = key.encode('utf-8')
    pub_key = load_pem_public_key(code_key)
    try:
        pub_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except:
        return False
