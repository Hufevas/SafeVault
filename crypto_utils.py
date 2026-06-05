import base64
import os

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

LEGACY_SALT = b"safevault"
VERIFICACAO_TOKEN = b"SAFEVAULT_OK"
ITERACOES = 100_000


def gerar_salt() -> bytes:
    return os.urandom(16)


def gerar_chave(senha_mestra: str, salt: bytes) -> Fernet:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=ITERACOES,
    )
    key = base64.urlsafe_b64encode(kdf.derive(senha_mestra.encode()))
    return Fernet(key)


def criar_verificacao(cipher: Fernet) -> bytes:
    return cipher.encrypt(VERIFICACAO_TOKEN)


def validar_senha(cipher: Fernet, verificacao: bytes | None) -> bool:
    if verificacao is None:
        return False
    try:
        cipher.decrypt(verificacao)
        return True
    except InvalidToken:
        return False
