from dataclasses import dataclass

from typing import List, Dict

from cryptography.fernet import Fernet

from .crypto import (
    decrypt_asymmetric,
    decrypt_symmetric,
    encrypt_asymmetric,
    encrypt_symmetric,
    generate_symmetric_key,
    get_public_key_fingerprint_from_private_key,
    get_public_key_fingerprint,
)


@dataclass
class EncryptedValue:
    cipher_bytes: bytes
    encrypted_keys: Dict[bytes, bytes]

    def decrypt(self, private_key, private_key_password):
        fingerprint = get_public_key_fingerprint_from_private_key(private_key, private_key_password)
        encrypted_ephemeral_key = self.encrypted_keys[fingerprint]
        ephemeral_key = decrypt_asymmetric(encrypted_ephemeral_key, private_key, private_key_password)
        return decrypt_symmetric(self.cipher_bytes, ephemeral_key)


class KeySet:
    public_keys: Dict[bytes, bytes]

    def __init__(self, public_keys: List[bytes] = None):
        self.public_keys = {}

        if public_keys:
            self._load_public_keys(public_keys)

    def _load_public_keys(self, public_keys: List[bytes]):
        for public_key in public_keys:
            fingerprint = get_public_key_fingerprint(public_key)
            self.public_keys[fingerprint] = public_key

    def encrypt(self, plain_bytes: bytes):
        ephemeral_key = generate_symmetric_key()
        cipher_bytes = encrypt_symmetric(plain_bytes, ephemeral_key)
        encrypted_keys: Dict[bytes, bytes] = {
            fingerprint: encrypt_asymmetric(ephemeral_key, public_key)
            for (fingerprint, public_key) in self.public_keys.items()
        }

        return EncryptedValue(cipher_bytes, encrypted_keys)
