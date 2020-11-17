from base64 import urlsafe_b64encode, urlsafe_b64decode
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
    RSA_BITS,
)
from .utils import Pack


FINGERPRINT_BYTES = 256 // 8
KEY_BYTES = RSA_BITS // 8
MAX_KEYS = 256  # number of keys encoded into unsigned char


@dataclass
class EncryptedValue:
    """
    An arbitrary value encrypted for all keys in a KeySet. The Fernet symmetric key used to encrypt
    the value is stored in an asymmetrically encrypted form for each key. Keys are identified using
    the SHA256 hash of the public key stored in DER form.
    """

    cipher_bytes: bytes
    encrypted_keys: Dict[bytes, bytes]

    def decrypt(self, private_key, private_key_password):
        fingerprint = get_public_key_fingerprint_from_private_key(private_key, private_key_password)
        encrypted_ephemeral_key = self.encrypted_keys[fingerprint]
        ephemeral_key = decrypt_asymmetric(encrypted_ephemeral_key, private_key, private_key_password)
        return decrypt_symmetric(self.cipher_bytes, ephemeral_key)

    def as_dict(self):
        """
        Serialize this `EncryptedValue` into a dict suitable for encoding into YAML, JSON etc.
        """
        return dict(
            k={k.hex(): urlsafe_b64encode(v).decode() for (k, v) in self.encrypted_keys.items()},
            c=urlsafe_b64encode(self.cipher_bytes).decode()
        )

    @classmethod
    def from_dict(cls, d):
        """
        Deserialize an `EncryptedValue` from a dict such as one read from YAML, JSON etc.
        """
        return cls(
            encrypted_keys={bytes.fromhex(k): urlsafe_b64decode(v) for (k, v) in d["k"].items()},
            cipher_bytes=urlsafe_b64decode(d["c"]),
        )

    def as_bytes(self):
        """
        Serialize this `EncryptedValue` into a binary string.
        """
        buf = Pack()

        # number of keys
        num_keys = len(self.encrypted_keys)
        if num_keys > MAX_KEYS:
            raise ValueError("maximum number of keys exceeded")
        buf.pack("<B", num_keys)

        # keys
        for fingerprint, public_key in self.encrypted_keys.items():
            buf.pack(f"<{FINGERPRINT_BYTES}s{KEY_BYTES}s", fingerprint, public_key)

        # length of ciphertext
        num_bytes = len(self.cipher_bytes)
        buf.pack("<L", num_bytes)

        # … and finally
        buf.pack(f"<{num_bytes}s", self.cipher_bytes)

        return buf.getvalue()

    @classmethod
    def from_bytes(cls, b):
        """
        Deserialize an `EncryptedValue` from a binary string produced using `as_bytes`.
        """
        buf = Pack(b)

        # number of keys
        num_keys, = buf.unpack("<B")

        # keys
        encrypted_keys = dict(buf.unpack(f"<{FINGERPRINT_BYTES}s{KEY_BYTES}s") for i in range(num_keys))

        # length of ciphertext
        num_bytes, = buf.unpack("<L")

        # … and finally
        cipher_bytes, = buf.unpack(f"<{num_bytes}s")

        return cls(cipher_bytes, encrypted_keys)


class KeySet:
    public_keys: Dict[bytes, bytes]

    def __init__(self, public_keys: List[bytes] = None):
        """
        :param public_keys: Public keys from `generate_asymmetric_key`
        """
        self.public_keys = {}

        if public_keys:
            self._load_public_keys(public_keys)

    def _load_public_keys(self, public_keys: List[bytes]):
        for public_key in public_keys:
            fingerprint = get_public_key_fingerprint(public_key)
            self.public_keys[fingerprint] = public_key

    def encrypt(self, plain_bytes: bytes):
        """
        Returns an EncryptedValue that represents `plain_bytes` encrypted for
        all public keys in `self`.
        """
        ephemeral_key = generate_symmetric_key()
        cipher_bytes = encrypt_symmetric(plain_bytes, ephemeral_key)
        encrypted_keys: Dict[bytes, bytes] = {
            fingerprint: encrypt_asymmetric(ephemeral_key, public_key)
            for (fingerprint, public_key) in self.public_keys.items()
        }

        return EncryptedValue(cipher_bytes, encrypted_keys)
