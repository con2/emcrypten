import json

from emcrypten.crypto import generate_symmetric_key, generate_asymmetric_key
from emcrypten.keyset import KeySet, EncryptedValue


def test_keyset():
    # NOTE: abusing generate_symmetric_key() for passwords because lazy
    # they need not be Fernet keys, any non-empty byte string will do

    alice_password = generate_symmetric_key()
    alice_priv, alice_pub = generate_asymmetric_key(alice_password)

    bob_password = generate_symmetric_key()
    bob_priv, bob_pub = generate_asymmetric_key(bob_password)

    key_set = KeySet([alice_pub, bob_pub])

    # loooooong value
    plain_bytes = 13 * generate_symmetric_key()
    encrypted_value = key_set.encrypt(plain_bytes)

    # serialize and deserialize
    encrypted_value = EncryptedValue.from_dict(json.loads(json.dumps(encrypted_value.as_dict())))

    alice_decrypted_bytes = encrypted_value.decrypt(alice_priv, alice_password)
    assert alice_decrypted_bytes == plain_bytes

    bob_decrypted_bytes = encrypted_value.decrypt(bob_priv, bob_password)
    assert bob_decrypted_bytes == plain_bytes

    # for explorative testing
    return key_set, encrypted_value


if __name__ == "__main__":
    key_set, encrypted_value = test_keyset()
    print(json.dumps(encrypted_value.as_dict(), indent=4))
